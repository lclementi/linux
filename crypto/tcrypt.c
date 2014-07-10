/*
 * Quick & dirty crypto testing module.
 *
 * This will only exist until we have a better testing mechanism
 * (e.g. a char device).
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2002 Jean-Francois Dive <jef@linuxbe.org>
 * Copyright (c) 2007 Nokia Siemens Networks
 *
 * Updated RFC4106 AES-GCM testing.
 *    Authors: Aidan O'Mahony (aidan.o.mahony@intel.com)
 *             Adrian Hoban <adrian.hoban@intel.com>
 *             Gabriele Paoloni <gabriele.paoloni@intel.com>
 *             Tadeusz Struk (tadeusz.struk@intel.com)
 *             Copyright (c) 2010, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#include <linux/interrupt.h>
#include <linux/debugfs.h>
#include <linux/ctype.h>
#include "tcrypt.h"
#include "internal.h"

/*
 * Need slab memory for testing (size in number of pages).
 */
#define TVMEMSIZE	4

/*
* Used by test_cipher_speed()
*/
#define ENCRYPT 1
#define DECRYPT 0

/*
 * return a string with the driver name
 */
#define get_driver_name(tfm_type, tfm) crypto_tfm_alg_driver_name(tfm_type ## _tfm(tfm))

/*
 * maximum length of command
 */
#define COMMAND_BUFFER_SIZE 128
#define OUTPUT_BUFFER_LINES 256


/*
 * Used by test_cipher_speed()
 */
static unsigned int sec;

static char *tvmem[TVMEMSIZE];

/**
 * base level dentry for the tcrypto debugfs
 */
static struct dentry *d_basetcrypt;
static char read_str[] =
	"tcrypt mini-HOWTO:\n\n"
	"# echo list > command : disply a list of available test commands\n"
	"# cat output\n"
	"hash_speed_<name_of_hash>\n"
	"ahash_speed_<name_of_hash>\n"
	"cipher_speed_aes\n"
	"cipher_speed_des3_ede\n"
	"[...]\n"
	"# echo clear > command : to clear the output buffer\n"
	"# cat output\n"
	"# echo hash_speed_sha256 > command : run the speed test on sha256\n"
	"# cat output\n"
	"some output of the sha256 test\n"
	"[...]\n"
	"# echo 2 > seconds : run next tests for 2 seconds\n"
	"     (it defaults to zero which uses CPU cycles instead)\n";

static struct debugfs_blob_wrapper readme_blob;

static struct tcrypt_data_type {
	char			*output[OUTPUT_BUFFER_LINES];
	size_t			cur_start;
	size_t			cur_stop;
} tcrypt_data;

/*
 * tcrypt_output_lock is used to protect the tcrypt_data.output buffer
 */
DEFINE_MUTEX(tcrypt_output_lock);

#define get_num_elements() ((OUTPUT_BUFFER_LINES + tcrypt_data.cur_stop - \
		tcrypt_data.cur_start) % OUTPUT_BUFFER_LINES)


#define tc_printf(...)							\
do {									\
	mutex_lock_interruptible(&tcrypt_output_lock);			\
	tc_printf_unlock(__VA_ARGS__);					\
	mutex_unlock(&tcrypt_output_lock);				\
} while (0)

static void
tc_printf_unlock(const char *fmt, ...)
{
	va_list ap;
	char *p;

	va_start(ap, fmt);
	p = kvasprintf(GFP_KERNEL, fmt, ap);
	va_end(ap);

	if (!p) {
		pr_err("tcrypt: Unable to allocate memory (output"
					" buffer)\n");
		return;
	}

	tcrypt_data.output[tcrypt_data.cur_stop] = p;

	tcrypt_data.cur_stop++;

	if (tcrypt_data.cur_stop == OUTPUT_BUFFER_LINES)
		/* cur_stop wraps */
		tcrypt_data.cur_stop = 0;

	if (tcrypt_data.cur_stop == tcrypt_data.cur_start) {
		/* buffer is full we need some space */
		kfree(tcrypt_data.output[tcrypt_data.cur_start]);
		tcrypt_data.cur_start++;
	}

	if (tcrypt_data.cur_start == OUTPUT_BUFFER_LINES)
		/* double wrap */
		tcrypt_data.cur_start = 0;
}



static char *check[] = {
	"des", "md5", "des3_ede", "rot13", "sha1", "sha224", "sha256",
	"blowfish", "twofish", "serpent", "sha384", "sha512", "md4", "aes",
	"cast6", "arc4", "michael_mic", "deflate", "crc32c", "tea", "xtea",
	"khazad", "wp512", "wp384", "wp256", "tnepres", "xeta",  "fcrypt",
	"camellia", "seed", "salsa20", "rmd128", "rmd160", "rmd256", "rmd320",
	"lzo", "cts", "zlib", NULL
};

static int test_cipher_jiffies(struct blkcipher_desc *desc, int enc,
			       struct scatterlist *sg, int blen, int secs)
{
	unsigned long start, end;
	int bcount;
	int ret;

	for (start = jiffies, end = start + secs * HZ, bcount = 0;
	     time_before(jiffies, end); bcount++) {
		if (enc)
			ret = crypto_blkcipher_encrypt(desc, sg, sg, blen);
		else
			ret = crypto_blkcipher_decrypt(desc, sg, sg, blen);

		if (ret)
			return ret;
	}

	tc_printf("%d operations in %d seconds (%ld bytes)\n",
	       bcount, secs, (long)bcount * blen);
	return 0;
}

static int test_cipher_cycles(struct blkcipher_desc *desc, int enc,
			      struct scatterlist *sg, int blen)
{
	unsigned long cycles = 0;
	int ret = 0;
	int i;

	local_irq_disable();

	/* Warm-up run. */
	for (i = 0; i < 4; i++) {
		if (enc)
			ret = crypto_blkcipher_encrypt(desc, sg, sg, blen);
		else
			ret = crypto_blkcipher_decrypt(desc, sg, sg, blen);

		if (ret)
			goto out;
	}

	/* The real thing. */
	for (i = 0; i < 8; i++) {
		cycles_t start, end;

		start = get_cycles();
		if (enc)
			ret = crypto_blkcipher_encrypt(desc, sg, sg, blen);
		else
			ret = crypto_blkcipher_decrypt(desc, sg, sg, blen);
		end = get_cycles();

		if (ret)
			goto out;

		cycles += end - start;
	}

out:
	local_irq_enable();

	if (ret == 0)
		tc_printf("1 operation in %lu cycles (%d bytes)\n",
		       (cycles + 4) / 8, blen);

	return ret;
}

static int test_aead_jiffies(struct aead_request *req, int enc,
				int blen, int secs)
{
	unsigned long start, end;
	int bcount;
	int ret;

	for (start = jiffies, end = start + secs * HZ, bcount = 0;
	     time_before(jiffies, end); bcount++) {
		if (enc)
			ret = crypto_aead_encrypt(req);
		else
			ret = crypto_aead_decrypt(req);

		if (ret)
			return ret;
	}

	tc_printf("%d operations in %d seconds (%ld bytes)\n",
	       bcount, secs, (long)bcount * blen);
	return 0;
}

static int test_aead_cycles(struct aead_request *req, int enc, int blen)
{
	unsigned long cycles = 0;
	int ret = 0;
	int i;

	local_irq_disable();

	/* Warm-up run. */
	for (i = 0; i < 4; i++) {
		if (enc)
			ret = crypto_aead_encrypt(req);
		else
			ret = crypto_aead_decrypt(req);

		if (ret)
			goto out;
	}

	/* The real thing. */
	for (i = 0; i < 8; i++) {
		cycles_t start, end;

		start = get_cycles();
		if (enc)
			ret = crypto_aead_encrypt(req);
		else
			ret = crypto_aead_decrypt(req);
		end = get_cycles();

		if (ret)
			goto out;

		cycles += end - start;
	}

out:
	local_irq_enable();

	if (ret == 0)
		tc_printf("1 operation in %lu cycles (%d bytes)\n",
		       (cycles + 4) / 8, blen);

	return ret;
}

static u32 block_sizes[] = { 16, 64, 256, 1024, 8192, 0 };
static u32 aead_sizes[] = { 16, 64, 256, 512, 1024, 2048, 4096, 8192, 0 };

#define XBUFSIZE 8
#define MAX_IVLEN 32

static int testmgr_alloc_buf(char *buf[XBUFSIZE])
{
	int i;

	for (i = 0; i < XBUFSIZE; i++) {
		buf[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!buf[i])
			goto err_free_buf;
	}

	return 0;

err_free_buf:
	while (i-- > 0)
		free_page((unsigned long)buf[i]);

	return -ENOMEM;
}

static void testmgr_free_buf(char *buf[XBUFSIZE])
{
	int i;

	for (i = 0; i < XBUFSIZE; i++)
		free_page((unsigned long)buf[i]);
}

static void sg_init_aead(struct scatterlist *sg, char *xbuf[XBUFSIZE],
			unsigned int buflen)
{
	int np = (buflen + PAGE_SIZE - 1)/PAGE_SIZE;
	int k, rem;

	np = (np > XBUFSIZE) ? XBUFSIZE : np;
	rem = buflen % PAGE_SIZE;
	if (np > XBUFSIZE) {
		rem = PAGE_SIZE;
		np = XBUFSIZE;
	}
	sg_init_table(sg, np);
	for (k = 0; k < np; ++k) {
		if (k == (np-1))
			sg_set_buf(&sg[k], xbuf[k], rem);
		else
			sg_set_buf(&sg[k], xbuf[k], PAGE_SIZE);
	}
}

static void test_aead_speed(const char *algo, int enc, unsigned int secs,
			    struct aead_speed_template *template,
			    unsigned int tcount, u8 authsize,
			    unsigned int aad_size, u8 *keysize)
{
	unsigned int i, j;
	struct crypto_aead *tfm;
	int ret = -ENOMEM;
	const char *key;
	struct aead_request *req;
	struct scatterlist *sg;
	struct scatterlist *asg;
	struct scatterlist *sgout;
	const char *e;
	void *assoc;
	char iv[MAX_IVLEN];
	char *xbuf[XBUFSIZE];
	char *xoutbuf[XBUFSIZE];
	char *axbuf[XBUFSIZE];
	unsigned int *b_size;
	unsigned int iv_len;

	if (aad_size >= PAGE_SIZE) {
		tc_printf("associate data length (%u) too big\n", aad_size);
		return;
	}

	if (enc == ENCRYPT)
		e = "encryption";
	else
		e = "decryption";

	if (testmgr_alloc_buf(xbuf))
		goto out_noxbuf;
	if (testmgr_alloc_buf(axbuf))
		goto out_noaxbuf;
	if (testmgr_alloc_buf(xoutbuf))
		goto out_nooutbuf;

	sg = kmalloc(sizeof(*sg) * 8 * 3, GFP_KERNEL);
	if (!sg)
		goto out_nosg;
	asg = &sg[8];
	sgout = &asg[8];

	tfm = crypto_alloc_aead(algo, 0, 0);

	if (IS_ERR(tfm)) {
		tc_printf("alg: aead: Failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		goto out_notfm;
	}

	tc_printf("\ntesting speed of %s (%s) %s\n", algo,
			get_driver_name(crypto_aead, tfm), e);

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		tc_printf("alg: aead: Failed to allocate request for %s\n",
		       algo);
		goto out_noreq;
	}

	i = 0;
	do {
		b_size = aead_sizes;
		do {
			assoc = axbuf[0];
			memset(assoc, 0xff, aad_size);
			sg_init_one(&asg[0], assoc, aad_size);

			if ((*keysize + *b_size) > TVMEMSIZE * PAGE_SIZE) {
				tc_printf("template (%u) too big for tvmem (%lu)\n",
				       *keysize + *b_size,
					TVMEMSIZE * PAGE_SIZE);
				goto out;
			}

			key = tvmem[0];
			for (j = 0; j < tcount; j++) {
				if (template[j].klen == *keysize) {
					key = template[j].key;
					break;
				}
			}
			ret = crypto_aead_setkey(tfm, key, *keysize);
			ret = crypto_aead_setauthsize(tfm, authsize);

			iv_len = crypto_aead_ivsize(tfm);
			if (iv_len)
				memset(&iv, 0xff, iv_len);

			crypto_aead_clear_flags(tfm, ~0);
			tc_printf("test %u (%d bit key, %d byte blocks): ",
					i, *keysize * 8, *b_size);


			memset(tvmem[0], 0xff, PAGE_SIZE);

			if (ret) {
				tc_printf("setkey() failed flags=%x\n",
						crypto_aead_get_flags(tfm));
				goto out;
			}

			sg_init_aead(&sg[0], xbuf,
				    *b_size + (enc ? authsize : 0));

			sg_init_aead(&sgout[0], xoutbuf,
				    *b_size + (enc ? authsize : 0));

			aead_request_set_crypt(req, sg, sgout, *b_size, iv);
			aead_request_set_assoc(req, asg, aad_size);

			if (secs)
				ret = test_aead_jiffies(req, enc, *b_size,
							secs);
			else
				ret = test_aead_cycles(req, enc, *b_size);

			if (ret) {
				tc_printf("%s() failed return code=%d\n", e, ret);
				break;
			}
			b_size++;
			i++;
		} while (*b_size);
		keysize++;
	} while (*keysize);

out:
	aead_request_free(req);
out_noreq:
	crypto_free_aead(tfm);
out_notfm:
	kfree(sg);
out_nosg:
	testmgr_free_buf(xoutbuf);
out_nooutbuf:
	testmgr_free_buf(axbuf);
out_noaxbuf:
	testmgr_free_buf(xbuf);
out_noxbuf:
	return;
}

static void test_cipher_speed(const char *algo, int enc, unsigned int secs,
			      struct cipher_speed_template *template,
			      unsigned int tcount, u8 *keysize)
{
	unsigned int ret, i, j, iv_len;
	const char *key;
	char iv[128];
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc;
	const char *e;
	u32 *b_size;

	if (enc == ENCRYPT)
	        e = "encryption";
	else
		e = "decryption";

	tfm = crypto_alloc_blkcipher(algo, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		tc_printf("failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		return;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	tc_printf("\ntesting speed of %s (%s) %s\n", algo,
			get_driver_name(crypto_blkcipher, tfm), e);

	i = 0;
	do {

		b_size = block_sizes;
		do {
			struct scatterlist sg[TVMEMSIZE];

			if ((*keysize + *b_size) > TVMEMSIZE * PAGE_SIZE) {
				tc_printf("template (%u) too big for "
				       "tvmem (%lu)\n", *keysize + *b_size,
				       TVMEMSIZE * PAGE_SIZE);
				goto out;
			}

			tc_printf("test %u (%d bit key, %d byte blocks): ", i,
					*keysize * 8, *b_size);

			memset(tvmem[0], 0xff, PAGE_SIZE);

			/* set key, plain text and IV */
			key = tvmem[0];
			for (j = 0; j < tcount; j++) {
				if (template[j].klen == *keysize) {
					key = template[j].key;
					break;
				}
			}

			ret = crypto_blkcipher_setkey(tfm, key, *keysize);
			if (ret) {
				tc_printf("setkey() failed flags=%x\n",
						crypto_blkcipher_get_flags(tfm));
				goto out;
			}

			sg_init_table(sg, TVMEMSIZE);
			sg_set_buf(sg, tvmem[0] + *keysize,
				   PAGE_SIZE - *keysize);
			for (j = 1; j < TVMEMSIZE; j++) {
				sg_set_buf(sg + j, tvmem[j], PAGE_SIZE);
				memset (tvmem[j], 0xff, PAGE_SIZE);
			}

			iv_len = crypto_blkcipher_ivsize(tfm);
			if (iv_len) {
				memset(&iv, 0xff, iv_len);
				crypto_blkcipher_set_iv(tfm, iv, iv_len);
			}

			if (secs)
				ret = test_cipher_jiffies(&desc, enc, sg,
							  *b_size, secs);
			else
				ret = test_cipher_cycles(&desc, enc, sg,
							 *b_size);

			if (ret) {
				tc_printf("%s() failed flags=%x\n", e, desc.flags);
				break;
			}
			b_size++;
			i++;
		} while (*b_size);
		keysize++;
	} while (*keysize);

out:
	crypto_free_blkcipher(tfm);
}

static int test_hash_jiffies_digest(struct hash_desc *desc,
				    struct scatterlist *sg, int blen,
				    char *out, int secs)
{
	unsigned long start, end;
	int bcount;
	int ret;

	for (start = jiffies, end = start + secs * HZ, bcount = 0;
	     time_before(jiffies, end); bcount++) {
		ret = crypto_hash_digest(desc, sg, blen, out);
		if (ret)
			return ret;
	}

	tc_printf("%6u opers/sec, %9lu bytes/sec\n",
	       bcount / secs, ((long)bcount * blen) / secs);

	return 0;
}

static int test_hash_jiffies(struct hash_desc *desc, struct scatterlist *sg,
			     int blen, int plen, char *out, int secs)
{
	unsigned long start, end;
	int bcount, pcount;
	int ret;

	if (plen == blen)
		return test_hash_jiffies_digest(desc, sg, blen, out, secs);

	for (start = jiffies, end = start + secs * HZ, bcount = 0;
	     time_before(jiffies, end); bcount++) {
		ret = crypto_hash_init(desc);
		if (ret)
			return ret;
		for (pcount = 0; pcount < blen; pcount += plen) {
			ret = crypto_hash_update(desc, sg, plen);
			if (ret)
				return ret;
		}
		/* we assume there is enough space in 'out' for the result */
		ret = crypto_hash_final(desc, out);
		if (ret)
			return ret;
	}

	tc_printf("%6u opers/sec, %9lu bytes/sec\n",
	       bcount / secs, ((long)bcount * blen) / secs);

	return 0;
}

static int test_hash_cycles_digest(struct hash_desc *desc,
				   struct scatterlist *sg, int blen, char *out)
{
	unsigned long cycles = 0;
	int i;
	int ret;

	local_irq_disable();

	/* Warm-up run. */
	for (i = 0; i < 4; i++) {
		ret = crypto_hash_digest(desc, sg, blen, out);
		if (ret)
			goto out;
	}

	/* The real thing. */
	for (i = 0; i < 8; i++) {
		cycles_t start, end;

		start = get_cycles();

		ret = crypto_hash_digest(desc, sg, blen, out);
		if (ret)
			goto out;

		end = get_cycles();

		cycles += end - start;
	}

out:
	local_irq_enable();

	if (ret)
		return ret;

	tc_printf("%6lu cycles/operation, %4lu cycles/byte\n",
	       cycles / 8, cycles / (8 * blen));

	return 0;
}

static int test_hash_cycles(struct hash_desc *desc, struct scatterlist *sg,
			    int blen, int plen, char *out)
{
	unsigned long cycles = 0;
	int i, pcount;
	int ret;

	if (plen == blen)
		return test_hash_cycles_digest(desc, sg, blen, out);

	local_irq_disable();

	/* Warm-up run. */
	for (i = 0; i < 4; i++) {
		ret = crypto_hash_init(desc);
		if (ret)
			goto out;
		for (pcount = 0; pcount < blen; pcount += plen) {
			ret = crypto_hash_update(desc, sg, plen);
			if (ret)
				goto out;
		}
		ret = crypto_hash_final(desc, out);
		if (ret)
			goto out;
	}

	/* The real thing. */
	for (i = 0; i < 8; i++) {
		cycles_t start, end;

		start = get_cycles();

		ret = crypto_hash_init(desc);
		if (ret)
			goto out;
		for (pcount = 0; pcount < blen; pcount += plen) {
			ret = crypto_hash_update(desc, sg, plen);
			if (ret)
				goto out;
		}
		ret = crypto_hash_final(desc, out);
		if (ret)
			goto out;

		end = get_cycles();

		cycles += end - start;
	}

out:
	local_irq_enable();

	if (ret)
		return ret;

	tc_printf("%6lu cycles/operation, %4lu cycles/byte\n",
	       cycles / 8, cycles / (8 * blen));

	return 0;
}

static void test_hash_sg_init(struct scatterlist *sg)
{
	int i;

	sg_init_table(sg, TVMEMSIZE);
	for (i = 0; i < TVMEMSIZE; i++) {
		sg_set_buf(sg + i, tvmem[i], PAGE_SIZE);
		memset(tvmem[i], 0xff, PAGE_SIZE);
	}
}

static void test_hash_speed(const char *algo, unsigned int secs,
			    struct hash_speed *speed, unsigned int keylen)
{
	struct scatterlist sg[TVMEMSIZE];
	struct crypto_hash *tfm;
	struct hash_desc desc;
	static char output[1024];
	int i;
	int ret;

	tfm = crypto_alloc_hash(algo, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		tc_printf("failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		return;
	}

	tc_printf("\ntesting speed of %s (%s)\n", algo,
			get_driver_name(crypto_hash, tfm));

	desc.tfm = tfm;
	desc.flags = 0;

	if (crypto_hash_digestsize(tfm) > sizeof(output)) {
		tc_printf("digestsize(%u) > outputbuffer(%zu)\n",
		       crypto_hash_digestsize(tfm), sizeof(output));
		goto out;
	}

	test_hash_sg_init(sg);
	for (i = 0; speed[i].blen != 0; i++) {
		if (speed[i].blen > TVMEMSIZE * PAGE_SIZE) {
			tc_printf("template (%u) too big for tvmem (%lu)\n",
			       speed[i].blen, TVMEMSIZE * PAGE_SIZE);
			goto out;
		}

		if (keylen)
			crypto_hash_setkey(tfm, tvmem[0], keylen);

		tc_printf("test%3u "
		       "(%5u byte blocks,%5u bytes per update,%4u updates): ",
		       i, speed[i].blen, speed[i].plen, speed[i].blen / speed[i].plen);

		if (secs)
			ret = test_hash_jiffies(&desc, sg, speed[i].blen,
						speed[i].plen, output, secs);
		else
			ret = test_hash_cycles(&desc, sg, speed[i].blen,
					       speed[i].plen, output);

		if (ret) {
			tc_printf("hashing failed ret=%d\n", ret);
			break;
		}
	}

out:
	crypto_free_hash(tfm);
}

struct tcrypt_result {
	struct completion completion;
	int err;
};

static void tcrypt_complete(struct crypto_async_request *req, int err)
{
	struct tcrypt_result *res = req->data;

	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}

static inline int do_one_ahash_op(struct ahash_request *req, int ret)
{
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		struct tcrypt_result *tr = req->base.data;

		ret = wait_for_completion_interruptible(&tr->completion);
		if (!ret)
			ret = tr->err;
		reinit_completion(&tr->completion);
	}
	return ret;
}

static int test_ahash_jiffies_digest(struct ahash_request *req, int blen,
				     char *out, int secs)
{
	unsigned long start, end;
	int bcount;
	int ret;

	for (start = jiffies, end = start + secs * HZ, bcount = 0;
	     time_before(jiffies, end); bcount++) {
		ret = do_one_ahash_op(req, crypto_ahash_digest(req));
		if (ret)
			return ret;
	}

	tc_printf("%6u opers/sec, %9lu bytes/sec\n",
	       bcount / secs, ((long)bcount * blen) / secs);

	return 0;
}

static int test_ahash_jiffies(struct ahash_request *req, int blen,
			      int plen, char *out, int secs)
{
	unsigned long start, end;
	int bcount, pcount;
	int ret;

	if (plen == blen)
		return test_ahash_jiffies_digest(req, blen, out, secs);

	for (start = jiffies, end = start + secs * HZ, bcount = 0;
	     time_before(jiffies, end); bcount++) {
		ret = crypto_ahash_init(req);
		if (ret)
			return ret;
		for (pcount = 0; pcount < blen; pcount += plen) {
			ret = do_one_ahash_op(req, crypto_ahash_update(req));
			if (ret)
				return ret;
		}
		/* we assume there is enough space in 'out' for the result */
		ret = do_one_ahash_op(req, crypto_ahash_final(req));
		if (ret)
			return ret;
	}

	tc_printf("%6u opers/sec, %9lu bytes/sec\n",
		bcount / secs, ((long)bcount * blen) / secs);

	return 0;
}

static int test_ahash_cycles_digest(struct ahash_request *req, int blen,
				    char *out)
{
	unsigned long cycles = 0;
	int ret, i;

	/* Warm-up run. */
	for (i = 0; i < 4; i++) {
		ret = do_one_ahash_op(req, crypto_ahash_digest(req));
		if (ret)
			goto out;
	}

	/* The real thing. */
	for (i = 0; i < 8; i++) {
		cycles_t start, end;

		start = get_cycles();

		ret = do_one_ahash_op(req, crypto_ahash_digest(req));
		if (ret)
			goto out;

		end = get_cycles();

		cycles += end - start;
	}

out:
	if (ret)
		return ret;

	tc_printf("%6lu cycles/operation, %4lu cycles/byte\n",
		cycles / 8, cycles / (8 * blen));

	return 0;
}

static int test_ahash_cycles(struct ahash_request *req, int blen,
			     int plen, char *out)
{
	unsigned long cycles = 0;
	int i, pcount, ret;

	if (plen == blen)
		return test_ahash_cycles_digest(req, blen, out);

	/* Warm-up run. */
	for (i = 0; i < 4; i++) {
		ret = crypto_ahash_init(req);
		if (ret)
			goto out;
		for (pcount = 0; pcount < blen; pcount += plen) {
			ret = do_one_ahash_op(req, crypto_ahash_update(req));
			if (ret)
				goto out;
		}
		ret = do_one_ahash_op(req, crypto_ahash_final(req));
		if (ret)
			goto out;
	}

	/* The real thing. */
	for (i = 0; i < 8; i++) {
		cycles_t start, end;

		start = get_cycles();

		ret = crypto_ahash_init(req);
		if (ret)
			goto out;
		for (pcount = 0; pcount < blen; pcount += plen) {
			ret = do_one_ahash_op(req, crypto_ahash_update(req));
			if (ret)
				goto out;
		}
		ret = do_one_ahash_op(req, crypto_ahash_final(req));
		if (ret)
			goto out;

		end = get_cycles();

		cycles += end - start;
	}

out:
	if (ret)
		return ret;

	tc_printf("%6lu cycles/operation, %4lu cycles/byte\n",
		cycles / 8, cycles / (8 * blen));

	return 0;
}

static void test_ahash_speed(const char *algo, unsigned int secs,
			     struct hash_speed *speed)
{
	struct scatterlist sg[TVMEMSIZE];
	struct tcrypt_result tresult;
	struct ahash_request *req;
	struct crypto_ahash *tfm;
	static char output[1024];
	int i, ret;

	tfm = crypto_alloc_ahash(algo, 0, 0);
	if (IS_ERR(tfm)) {
		tc_printf("failed to load transform for %s: %ld\n",
		       algo, PTR_ERR(tfm));
		return;
	}

	tc_printf("\ntesting speed of async %s (%s)\n", algo,
			get_driver_name(crypto_ahash, tfm));

	if (crypto_ahash_digestsize(tfm) > sizeof(output)) {
		tc_printf("digestsize(%u) > outputbuffer(%zu)\n",
		       crypto_ahash_digestsize(tfm), sizeof(output));
		goto out;
	}

	test_hash_sg_init(sg);
	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		tc_printf("ahash request allocation failure\n");
		goto out;
	}

	init_completion(&tresult.completion);
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   tcrypt_complete, &tresult);

	for (i = 0; speed[i].blen != 0; i++) {
		if (speed[i].blen > TVMEMSIZE * PAGE_SIZE) {
			tc_printf("template (%u) too big for tvmem (%lu)\n",
			       speed[i].blen, TVMEMSIZE * PAGE_SIZE);
			break;
		}

		tc_printf("test%3u "
			"(%5u byte blocks,%5u bytes per update,%4u updates): ",
			i, speed[i].blen, speed[i].plen, speed[i].blen / speed[i].plen);

		ahash_request_set_crypt(req, sg, output, speed[i].plen);

		if (secs)
			ret = test_ahash_jiffies(req, speed[i].blen,
						 speed[i].plen, output, secs);
		else
			ret = test_ahash_cycles(req, speed[i].blen,
						speed[i].plen, output);

		if (ret) {
			tc_printf("hashing failed ret=%d\n", ret);
			break;
		}
	}

	ahash_request_free(req);

out:
	crypto_free_ahash(tfm);
}

static inline int do_one_acipher_op(struct ablkcipher_request *req, int ret)
{
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		struct tcrypt_result *tr = req->base.data;

		ret = wait_for_completion_interruptible(&tr->completion);
		if (!ret)
			ret = tr->err;
		reinit_completion(&tr->completion);
	}

	return ret;
}

static int test_acipher_jiffies(struct ablkcipher_request *req, int enc,
				int blen, int secs)
{
	unsigned long start, end;
	int bcount;
	int ret;

	for (start = jiffies, end = start + secs * HZ, bcount = 0;
	     time_before(jiffies, end); bcount++) {
		if (enc)
			ret = do_one_acipher_op(req,
						crypto_ablkcipher_encrypt(req));
		else
			ret = do_one_acipher_op(req,
						crypto_ablkcipher_decrypt(req));

		if (ret)
			return ret;
	}

	tc_printf("%d operations in %d seconds (%ld bytes)\n",
		bcount, secs, (long)bcount * blen);
	return 0;
}

static int test_acipher_cycles(struct ablkcipher_request *req, int enc,
			       int blen)
{
	unsigned long cycles = 0;
	int ret = 0;
	int i;

	/* Warm-up run. */
	for (i = 0; i < 4; i++) {
		if (enc)
			ret = do_one_acipher_op(req,
						crypto_ablkcipher_encrypt(req));
		else
			ret = do_one_acipher_op(req,
						crypto_ablkcipher_decrypt(req));

		if (ret)
			goto out;
	}

	/* The real thing. */
	for (i = 0; i < 8; i++) {
		cycles_t start, end;

		start = get_cycles();
		if (enc)
			ret = do_one_acipher_op(req,
						crypto_ablkcipher_encrypt(req));
		else
			ret = do_one_acipher_op(req,
						crypto_ablkcipher_decrypt(req));
		end = get_cycles();

		if (ret)
			goto out;

		cycles += end - start;
	}

out:
	if (ret == 0)
		tc_printf("1 operation in %lu cycles (%d bytes)\n",
			(cycles + 4) / 8, blen);

	return ret;
}

static void test_acipher_speed(const char *algo, int enc, unsigned int secs,
			       struct cipher_speed_template *template,
			       unsigned int tcount, u8 *keysize)
{
	unsigned int ret, i, j, k, iv_len;
	struct tcrypt_result tresult;
	const char *key;
	char iv[128];
	struct ablkcipher_request *req;
	struct crypto_ablkcipher *tfm;
	const char *e;
	u32 *b_size;

	if (enc == ENCRYPT)
		e = "encryption";
	else
		e = "decryption";

	init_completion(&tresult.completion);

	tfm = crypto_alloc_ablkcipher(algo, 0, 0);

	if (IS_ERR(tfm)) {
		tc_printf("failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		return;
	}

	tc_printf("\ntesting speed of async %s (%s) %s\n", algo,
			get_driver_name(crypto_ablkcipher, tfm), e);

	req = ablkcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		tc_printf("tcrypt: skcipher: Failed to allocate request for %s\n",
		       algo);
		goto out;
	}

	ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					tcrypt_complete, &tresult);

	i = 0;
	do {
		b_size = block_sizes;

		do {
			struct scatterlist sg[TVMEMSIZE];

			if ((*keysize + *b_size) > TVMEMSIZE * PAGE_SIZE) {
				tc_printf("template (%u) too big for "
				       "tvmem (%lu)\n", *keysize + *b_size,
				       TVMEMSIZE * PAGE_SIZE);
				goto out_free_req;
			}

			tc_printf("test %u (%d bit key, %d byte blocks): ", i,
				*keysize * 8, *b_size);

			memset(tvmem[0], 0xff, PAGE_SIZE);

			/* set key, plain text and IV */
			key = tvmem[0];
			for (j = 0; j < tcount; j++) {
				if (template[j].klen == *keysize) {
					key = template[j].key;
					break;
				}
			}

			crypto_ablkcipher_clear_flags(tfm, ~0);

			ret = crypto_ablkcipher_setkey(tfm, key, *keysize);
			if (ret) {
				tc_printf("setkey() failed flags=%x\n",
					crypto_ablkcipher_get_flags(tfm));
				goto out_free_req;
			}

			sg_init_table(sg, TVMEMSIZE);

			k = *keysize + *b_size;
			if (k > PAGE_SIZE) {
				sg_set_buf(sg, tvmem[0] + *keysize,
				   PAGE_SIZE - *keysize);
				k -= PAGE_SIZE;
				j = 1;
				while (k > PAGE_SIZE) {
					sg_set_buf(sg + j, tvmem[j], PAGE_SIZE);
					memset(tvmem[j], 0xff, PAGE_SIZE);
					j++;
					k -= PAGE_SIZE;
				}
				sg_set_buf(sg + j, tvmem[j], k);
				memset(tvmem[j], 0xff, k);
			} else {
				sg_set_buf(sg, tvmem[0] + *keysize, *b_size);
			}

			iv_len = crypto_ablkcipher_ivsize(tfm);
			if (iv_len)
				memset(&iv, 0xff, iv_len);

			ablkcipher_request_set_crypt(req, sg, sg, *b_size, iv);

			if (secs)
				ret = test_acipher_jiffies(req, enc,
							   *b_size, secs);
			else
				ret = test_acipher_cycles(req, enc,
							  *b_size);

			if (ret) {
				tc_printf("%s() failed flags=%x\n", e,
					crypto_ablkcipher_get_flags(tfm));
				break;
			}
			b_size++;
			i++;
		} while (*b_size);
		keysize++;
	} while (*keysize);

out_free_req:
	ablkcipher_request_free(req);
out:
	crypto_free_ablkcipher(tfm);
}

static void test_available(void)
{
	char **name = check;

	while (*name) {
		tc_printf("alg %s ", *name);
		tc_printf(crypto_has_alg(*name, 0, 0) ?
		       "found\n" : "not found\n");
		name++;
	}
}

static inline int tcrypt_test(const char *alg)
{
	int ret;

	ret = alg_test(alg, alg, 0, 0);
	/* non-fips algs return -EINVAL in fips mode */
	if (fips_enabled && ret == -EINVAL)
		ret = 0;
	return ret;
}

static int do_test(const char *test)
{

#if 0
	case 1:
		ret += tcrypt_test("md5");
		break;

	case 2:
		ret += tcrypt_test("sha1");
		break;

	case 3:
		ret += tcrypt_test("ecb(des)");
		ret += tcrypt_test("cbc(des)");
		ret += tcrypt_test("ctr(des)");
		break;

	case 4:
		ret += tcrypt_test("ecb(des3_ede)");
		ret += tcrypt_test("cbc(des3_ede)");
		ret += tcrypt_test("ctr(des3_ede)");
		break;

	case 5:
		ret += tcrypt_test("md4");
		break;

	case 6:
		ret += tcrypt_test("sha256");
		break;

	case 7:
		ret += tcrypt_test("ecb(blowfish)");
		ret += tcrypt_test("cbc(blowfish)");
		ret += tcrypt_test("ctr(blowfish)");
		break;

	case 8:
		ret += tcrypt_test("ecb(twofish)");
		ret += tcrypt_test("cbc(twofish)");
		ret += tcrypt_test("ctr(twofish)");
		ret += tcrypt_test("lrw(twofish)");
		ret += tcrypt_test("xts(twofish)");
		break;

	case 9:
		ret += tcrypt_test("ecb(serpent)");
		ret += tcrypt_test("cbc(serpent)");
		ret += tcrypt_test("ctr(serpent)");
		ret += tcrypt_test("lrw(serpent)");
		ret += tcrypt_test("xts(serpent)");
		break;

	case 10:
		ret += tcrypt_test("ecb(aes)");
		ret += tcrypt_test("cbc(aes)");
		ret += tcrypt_test("lrw(aes)");
		ret += tcrypt_test("xts(aes)");
		ret += tcrypt_test("ctr(aes)");
		ret += tcrypt_test("rfc3686(ctr(aes))");
		break;

	case 11:
		ret += tcrypt_test("sha384");
		break;

	case 12:
		ret += tcrypt_test("sha512");
		break;

	case 13:
		ret += tcrypt_test("deflate");
		break;

	case 14:
		ret += tcrypt_test("ecb(cast5)");
		ret += tcrypt_test("cbc(cast5)");
		ret += tcrypt_test("ctr(cast5)");
		break;

	case 15:
		ret += tcrypt_test("ecb(cast6)");
		ret += tcrypt_test("cbc(cast6)");
		ret += tcrypt_test("ctr(cast6)");
		ret += tcrypt_test("lrw(cast6)");
		ret += tcrypt_test("xts(cast6)");
		break;

	case 16:
		ret += tcrypt_test("ecb(arc4)");
		break;

	case 17:
		ret += tcrypt_test("michael_mic");
		break;

	case 18:
		ret += tcrypt_test("crc32c");
		break;

	case 19:
		ret += tcrypt_test("ecb(tea)");
		break;

	case 20:
		ret += tcrypt_test("ecb(xtea)");
		break;

	case 21:
		ret += tcrypt_test("ecb(khazad)");
		break;

	case 22:
		ret += tcrypt_test("wp512");
		break;

	case 23:
		ret += tcrypt_test("wp384");
		break;

	case 24:
		ret += tcrypt_test("wp256");
		break;

	case 25:
		ret += tcrypt_test("ecb(tnepres)");
		break;

	case 26:
		ret += tcrypt_test("ecb(anubis)");
		ret += tcrypt_test("cbc(anubis)");
		break;

	case 27:
		ret += tcrypt_test("tgr192");
		break;

	case 28:
		ret += tcrypt_test("tgr160");
		break;

	case 29:
		ret += tcrypt_test("tgr128");
		break;

	case 30:
		ret += tcrypt_test("ecb(xeta)");
		break;

	case 31:
		ret += tcrypt_test("pcbc(fcrypt)");
		break;

	case 32:
		ret += tcrypt_test("ecb(camellia)");
		ret += tcrypt_test("cbc(camellia)");
		ret += tcrypt_test("ctr(camellia)");
		ret += tcrypt_test("lrw(camellia)");
		ret += tcrypt_test("xts(camellia)");
		break;

	case 33:
		ret += tcrypt_test("sha224");
		break;

	case 34:
		ret += tcrypt_test("salsa20");
		break;

	case 35:
		ret += tcrypt_test("gcm(aes)");
		break;

	case 36:
		ret += tcrypt_test("lzo");
		break;

	case 37:
		ret += tcrypt_test("ccm(aes)");
		break;

	case 38:
		ret += tcrypt_test("cts(cbc(aes))");
		break;

        case 39:
		ret += tcrypt_test("rmd128");
		break;

        case 40:
		ret += tcrypt_test("rmd160");
		break;

	case 41:
		ret += tcrypt_test("rmd256");
		break;

	case 42:
		ret += tcrypt_test("rmd320");
		break;

	case 43:
		ret += tcrypt_test("ecb(seed)");
		break;

	case 44:
		ret += tcrypt_test("zlib");
		break;

	case 45:
		ret += tcrypt_test("rfc4309(ccm(aes))");
		break;

	case 46:
		ret += tcrypt_test("ghash");
		break;

	case 47:
		ret += tcrypt_test("crct10dif");
		break;

	case 100:
		ret += tcrypt_test("hmac(md5)");
		break;

	case 101:
		ret += tcrypt_test("hmac(sha1)");
		break;

	case 102:
		ret += tcrypt_test("hmac(sha256)");
		break;

	case 103:
		ret += tcrypt_test("hmac(sha384)");
		break;

	case 104:
		ret += tcrypt_test("hmac(sha512)");
		break;

	case 105:
		ret += tcrypt_test("hmac(sha224)");
		break;

	case 106:
		ret += tcrypt_test("xcbc(aes)");
		break;

	case 107:
		ret += tcrypt_test("hmac(rmd128)");
		break;

	case 108:
		ret += tcrypt_test("hmac(rmd160)");
		break;

	case 109:
		ret += tcrypt_test("vmac(aes)");
		break;

	case 110:
		ret += tcrypt_test("hmac(crc32)");
		break;

	case 150:
		ret += tcrypt_test("ansi_cprng");
		break;

	case 151:
		ret += tcrypt_test("rfc4106(gcm(aes))");
		break;

	case 152:
		ret += tcrypt_test("rfc4543(gcm(aes))");
		break;

	case 153:
		ret += tcrypt_test("cmac(aes)");
		break;

	case 154:
		ret += tcrypt_test("cmac(des3_ede)");
		break;

	case 155:
		ret += tcrypt_test("authenc(hmac(sha1),cbc(aes))");
		break;

	case 156:
		ret += tcrypt_test("authenc(hmac(md5),ecb(cipher_null))");
		break;

	case 157:
		ret += tcrypt_test("authenc(hmac(sha1),ecb(cipher_null))");
		break;
	case 181:
		ret += tcrypt_test("authenc(hmac(sha1),cbc(des))");
		break;
	case 182:
		ret += tcrypt_test("authenc(hmac(sha1),cbc(des3_ede))");
		break;
	case 183:
		ret += tcrypt_test("authenc(hmac(sha224),cbc(des))");
		break;
	case 184:
		ret += tcrypt_test("authenc(hmac(sha224),cbc(des3_ede))");
		break;
	case 185:
		ret += tcrypt_test("authenc(hmac(sha256),cbc(des))");
		break;
	case 186:
		ret += tcrypt_test("authenc(hmac(sha256),cbc(des3_ede))");
		break;
	case 187:
		ret += tcrypt_test("authenc(hmac(sha384),cbc(des))");
		break;
	case 188:
		ret += tcrypt_test("authenc(hmac(sha384),cbc(des3_ede))");
		break;
	case 189:
		ret += tcrypt_test("authenc(hmac(sha512),cbc(des))");
		break;
	case 190:
		ret += tcrypt_test("authenc(hmac(sha512),cbc(des3_ede))");
		break;
#endif

	if (strcmp(test, "cipher_speed_aes") == 0) {
		test_cipher_speed("ecb(aes)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("ecb(aes)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("cbc(aes)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("cbc(aes)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("lrw(aes)", ENCRYPT, sec, NULL, 0,
				speed_template_32_40_48);
		test_cipher_speed("lrw(aes)", DECRYPT, sec, NULL, 0,
				speed_template_32_40_48);
		test_cipher_speed("xts(aes)", ENCRYPT, sec, NULL, 0,
				speed_template_32_48_64);
		test_cipher_speed("xts(aes)", DECRYPT, sec, NULL, 0,
				speed_template_32_48_64);
		test_cipher_speed("ctr(aes)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("ctr(aes)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);

	} else if (strcmp(test, "cipher_speed_des3_ede") == 0) {

		test_cipher_speed("ecb(des3_ede)", ENCRYPT, sec,
				des3_speed_template, DES3_SPEED_VECTORS,
				speed_template_24);
		test_cipher_speed("ecb(des3_ede)", DECRYPT, sec,
				des3_speed_template, DES3_SPEED_VECTORS,
				speed_template_24);
		test_cipher_speed("cbc(des3_ede)", ENCRYPT, sec,
				des3_speed_template, DES3_SPEED_VECTORS,
				speed_template_24);
		test_cipher_speed("cbc(des3_ede)", DECRYPT, sec,
				des3_speed_template, DES3_SPEED_VECTORS,
				speed_template_24);
		test_cipher_speed("ctr(des3_ede)", ENCRYPT, sec,
				des3_speed_template, DES3_SPEED_VECTORS,
				speed_template_24);
		test_cipher_speed("ctr(des3_ede)", DECRYPT, sec,
				des3_speed_template, DES3_SPEED_VECTORS,
				speed_template_24);

	} else if (strcmp(test, "cipher_speed_twofish") == 0) {

		test_cipher_speed("ecb(twofish)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("ecb(twofish)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("cbc(twofish)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("cbc(twofish)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("ctr(twofish)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("ctr(twofish)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("lrw(twofish)", ENCRYPT, sec, NULL, 0,
				speed_template_32_40_48);
		test_cipher_speed("lrw(twofish)", DECRYPT, sec, NULL, 0,
				speed_template_32_40_48);
		test_cipher_speed("xts(twofish)", ENCRYPT, sec, NULL, 0,
				speed_template_32_48_64);
		test_cipher_speed("xts(twofish)", DECRYPT, sec, NULL, 0,
				speed_template_32_48_64);

	} else if (strcmp(test, "cipher_speed_blowfish") == 0) {

		test_cipher_speed("ecb(blowfish)", ENCRYPT, sec, NULL, 0,
				  speed_template_8_32);
		test_cipher_speed("ecb(blowfish)", DECRYPT, sec, NULL, 0,
				  speed_template_8_32);
		test_cipher_speed("cbc(blowfish)", ENCRYPT, sec, NULL, 0,
				  speed_template_8_32);
		test_cipher_speed("cbc(blowfish)", DECRYPT, sec, NULL, 0,
				  speed_template_8_32);
		test_cipher_speed("ctr(blowfish)", ENCRYPT, sec, NULL, 0,
				  speed_template_8_32);
		test_cipher_speed("ctr(blowfish)", DECRYPT, sec, NULL, 0,
				  speed_template_8_32);

	} else if (strcmp(test, "cipher_speed_des") == 0) {

		test_cipher_speed("ecb(des)", ENCRYPT, sec, NULL, 0,
				  speed_template_8);
		test_cipher_speed("ecb(des)", DECRYPT, sec, NULL, 0,
				  speed_template_8);
		test_cipher_speed("cbc(des)", ENCRYPT, sec, NULL, 0,
				  speed_template_8);
		test_cipher_speed("cbc(des)", DECRYPT, sec, NULL, 0,
				  speed_template_8);

	} else if (strcmp(test, "cipher_speed_camellia") == 0) {

		test_cipher_speed("ecb(camellia)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("ecb(camellia)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("cbc(camellia)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("cbc(camellia)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("ctr(camellia)", ENCRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("ctr(camellia)", DECRYPT, sec, NULL, 0,
				speed_template_16_24_32);
		test_cipher_speed("lrw(camellia)", ENCRYPT, sec, NULL, 0,
				speed_template_32_40_48);
		test_cipher_speed("lrw(camellia)", DECRYPT, sec, NULL, 0,
				speed_template_32_40_48);
		test_cipher_speed("xts(camellia)", ENCRYPT, sec, NULL, 0,
				speed_template_32_48_64);
		test_cipher_speed("xts(camellia)", DECRYPT, sec, NULL, 0,
				speed_template_32_48_64);

	} else if (strcmp(test, "cipher_speed_salsa20") == 0) {

		test_cipher_speed("salsa20", ENCRYPT, sec, NULL, 0,
				  speed_template_16_32);

	} else if (strcmp(test, "cipher_speed_serpent") == 0) {

		test_cipher_speed("ecb(serpent)", ENCRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("ecb(serpent)", DECRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("cbc(serpent)", ENCRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("cbc(serpent)", DECRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("ctr(serpent)", ENCRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("ctr(serpent)", DECRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("lrw(serpent)", ENCRYPT, sec, NULL, 0,
				  speed_template_32_48);
		test_cipher_speed("lrw(serpent)", DECRYPT, sec, NULL, 0,
				  speed_template_32_48);
		test_cipher_speed("xts(serpent)", ENCRYPT, sec, NULL, 0,
				  speed_template_32_64);
		test_cipher_speed("xts(serpent)", DECRYPT, sec, NULL, 0,
				  speed_template_32_64);

	} else if (strcmp(test, "cipher_speed_arc4") == 0) {

		test_cipher_speed("ecb(arc4)", ENCRYPT, sec, NULL, 0,
				  speed_template_8);

	} else if (strcmp(test, "cipher_speed_cast5") == 0) {

		test_cipher_speed("ecb(cast5)", ENCRYPT, sec, NULL, 0,
				  speed_template_8_16);
		test_cipher_speed("ecb(cast5)", DECRYPT, sec, NULL, 0,
				  speed_template_8_16);
		test_cipher_speed("cbc(cast5)", ENCRYPT, sec, NULL, 0,
				  speed_template_8_16);
		test_cipher_speed("cbc(cast5)", DECRYPT, sec, NULL, 0,
				  speed_template_8_16);
		test_cipher_speed("ctr(cast5)", ENCRYPT, sec, NULL, 0,
				  speed_template_8_16);
		test_cipher_speed("ctr(cast5)", DECRYPT, sec, NULL, 0,
				  speed_template_8_16);

	} else if (strcmp(test, "cipher_speed_cast6") == 0) {

		test_cipher_speed("ecb(cast6)", ENCRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("ecb(cast6)", DECRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("cbc(cast6)", ENCRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("cbc(cast6)", DECRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("ctr(cast6)", ENCRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("ctr(cast6)", DECRYPT, sec, NULL, 0,
				  speed_template_16_32);
		test_cipher_speed("lrw(cast6)", ENCRYPT, sec, NULL, 0,
				  speed_template_32_48);
		test_cipher_speed("lrw(cast6)", DECRYPT, sec, NULL, 0,
				  speed_template_32_48);
		test_cipher_speed("xts(cast6)", ENCRYPT, sec, NULL, 0,
				  speed_template_32_64);
		test_cipher_speed("xts(cast6)", DECRYPT, sec, NULL, 0,
				  speed_template_32_64);

	} else if (strcmp(test, "aead_speed_aes") == 0) {

		test_aead_speed("rfc4106(gcm(aes))", ENCRYPT, sec,
				NULL, 0, 16, 8, aead_speed_template_20);


	} else if (strcmp(test, "acipher_speed_aes") == 0) {

		test_acipher_speed("ecb(aes)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("ecb(aes)", DECRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("cbc(aes)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("cbc(aes)", DECRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("lrw(aes)", ENCRYPT, sec, NULL, 0,
				   speed_template_32_40_48);
		test_acipher_speed("lrw(aes)", DECRYPT, sec, NULL, 0,
				   speed_template_32_40_48);
		test_acipher_speed("xts(aes)", ENCRYPT, sec, NULL, 0,
				   speed_template_32_48_64);
		test_acipher_speed("xts(aes)", DECRYPT, sec, NULL, 0,
				   speed_template_32_48_64);
		test_acipher_speed("ctr(aes)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("ctr(aes)", DECRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("cfb(aes)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("cfb(aes)", DECRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("ofb(aes)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("ofb(aes)", DECRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("rfc3686(ctr(aes))", ENCRYPT, sec, NULL, 0,
				   speed_template_20_28_36);
		test_acipher_speed("rfc3686(ctr(aes))", DECRYPT, sec, NULL, 0,
				   speed_template_20_28_36);

	} else if (strcmp(test, "aciper_speed_des3_ede") == 0) {

		test_acipher_speed("ecb(des3_ede)", ENCRYPT, sec,
				   des3_speed_template, DES3_SPEED_VECTORS,
				   speed_template_24);
		test_acipher_speed("ecb(des3_ede)", DECRYPT, sec,
				   des3_speed_template, DES3_SPEED_VECTORS,
				   speed_template_24);
		test_acipher_speed("cbc(des3_ede)", ENCRYPT, sec,
				   des3_speed_template, DES3_SPEED_VECTORS,
				   speed_template_24);
		test_acipher_speed("cbc(des3_ede)", DECRYPT, sec,
				   des3_speed_template, DES3_SPEED_VECTORS,
				   speed_template_24);
		test_acipher_speed("cfb(des3_ede)", ENCRYPT, sec,
				   des3_speed_template, DES3_SPEED_VECTORS,
				   speed_template_24);
		test_acipher_speed("cfb(des3_ede)", DECRYPT, sec,
				   des3_speed_template, DES3_SPEED_VECTORS,
				   speed_template_24);
		test_acipher_speed("ofb(des3_ede)", ENCRYPT, sec,
				   des3_speed_template, DES3_SPEED_VECTORS,
				   speed_template_24);
		test_acipher_speed("ofb(des3_ede)", DECRYPT, sec,
				   des3_speed_template, DES3_SPEED_VECTORS,
				   speed_template_24);

	} else if (strcmp(test, "acipher_speed_des") == 0) {

		test_acipher_speed("ecb(des)", ENCRYPT, sec, NULL, 0,
				   speed_template_8);
		test_acipher_speed("ecb(des)", DECRYPT, sec, NULL, 0,
				   speed_template_8);
		test_acipher_speed("cbc(des)", ENCRYPT, sec, NULL, 0,
				   speed_template_8);
		test_acipher_speed("cbc(des)", DECRYPT, sec, NULL, 0,
				   speed_template_8);
		test_acipher_speed("cfb(des)", ENCRYPT, sec, NULL, 0,
				   speed_template_8);
		test_acipher_speed("cfb(des)", DECRYPT, sec, NULL, 0,
				   speed_template_8);
		test_acipher_speed("ofb(des)", ENCRYPT, sec, NULL, 0,
				   speed_template_8);
		test_acipher_speed("ofb(des)", DECRYPT, sec, NULL, 0,
				   speed_template_8);

	} else if (strcmp(test, "acipher_speed_serpent") == 0) {

		test_acipher_speed("ecb(serpent)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("ecb(serpent)", DECRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("cbc(serpent)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("cbc(serpent)", DECRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("ctr(serpent)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("ctr(serpent)", DECRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("lrw(serpent)", ENCRYPT, sec, NULL, 0,
				   speed_template_32_48);
		test_acipher_speed("lrw(serpent)", DECRYPT, sec, NULL, 0,
				   speed_template_32_48);
		test_acipher_speed("xts(serpent)", ENCRYPT, sec, NULL, 0,
				   speed_template_32_64);
		test_acipher_speed("xts(serpent)", DECRYPT, sec, NULL, 0,
				   speed_template_32_64);

	} else if (strcmp(test, "acipher_speed_twofish") == 0) {

		test_acipher_speed("ecb(twofish)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("ecb(twofish)", DECRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("cbc(twofish)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("cbc(twofish)", DECRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("ctr(twofish)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("ctr(twofish)", DECRYPT, sec, NULL, 0,
				   speed_template_16_24_32);
		test_acipher_speed("lrw(twofish)", ENCRYPT, sec, NULL, 0,
				   speed_template_32_40_48);
		test_acipher_speed("lrw(twofish)", DECRYPT, sec, NULL, 0,
				   speed_template_32_40_48);
		test_acipher_speed("xts(twofish)", ENCRYPT, sec, NULL, 0,
				   speed_template_32_48_64);
		test_acipher_speed("xts(twofish)", DECRYPT, sec, NULL, 0,
				   speed_template_32_48_64);

	} else if (strcmp(test, "acipher_speed_arc4") == 0) {

		test_acipher_speed("ecb(arc4)", ENCRYPT, sec, NULL, 0,
				   speed_template_8);

	} else if (strcmp(test, "acipher_speed_cast5") == 0) {

		test_acipher_speed("ecb(cast5)", ENCRYPT, sec, NULL, 0,
				   speed_template_8_16);
		test_acipher_speed("ecb(cast5)", DECRYPT, sec, NULL, 0,
				   speed_template_8_16);
		test_acipher_speed("cbc(cast5)", ENCRYPT, sec, NULL, 0,
				   speed_template_8_16);
		test_acipher_speed("cbc(cast5)", DECRYPT, sec, NULL, 0,
				   speed_template_8_16);
		test_acipher_speed("ctr(cast5)", ENCRYPT, sec, NULL, 0,
				   speed_template_8_16);
		test_acipher_speed("ctr(cast5)", DECRYPT, sec, NULL, 0,
				   speed_template_8_16);

	} else if (strcmp(test, "acipher_speed_cast6") == 0) {

		test_acipher_speed("ecb(cast6)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("ecb(cast6)", DECRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("cbc(cast6)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("cbc(cast6)", DECRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("ctr(cast6)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("ctr(cast6)", DECRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("lrw(cast6)", ENCRYPT, sec, NULL, 0,
				   speed_template_32_48);
		test_acipher_speed("lrw(cast6)", DECRYPT, sec, NULL, 0,
				   speed_template_32_48);
		test_acipher_speed("xts(cast6)", ENCRYPT, sec, NULL, 0,
				   speed_template_32_64);
		test_acipher_speed("xts(cast6)", DECRYPT, sec, NULL, 0,
				   speed_template_32_64);

	} else if (strcmp(test, "acipher_speed_camellia") == 0) {

		test_acipher_speed("ecb(camellia)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("ecb(camellia)", DECRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("cbc(camellia)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("cbc(camellia)", DECRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("ctr(camellia)", ENCRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("ctr(camellia)", DECRYPT, sec, NULL, 0,
				   speed_template_16_32);
		test_acipher_speed("lrw(camellia)", ENCRYPT, sec, NULL, 0,
				   speed_template_32_48);
		test_acipher_speed("lrw(camellia)", DECRYPT, sec, NULL, 0,
				   speed_template_32_48);
		test_acipher_speed("xts(camellia)", ENCRYPT, sec, NULL, 0,
				   speed_template_32_64);
		test_acipher_speed("xts(camellia)", DECRYPT, sec, NULL, 0,
				   speed_template_32_64);

	} else if (strcmp(test, "acipher_speed_blowfish") == 0) {

		test_acipher_speed("ecb(blowfish)", ENCRYPT, sec, NULL, 0,
				   speed_template_8_32);
		test_acipher_speed("ecb(blowfish)", DECRYPT, sec, NULL, 0,
				   speed_template_8_32);
		test_acipher_speed("cbc(blowfish)", ENCRYPT, sec, NULL, 0,
				   speed_template_8_32);
		test_acipher_speed("cbc(blowfish)", DECRYPT, sec, NULL, 0,
				   speed_template_8_32);
		test_acipher_speed("ctr(blowfish)", ENCRYPT, sec, NULL, 0,
				   speed_template_8_32);
		test_acipher_speed("ctr(blowfish)", DECRYPT, sec, NULL, 0,
				   speed_template_8_32);

	} else
		return 0;

	return 1;

}

char *fixed_tests[] = {
	/* generated with
	 * sed -n 's/\t\(} else \)\?if (strcmp(test, \(".*"\)) == 0) {/\t\2,/p' crypto/tcrypt.c
	 */
	"cipher_speed_aes",
	"cipher_speed_des3_ede",
	"cipher_speed_twofish",
	"cipher_speed_blowfish",
	"cipher_speed_des",
	"cipher_speed_camellia",
	"cipher_speed_salsa20",
	"cipher_speed_serpent",
	"cipher_speed_arc4",
	"cipher_speed_cast5",
	"cipher_speed_cast6",
	"aead_speed_aes",
	"acipher_speed_aes",
	"aciper_speed_des3_ede",
	"acipher_speed_des",
	"acipher_speed_serpent",
	"acipher_speed_twofish",
	"acipher_speed_arc4",
	"acipher_speed_cast5",
	"acipher_speed_cast6",
	"acipher_speed_camellia",
	"acipher_speed_blowfish",
};

static int do_alg_test(const char *alg, u32 type, u32 mask)
{
	return crypto_has_alg(alg, type, mask ?: CRYPTO_ALG_TYPE_MASK) ?
	       0 : -ENOENT;
}


int tcrypt_open_generic(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;
	return 0;
}

static ssize_t
tcrypt_sec_read(struct file *filp, char __user *ubuf,
				 size_t cnt, loff_t *ppos)
{
	char buf[64];
	int r;

	r = scnprintf(buf, sizeof(buf), "%u\n", sec);

	return simple_read_from_buffer(ubuf, cnt, ppos, buf, r);
}


static ssize_t
tcrypt_sec_write(struct file *filp, const char __user *ubuf,
				  size_t cnt, loff_t *ppos)
{
	int ret;

	ret = kstrtouint_from_user(ubuf, cnt, 10, &sec);
	if (ret)
		return ret;

	*ppos += cnt;

	return cnt;
}

static const struct file_operations tcrypt_sec_fops = {
	.read		= tcrypt_sec_read,
	.write		= tcrypt_sec_write,
};


static void
clear_buffer(void)
{
	size_t i, stop;

	if (tcrypt_data.cur_stop == tcrypt_data.cur_start)
		return;

	mutex_lock_interruptible(&tcrypt_output_lock);
	if (tcrypt_data.cur_stop < tcrypt_data.cur_start)
		stop = tcrypt_data.cur_stop + OUTPUT_BUFFER_LINES;
	else
		stop = tcrypt_data.cur_stop;

	for (i = tcrypt_data.cur_start; i < stop; ++i)
		kfree(tcrypt_data.output[i % OUTPUT_BUFFER_LINES]);

	tcrypt_data.cur_start = 0;
	tcrypt_data.cur_stop = 0;
	mutex_unlock(&tcrypt_output_lock);
}

static int launch_test(const char *buf)
{

	size_t ret = -EINVAL;
	int i;

	if (strcmp(buf, "list") == 0) {
		mutex_lock_interruptible(&tcrypt_output_lock);
		tc_printf_unlock("hash_speed_<name_of_hash>\n");
		tc_printf_unlock("ahash_speed_<name_of_hash>\n");
		for (i = 0; i < ARRAY_SIZE(fixed_tests); i++) {
			tc_printf_unlock("%s\n", fixed_tests[i]);
		}

		mutex_unlock(&tcrypt_output_lock);
		return 0;
	} else if (strcmp(buf, "clear") == 0) {
		clear_buffer();
		return 0;
	} else if (memcmp(buf, "hash_speed_", 11) == 0) {
		buf += 11;
		if (!crypto_has_hash(buf, 0, 0)) {
			tc_printf("Hash %s does not exist.\n", buf);
			return ret;
		}

		if (strcmp(buf, "ghash-generic") == 0)
			test_hash_speed(buf, sec,
				generic_hash_speed_template, 16);
		else
			test_hash_speed(buf, sec,
				generic_hash_speed_template, 0);

		return 0;
	} else if (memcmp(buf, "ahash_speed_", 12) == 0) {
		buf += 12;
		if (!crypto_has_hash(buf, 0, CRYPTO_ALG_ASYNC)) {
			tc_printf("Hash %s does not exist.\n", buf);
			return ret;
		}

		test_ahash_speed(buf, sec, generic_hash_speed_template);
		return 0;
	} else if (do_test(buf))
		return 0;


	return ret;
}

static ssize_t
tcrypt_set_command_write(struct file *filp, const char __user *ubuf,
			size_t cnt, loff_t *ppos)
{
	char buf[COMMAND_BUFFER_SIZE + 1];
	int i;
	size_t ret;
	int err;

	ret = cnt;

	if (cnt > COMMAND_BUFFER_SIZE)
		cnt = COMMAND_BUFFER_SIZE;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;

	buf[cnt] = 0;

	/* strip ending whitespace. */
	for (i = cnt - 1; i > 0 && isspace(buf[i]); i--)
		buf[i] = 0;

	err = launch_test(buf);
	if (err < 0)
		return err;

	*ppos += ret;

	return ret;
}

static const struct file_operations set_tcrypt_fops = {
	.write		= tcrypt_set_command_write,
	.llseek		= generic_file_llseek,
};


static void *
s_start(struct seq_file *m, loff_t *pos)
{
	size_t *ptr;

	mutex_lock_interruptible(&tcrypt_output_lock);
	if (*pos >= get_num_elements())
		return NULL;

	ptr = kmalloc(sizeof(size_t), GFP_KERNEL);
	if (!ptr)
		return NULL;

	*ptr = *pos;
	return ptr;
}

static void *
s_next(struct seq_file *m, void *v, loff_t *pos)
{
	size_t *ptr = v;

	++*pos;
	if (*pos >= get_num_elements())
		return NULL;

	*ptr = *pos;
	return ptr;
}

static int
s_show(struct seq_file *m, void *v)
{
	size_t *ptr = v;
	size_t temp = (tcrypt_data.cur_start + *ptr) % OUTPUT_BUFFER_LINES;

	seq_printf(m, "%s", tcrypt_data.output[temp]);
	return 0;

}

static void
s_stop(struct seq_file *m, void *p)
{
	kfree(p);
	mutex_unlock(&tcrypt_output_lock);
}



static const struct seq_operations tcrypt_seq_output_ops = {
	.start		= s_start,
	.next		= s_next,
	.stop		= s_stop,
	.show		= s_show,
};


static int
tcrypt_get_output_open(struct inode *inode, struct file *file)
{

	return seq_open(file, &tcrypt_seq_output_ops);
}


static const struct file_operations show_tcrypt_fops = {
	.open		= tcrypt_get_output_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init tcrypt_mod_init(void)
{
	int i;

	struct dentry *temp_dentry;

	tcrypt_data.cur_start = 0;
	tcrypt_data.cur_stop = 0;

	d_basetcrypt = debugfs_create_dir("tcrypto", NULL);
	if (!d_basetcrypt)
		goto err_free;

	readme_blob.data = read_str;
	readme_blob.size = strlen(read_str);
	temp_dentry = debugfs_create_blob("README", 0444, d_basetcrypt, &readme_blob);
	if (!temp_dentry)
		goto err_free;

	temp_dentry = debugfs_create_file("command", 0644, d_basetcrypt,
						NULL, &set_tcrypt_fops);
	if (!temp_dentry)
		goto err_free;

	temp_dentry = debugfs_create_file("output", 0644, d_basetcrypt,
						NULL, &show_tcrypt_fops);
	if (!temp_dentry)
		goto err_free;

	temp_dentry = debugfs_create_file("seconds", 0644, d_basetcrypt,
						NULL, &tcrypt_sec_fops);
	if (!temp_dentry)
		goto err_free;


	for (i = 0; i < TVMEMSIZE; i++) {
		tvmem[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!tvmem[i])
			goto err_free;
	}

	return 0;

err_free:
	pr_err("tcrypt: Unable to allocate memory (init)\n");
	for (i = 0; i < TVMEMSIZE && tvmem[i]; i++)
		free_page((unsigned long)tvmem[i]);
	if (d_basetcrypt)
		debugfs_remove_recursive(d_basetcrypt);

	return -ENOMEM;
}

/*
 * Release debugfs and tvmem
 */
static void __exit tcrypt_mod_fini(void)
{
	int i;

	debugfs_remove_recursive(d_basetcrypt);
	clear_buffer();
	for (i = 0; i < TVMEMSIZE && tvmem[i]; i++)
		free_page((unsigned long)tvmem[i]);
}

module_init(tcrypt_mod_init);
module_exit(tcrypt_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Quick & dirty crypto testing module");
MODULE_AUTHOR("James Morris <jmorris@intercode.com.au>");
