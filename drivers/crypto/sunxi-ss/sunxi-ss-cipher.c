/*
 * sunxi-ss-cipher.c - hardware cryptographic accelerator for Allwinner A20 SoC
 *
 * Copyright (C) 2013-2014 Corentin LABBE <clabbe.montjoie@gmail.com>
 *
 * This file add support for AES cipher with 128,192,256 bits
 * keysize in CBC mode.
 * Add support also for DES and 3DES in CBC mode.
 *
 * You could find the datasheet in Documentation/arm/sunxi/README
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include "sunxi-ss.h"

extern struct sunxi_ss_ctx *ss;

static int sunxi_ss_cipher(struct ablkcipher_request *areq, u32 mode)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sunxi_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	const char *cipher_type;

	if (areq->nbytes == 0)
		return 0;

	if (areq->info == NULL) {
		dev_err(ss->dev, "ERROR: Empty IV\n");
		return -EINVAL;
	}

	if (areq->src == NULL || areq->dst == NULL) {
		dev_err(ss->dev, "ERROR: Some SGs are NULL\n");
		return -EINVAL;
	}

	cipher_type = crypto_tfm_alg_name(crypto_ablkcipher_tfm(tfm));

	if (strcmp("cbc(aes)", cipher_type) == 0) {
		mode |= SS_OP_AES | SS_CBC | SS_ENABLED | op->keymode;
		return sunxi_ss_aes_poll(areq, mode);
	}

	if (strcmp("cbc(des)", cipher_type) == 0) {
		mode |= SS_OP_DES | SS_CBC | SS_ENABLED | op->keymode;
		return sunxi_ss_des_poll(areq, mode);
	}

	if (strcmp("cbc(des3_ede)", cipher_type) == 0) {
		mode |= SS_OP_3DES | SS_CBC | SS_ENABLED | op->keymode;
		return sunxi_ss_des_poll(areq, mode);
	}

	dev_err(ss->dev, "ERROR: Cipher %s not handled\n", cipher_type);
	return -EINVAL;
}

int sunxi_ss_cipher_encrypt(struct ablkcipher_request *areq)
{
	return sunxi_ss_cipher(areq, SS_ENCRYPTION);
}

int sunxi_ss_cipher_decrypt(struct ablkcipher_request *areq)
{
	return sunxi_ss_cipher(areq, SS_DECRYPTION);
}

int sunxi_ss_cipher_init(struct crypto_tfm *tfm)
{
	struct sunxi_tfm_ctx *op = crypto_tfm_ctx(tfm);

	memset(op, 0, sizeof(struct sunxi_tfm_ctx));
	return 0;
}

/*
 * Optimized function for the case where we have only one SG,
 * so we can use kmap_atomic
 */
static int sunxi_ss_aes_poll_atomic(struct ablkcipher_request *areq)
{
	u32 spaces;
	struct scatterlist *in_sg = areq->src;
	struct scatterlist *out_sg = areq->dst;
	void *src_addr;
	void *dst_addr;
	unsigned int ileft = areq->nbytes;
	unsigned int oleft = areq->nbytes;
	unsigned int todo;
	u32 *src32;
	u32 *dst32;
	u32 rx_cnt = 32;
	u32 tx_cnt = 0;
	int i;

	src_addr = kmap_atomic(sg_page(in_sg)) + in_sg->offset;
	if (src_addr == NULL) {
		dev_err(ss->dev, "kmap_atomic error for src SG\n");
		writel(0, ss->base + SS_CTL);
		mutex_unlock(&ss->lock);
		return -EINVAL;
	}

	dst_addr = kmap_atomic(sg_page(out_sg)) + out_sg->offset;
	if (dst_addr == NULL) {
		dev_err(ss->dev, "kmap_atomic error for dst SG\n");
		writel(0, ss->base + SS_CTL);
		kunmap_atomic(src_addr);
		mutex_unlock(&ss->lock);
		return -EINVAL;
	}

	src32 = (u32 *)src_addr;
	dst32 = (u32 *)dst_addr;
	ileft = areq->nbytes / 4;
	oleft = areq->nbytes / 4;
	i = 0;
	do {
		if (ileft > 0 && rx_cnt > 0) {
			todo = min(rx_cnt, ileft);
			ileft -= todo;
			do {
				writel_relaxed(*src32++,
						ss->base +
						SS_RXFIFO);
				todo--;
			} while (todo > 0);
		}
		if (tx_cnt > 0) {
			todo = min(tx_cnt, oleft);
			oleft -= todo;
			do {
				*dst32++ = readl_relaxed(ss->base +
						SS_TXFIFO);
				todo--;
			} while (todo > 0);
		}
		spaces = readl_relaxed(ss->base + SS_FCSR);
		rx_cnt = SS_RXFIFO_SPACES(spaces);
		tx_cnt = SS_TXFIFO_SPACES(spaces);
	} while (oleft > 0);
	writel(0, ss->base + SS_CTL);
	kunmap_atomic(src_addr);
	kunmap_atomic(dst_addr);
	mutex_unlock(&ss->lock);
	return 0;
}

int sunxi_ss_aes_poll(struct ablkcipher_request *areq, u32 mode)
{
	u32 spaces;
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sunxi_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	unsigned int ivsize = crypto_ablkcipher_ivsize(tfm);
	/* when activating SS, the default FIFO space is 32 */
	u32 rx_cnt = 32;
	u32 tx_cnt = 0;
	u32 v;
	int i;
	struct scatterlist *in_sg = areq->src;
	struct scatterlist *out_sg = areq->dst;
	void *src_addr;
	void *dst_addr;
	unsigned int ileft = areq->nbytes;
	unsigned int oleft = areq->nbytes;
	unsigned int sgileft = areq->src->length;
	unsigned int sgoleft = areq->dst->length;
	unsigned int todo;
	u32 *src32;
	u32 *dst32;

	mutex_lock(&ss->lock);

	for (i = 0; i < op->keylen; i += 4)
		writel(*(op->key + i/4), ss->base + SS_KEY0 + i);

	if (areq->info != NULL) {
		for (i = 0; i < 4 && i < ivsize / 4; i++) {
			v = *(u32 *)(areq->info + i * 4);
			writel(v, ss->base + SS_IV0 + i * 4);
		}
	}
	writel(mode, ss->base + SS_CTL);

	/* If we have only one SG, we can use kmap_atomic */
	if (sg_next(in_sg) == NULL && sg_next(out_sg) == NULL)
		return sunxi_ss_aes_poll_atomic(areq);

	/*
	 * If we have more than one SG, we cannot use kmap_atomic since
	 * we hold the mapping too long
	 */
	src_addr = kmap(sg_page(in_sg)) + in_sg->offset;
	if (src_addr == NULL) {
		dev_err(ss->dev, "KMAP error for src SG\n");
		mutex_unlock(&ss->lock);
		return -EINVAL;
	}
	dst_addr = kmap(sg_page(out_sg)) + out_sg->offset;
	if (dst_addr == NULL) {
		kunmap(sg_page(in_sg));
		dev_err(ss->dev, "KMAP error for dst SG\n");
		mutex_unlock(&ss->lock);
		return -EINVAL;
	}
	src32 = (u32 *)src_addr;
	dst32 = (u32 *)dst_addr;
	ileft = areq->nbytes / 4;
	oleft = areq->nbytes / 4;
	sgileft = in_sg->length / 4;
	sgoleft = out_sg->length / 4;
	do {
		spaces = readl_relaxed(ss->base + SS_FCSR);
		rx_cnt = SS_RXFIFO_SPACES(spaces);
		tx_cnt = SS_TXFIFO_SPACES(spaces);
		todo = min3(rx_cnt, ileft, sgileft);
		if (todo > 0) {
			ileft -= todo;
			sgileft -= todo;
		}
		while (todo > 0) {
			writel_relaxed(*src32++, ss->base + SS_RXFIFO);
			todo--;
		}
		if (in_sg != NULL && sgileft == 0 && ileft > 0) {
			kunmap(sg_page(in_sg));
			in_sg = sg_next(in_sg);
			while (in_sg != NULL && in_sg->length == 0)
				in_sg = sg_next(in_sg);
			if (in_sg != NULL && ileft > 0) {
				src_addr = kmap(sg_page(in_sg)) + in_sg->offset;
				if (src_addr == NULL) {
					dev_err(ss->dev, "ERROR: KMAP for src SG\n");
					mutex_unlock(&ss->lock);
					return -EINVAL;
				}
				src32 = src_addr;
				sgileft = in_sg->length / 4;
			}
		}
		/* do not test oleft since when oleft == 0 we have finished */
		todo = min3(tx_cnt, oleft, sgoleft);
		if (todo > 0) {
			oleft -= todo;
			sgoleft -= todo;
		}
		while (todo > 0) {
			*dst32++ = readl_relaxed(ss->base + SS_TXFIFO);
			todo--;
		}
		if (out_sg != NULL && sgoleft == 0 && oleft >= 0) {
			kunmap(sg_page(out_sg));
			out_sg = sg_next(out_sg);
			while (out_sg != NULL && out_sg->length == 0)
				out_sg = sg_next(out_sg);
			if (out_sg != NULL && oleft > 0) {
				dst_addr = kmap(sg_page(out_sg)) +
					out_sg->offset;
				if (dst_addr == NULL) {
					dev_err(ss->dev, "KMAP error\n");
					mutex_unlock(&ss->lock);
					return -EINVAL;
				}
				dst32 = dst_addr;
				sgoleft = out_sg->length / 4;
			}
		}
	} while (oleft > 0);

	writel_relaxed(0, ss->base + SS_CTL);
	mutex_unlock(&ss->lock);
	return 0;
}

/*
 * Pure CPU way of doing DES/3DES with SS
 * Since DES and 3DES SGs could be smaller than 4 bytes, I use sg_copy_to_buffer
 * for "linearize" them.
 * The problem with that is that I alloc (2 x areq->nbytes) for buf_in/buf_out
 * TODO: change this system, I need to support other mode than CBC where len
 * is not a multiple of 4 and the hack of linearize use too much memory
 * SGsrc -> buf_in -> SS -> buf_out -> SGdst
 */
int sunxi_ss_des_poll(struct ablkcipher_request *areq, u32 mode)
{
	u32 value, spaces;
	size_t nb_in_sg_tx, nb_in_sg_rx;
	size_t ir, it;
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sunxi_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	unsigned int ivsize = crypto_ablkcipher_ivsize(tfm);
	u32 tx_cnt = 0;
	u32 rx_cnt = 0;
	u32 v;
	int i;
	int no_chunk = 1;
	struct scatterlist *in_sg = areq->src;
	struct scatterlist *out_sg = areq->dst;

	/*
	 * if we have only SGs with size multiple of 4,
	 * we can use the SS AES function
	 */
	while (in_sg != NULL && no_chunk == 1) {
		if ((in_sg->length % 4) != 0)
			no_chunk = 0;
		in_sg = sg_next(in_sg);
	}
	while (out_sg != NULL && no_chunk == 1) {
		if ((out_sg->length % 4) != 0)
			no_chunk = 0;
		out_sg = sg_next(out_sg);
	}

	if (no_chunk == 1)
		return sunxi_ss_aes_poll(areq, mode);

	in_sg = areq->src;
	out_sg = areq->dst;

	nb_in_sg_rx = sg_nents(in_sg);
	nb_in_sg_tx = sg_nents(out_sg);

	/*
	 * buf_in and buf_out are allocated only one time
	 * then we keep the buffer until driver end
	 * the allocation can only grow more
	 * we do not reduce it for simplification
	 */
	mutex_lock(&ss->bufin_lock);
	if (ss->buf_in == NULL) {
		ss->buf_in = kmalloc(areq->nbytes, GFP_KERNEL);
		ss->buf_in_size = areq->nbytes;
	} else {
		if (areq->nbytes > ss->buf_in_size) {
			kfree(ss->buf_in);
			ss->buf_in = kmalloc(areq->nbytes, GFP_KERNEL);
			ss->buf_in_size = areq->nbytes;
		}
	}
	if (ss->buf_in == NULL) {
		ss->buf_in_size = 0;
		mutex_unlock(&ss->bufin_lock);
		dev_err(ss->dev, "Unable to allocate pages.\n");
		return -ENOMEM;
	}
	mutex_lock(&ss->bufout_lock);
	if (ss->buf_out == NULL) {
		ss->buf_out = kmalloc(areq->nbytes, GFP_KERNEL);
		if (ss->buf_out == NULL) {
			ss->buf_out_size = 0;
			mutex_unlock(&ss->bufin_lock);
			mutex_unlock(&ss->bufout_lock);
			dev_err(ss->dev, "Unable to allocate pages.\n");
			return -ENOMEM;
		}
		ss->buf_out_size = areq->nbytes;
	} else {
		if (areq->nbytes > ss->buf_out_size) {
			kfree(ss->buf_out);
			ss->buf_out = kmalloc(areq->nbytes, GFP_KERNEL);
			if (ss->buf_out == NULL) {
				ss->buf_out_size = 0;
				mutex_unlock(&ss->bufin_lock);
				mutex_unlock(&ss->bufout_lock);
				dev_err(ss->dev, "Unable to allocate pages.\n");
				return -ENOMEM;
			}
			ss->buf_out_size = areq->nbytes;
		}
	}

	sg_copy_to_buffer(areq->src, nb_in_sg_rx, ss->buf_in, areq->nbytes);

	ir = 0;
	it = 0;
	mutex_lock(&ss->lock);

	for (i = 0; i < op->keylen; i += 4)
		writel(*(op->key + i/4), ss->base + SS_KEY0 + i);
	if (areq->info != NULL) {
		for (i = 0; i < 4 && i < ivsize / 4; i++) {
			v = *(u32 *)(areq->info + i * 4);
			writel(v, ss->base + SS_IV0 + i * 4);
		}
	}
	writel(mode, ss->base + SS_CTL);

	do {
		if (rx_cnt == 0 || tx_cnt == 0) {
			spaces = readl(ss->base + SS_FCSR);
			rx_cnt = SS_RXFIFO_SPACES(spaces);
			tx_cnt = SS_TXFIFO_SPACES(spaces);
		}
		if (rx_cnt > 0 && ir < areq->nbytes) {
			do {
				value = *(u32 *)(ss->buf_in + ir);
				writel(value, ss->base + SS_RXFIFO);
				ir += 4;
				rx_cnt--;
			} while (rx_cnt > 0 && ir < areq->nbytes);
		}
		if (tx_cnt > 0 && it < areq->nbytes) {
			do {
				value = readl(ss->base + SS_TXFIFO);
				*(u32 *)(ss->buf_out + it) = value;
				it += 4;
				tx_cnt--;
			} while (tx_cnt > 0 && it < areq->nbytes);
		}
		if (ir == areq->nbytes) {
			mutex_unlock(&ss->bufin_lock);
			ir++;
		}
	} while (it < areq->nbytes);

	writel(0, ss->base + SS_CTL);
	mutex_unlock(&ss->lock);

	/*
	 * a simple optimization, since we dont need the hardware for this copy
	 * we release the lock and do the copy. With that we gain 5/10% perf
	 */
	sg_copy_from_buffer(areq->dst, nb_in_sg_tx, ss->buf_out, areq->nbytes);

	mutex_unlock(&ss->bufout_lock);
	return 0;
}

/* check and set the AES key, prepare the mode to be used */
int sunxi_ss_aes_setkey(struct crypto_ablkcipher *tfm, const u8 *key,
		unsigned int keylen)
{
	struct sunxi_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);

	switch (keylen) {
	case 128 / 8:
		op->keymode = SS_AES_128BITS;
		break;
	case 192 / 8:
		op->keymode = SS_AES_192BITS;
		break;
	case 256 / 8:
		op->keymode = SS_AES_256BITS;
		break;
	default:
		dev_err(ss->dev, "ERROR: Invalid keylen %u\n", keylen);
		crypto_ablkcipher_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	op->keylen = keylen;
	memcpy(op->key, key, keylen);
	return 0;
}

/* check and set the DES key, prepare the mode to be used */
int sunxi_ss_des_setkey(struct crypto_ablkcipher *tfm, const u8 *key,
		unsigned int keylen)
{
	struct sunxi_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);

	if (keylen != DES_KEY_SIZE) {
		dev_err(ss->dev, "Invalid keylen %u\n", keylen);
		crypto_ablkcipher_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	op->keylen = keylen;
	memcpy(op->key, key, keylen);
	return 0;
}

/* check and set the 3DES key, prepare the mode to be used */
int sunxi_ss_des3_setkey(struct crypto_ablkcipher *tfm, const u8 *key,
		unsigned int keylen)
{
	struct sunxi_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);

	if (keylen != 3 * DES_KEY_SIZE) {
		dev_err(ss->dev, "Invalid keylen %u\n", keylen);
		crypto_ablkcipher_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}
	op->keylen = keylen;
	memcpy(op->key, key, keylen);
	return 0;
}
