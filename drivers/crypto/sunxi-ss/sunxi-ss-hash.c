/*
 * sunxi-ss-hash.c - hardware cryptographic accelerator for Allwinner A20 SoC
 *
 * Copyright (C) 2013-2014 Corentin LABBE <clabbe.montjoie@gmail.com>
 *
 * This file add support for MD5 and SHA1.
 *
 * You could find the datasheet in Documentation/arm/sunxi/README
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include "sunxi-ss.h"

/* This is a totaly arbitrary value */
#define SS_TIMEOUT 100

extern struct sunxi_ss_ctx *ss;

int sunxi_hash_crainit(struct crypto_tfm *tfm)
{
	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
			sizeof(struct sunxi_req_ctx));
	return 0;
}

/* sunxi_hash_init: initialize request context */
int sunxi_hash_init(struct ahash_request *areq)
{
	const char *hash_type;
	struct sunxi_req_ctx *op = ahash_request_ctx(areq);

	memset(op, 0, sizeof(struct sunxi_req_ctx));

	hash_type = crypto_tfm_alg_name(areq->base.tfm);

	if (strcmp(hash_type, "sha1") == 0)
		op->mode = SS_OP_SHA1;
	if (strcmp(hash_type, "md5") == 0)
		op->mode = SS_OP_MD5;
	if (op->mode == 0)
		return -EINVAL;

	return 0;
}

static u32 rx_cnt;

inline void ss_writer(const u32 v)
{
	u32 spaces;

	writel(v, ss->base + SS_RXFIFO);
	rx_cnt--;
	while (rx_cnt == 0) {
		spaces = readl_relaxed(ss->base + SS_FCSR);
		rx_cnt = SS_RXFIFO_SPACES(spaces);
	}
}

inline void ss_writer_relaxed(const u32 v)
{
	u32 spaces;

	writel_relaxed(v, ss->base + SS_RXFIFO);
	rx_cnt--;
	while (rx_cnt == 0) {
		spaces = readl_relaxed(ss->base + SS_FCSR);
		rx_cnt = SS_RXFIFO_SPACES(spaces);
	}
}

/*
 * sunxi_hash_update: update hash engine
 *
 * Could be used for both SHA1 and MD5
 * Write data by step of 32bits and put then in the SS.
 *
 * Since we cannot leave partial data and hash state in the engine,
 * we need to get the hash state at the end of this function.
 * After some work, I have found that we can get the hash state every 64o
 *
 * So the first work is to get the number of bytes to write to SS modulo 64
 * The extra bytes will go to two different destination:
 * op->wait for full 32bits word
 * op->wb (waiting bytes) for partial 32 bits word
 * So we can have up to (64/4)-1 op->wait words and 0/1/2/3 bytes in wb
 *
 * So at the begin of update()
 * if op->nwait * 4 + areq->nbytes < 64
 * => all data writed to wait buffers and end=0
 * if not write all nwait to the device and position end to complete to 64o
 *
 * example 1:
 * update1 60o => nwait=15
 * update2 60o => need one more word to have 64o
 * end=4
 * so write all data in op->wait and one word of SGs
 * write remaining data in op->wait
 * final state op->nwait=14
 */
int sunxi_hash_update(struct ahash_request *areq)
{
	u32 v, ivmode = 0;
	unsigned int i = 0;
	/*
	 * i is the total bytes read from SGs, to be compared to areq->nbytes
	 * i is important because we cannot rely on SG length since the sum of
	 * SG->length could be greater than areq->nbytes
	 */

	struct sunxi_req_ctx *op = ahash_request_ctx(areq);
	struct scatterlist *in_sg;
	unsigned int in_i = 0; /* advancement in the current SG */
	u64 end;
	/*
	 * end is the position when we need to stop writing to the device,
	 * to be compared to i
	 */
	int in_r;
	void *src_addr;

	dev_dbg(ss->dev, "%s %s bc=%llu len=%u mode=%x bw=%u ww=%u",
			__func__, crypto_tfm_alg_name(areq->base.tfm),
			op->byte_count, areq->nbytes, op->mode,
			op->nbw, op->nwait);

	if (areq->nbytes == 0)
		return 0;

	end = ((areq->nbytes + op->nwait * 4 + op->nbw) / 64) * 64
		- op->nbw - op->nwait * 4;

	if (end > areq->nbytes || areq->nbytes - end > 63) {
		dev_err(ss->dev, "ERROR: Bound error %llu %u\n",
				end, areq->nbytes);
		return -EINVAL;
	}

	if (op->nwait > 0 && end > 0) {
		/* a precedent update was done */
		for (i = 0; i < op->nwait; i++) {
			ss_writer(op->wait[i]);
			op->byte_count += 4;
		}
		op->nwait = 0;
	}

	mutex_lock(&ss->lock);
	/*
	 * if some data have been processed before,
	 * we need to restore the partial hash state
	 */
	if (op->byte_count > 0) {
		ivmode = SS_IV_ARBITRARY;
		for (i = 0; i < 5; i++)
			writel(op->hash[i], ss->base + SS_IV0 + i * 4);
	}
	/* Enable the device */
	writel(op->mode | SS_ENABLED | ivmode, ss->base + SS_CTL);

	rx_cnt = 0;
	i = 0;

	in_sg = areq->src;
	src_addr = kmap(sg_page(in_sg)) + in_sg->offset;
	if (src_addr == NULL) {
		mutex_unlock(&ss->lock);
		dev_err(ss->dev, "ERROR: Cannot kmap source buffer\n");
		return -EFAULT;
	}
	do {
		/*
		 * step 1, if some bytes remains from last SG,
		 * try to complete them to 4 and send that word
		 */
		if (op->nbw > 0) {
			while (op->nbw < 4 && i < areq->nbytes &&
					in_i < in_sg->length) {
				op->wb |= (*(u8 *)(src_addr + in_i))
					<< (8 * op->nbw);
				dev_dbg(ss->dev, "%s Complete w=%d wb=%x\n",
						__func__, op->nbw, op->wb);
				i++;
				in_i++;
				op->nbw++;
			}
			if (op->nbw == 4) {
				if (i <= end) {
					ss_writer(op->wb);
					op->byte_count += 4;
				} else {
					op->wait[op->nwait] = op->wb;
					op->nwait++;
					dev_dbg(ss->dev, "%s Keep %u bytes after %llu\n",
						__func__, op->nwait, end);
				}
				op->nbw = 0;
				op->wb = 0;
			}
		}
		/* step 2, main loop, read data 4bytes at a time */
		while (i < areq->nbytes && in_i < in_sg->length) {
			/* how many bytes we can read, (we need 4) */
			in_r = min(in_sg->length - in_i, areq->nbytes - i);
			if (in_r < 4) {
				/* Not enough data to write to the device */
				op->wb = 0;
				while (in_r > 0) {
					op->wb |= (*(u8 *)(src_addr + in_i))
						<< (8 * op->nbw);
					dev_dbg(ss->dev, "%s ending bw=%d wb=%x\n",
						__func__, op->nbw, op->wb);
					in_r--;
					i++;
					in_i++;
					op->nbw++;
				}
				goto nextsg;
			}
			v = *(u32 *)(src_addr + in_i);
			if (i < end) {
				/* last write must be done without relaxed */
				if (i + 4 >= end)
					ss_writer(v);
				else
					ss_writer_relaxed(v);
				i += 4;
				op->byte_count += 4;
				in_i += 4;
			} else {
				op->wait[op->nwait] = v;
				i += 4;
				in_i += 4;
				op->nwait++;
				dev_dbg(ss->dev, "%s Keep word ww=%u after %llu\n",
						__func__, op->nwait, end);
				if (op->nwait > 15) {
					dev_err(ss->dev, "FATAL: Cannot enqueue more, bug?\n");
					writel(0, ss->base + SS_CTL);
					mutex_unlock(&ss->lock);
					return -EIO;
				}
			}
		}
nextsg:
		/* Nothing more to read in this SG */
		if (in_i == in_sg->length) {
			kunmap(sg_page(in_sg));
			do {
				in_sg = sg_next(in_sg);
			} while (in_sg != NULL && in_sg->length == 0);
			in_i = 0;
			if (in_sg != NULL) {
				src_addr = kmap(sg_page(in_sg)) + in_sg->offset;
				if (src_addr == NULL) {
					mutex_unlock(&ss->lock);
					dev_err(ss->dev, "ERROR: Cannot kmap source buffer\n");
					return -EFAULT;
				}
			}
		}
	} while (in_sg != NULL && i < areq->nbytes);

	/* ask the device to finish the hashing */
	writel(op->mode | SS_ENABLED | SS_DATA_END, ss->base + SS_CTL);
	i = 0;
	do {
		v = readl(ss->base + SS_CTL);
		i++;
	} while (i < SS_TIMEOUT && (v & SS_DATA_END) > 0);
	if (i >= SS_TIMEOUT) {
		dev_err(ss->dev, "ERROR: %s hash end timeout after %d loop, CTL=%x\n",
				__func__, i, v);
		writel(0, ss->base + SS_CTL);
		mutex_unlock(&ss->lock);
		return -EIO;
	}

	/* get the partial hash */
	if (op->mode == SS_OP_SHA1) {
		for (i = 0; i < 5; i++)
			op->hash[i] = readl(ss->base + SS_MD0 + i * 4);
	} else {
		for (i = 0; i < 4; i++)
			op->hash[i] = readl(ss->base + SS_MD0 + i * 4);
	}

	writel(0, ss->base + SS_CTL);
	mutex_unlock(&ss->lock);
	return 0;
}

/*
 * sunxi_hash_final: finalize hashing operation
 *
 * If we have some remaining bytes, we write them.
 * Then ask the SS for finalizing the hashing operation
 */
int sunxi_hash_final(struct ahash_request *areq)
{
	u32 v, ivmode = 0;
	unsigned int i;
	int zeros;
	unsigned int index, padlen;
	__be64 bits;
	struct sunxi_req_ctx *op = ahash_request_ctx(areq);

	dev_dbg(ss->dev, "%s byte=%llu len=%u mode=%x bw=%u %x h=%x ww=%u",
			__func__, op->byte_count, areq->nbytes, op->mode,
			op->nbw, op->wb, op->hash[0], op->nwait);

	mutex_lock(&ss->lock);
	rx_cnt = 0;

	/*
	 * if we have already writed something,
	 * restore the partial hash state
	 */
	if (op->byte_count > 0) {
		ivmode = SS_IV_ARBITRARY;
		for (i = 0; i < 5; i++)
			writel(op->hash[i], ss->base + SS_IV0 + i * 4);
	}
	writel(op->mode | SS_ENABLED | ivmode, ss->base + SS_CTL);

	/* write the remaining words of the wait buffer */
	if (op->nwait > 0) {
		for (i = 0; i < op->nwait; i++) {
			v = op->wait[i];
			ss_writer(v);
			op->byte_count += 4;
			dev_dbg(ss->dev, "%s write %llu i=%u %x\n",
					__func__, op->byte_count, i, v);
		}
		op->nwait = 0;
	}

	/* write the remaining bytes of the nbw buffer */
	if (op->nbw > 0) {
		op->wb |= ((1 << 7) << (op->nbw * 8));
		ss_writer(op->wb);
	} else {
		ss_writer((1 << 7));
	}

	/*
	 * number of space to pad to obtain 64o minus 8(size) minus 4 (final 1)
	 * I take the operations from other md5/sha1 implementations
	 */

	/* we have already send 4 more byte of which nbw data */
	if (op->mode == SS_OP_MD5) {
		index = (op->byte_count + 4) & 0x3f;
		op->byte_count += op->nbw;
		if (index > 56)
			zeros = (120 - index) / 4;
		else
			zeros = (56 - index) / 4;
	} else {
		op->byte_count += op->nbw;
		index = op->byte_count & 0x3f;
		padlen = (index < 56) ? (56 - index) : ((64+56) - index);
		zeros = (padlen - 1) / 4;
	}
	for (i = 0; i < zeros; i++)
		ss_writer(0);

	/* write the length of data */
	if (op->mode == SS_OP_SHA1) {
		bits = cpu_to_be64(op->byte_count << 3);
		ss_writer(bits & 0xffffffff);
		ss_writer((bits >> 32) & 0xffffffff);
	} else {
		ss_writer((op->byte_count << 3) & 0xffffffff);
		ss_writer((op->byte_count >> 29) & 0xffffffff);
	}

	/* Tell the SS to stop the hashing */
	writel(op->mode | SS_ENABLED | SS_DATA_END, ss->base + SS_CTL);

	/*
	 * Wait for SS to finish the hash.
	 * The timeout could happend only in case of bad overcloking
	 * or driver bug.
	 */
	i = 0;
	do {
		v = readl(ss->base + SS_CTL);
		i++;
	} while (i < SS_TIMEOUT && (v & SS_DATA_END) > 0);
	if (i >= SS_TIMEOUT) {
		dev_err(ss->dev, "ERROR: hash end timeout %d>%d ctl=%x len=%u\n",
				i, SS_TIMEOUT, v, areq->nbytes);
		writel(0, ss->base + SS_CTL);
		mutex_unlock(&ss->lock);
		return -EIO;
	}

	/* Get the hash from the device */
	if (op->mode == SS_OP_SHA1) {
		for (i = 0; i < 5; i++) {
			v = cpu_to_be32(readl(ss->base + SS_MD0 + i * 4));
			memcpy(areq->result + i * 4, &v, 4);
		}
	} else {
		for (i = 0; i < 4; i++) {
			v = readl(ss->base + SS_MD0 + i * 4);
			memcpy(areq->result + i * 4, &v, 4);
		}
	}
	writel(0, ss->base + SS_CTL);
	mutex_unlock(&ss->lock);
	return 0;
}

/* sunxi_hash_finup: finalize hashing operation after an update */
int sunxi_hash_finup(struct ahash_request *areq)
{
	int err;

	err = sunxi_hash_update(areq);
	if (err != 0)
		return err;

	return sunxi_hash_final(areq);
}

/* combo of init/update/final functions */
int sunxi_hash_digest(struct ahash_request *areq)
{
	int err;

	err = sunxi_hash_init(areq);
	if (err != 0)
		return err;

	err = sunxi_hash_update(areq);
	if (err != 0)
		return err;

	return sunxi_hash_final(areq);
}
