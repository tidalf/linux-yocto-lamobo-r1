/*
 * sunxi-ss-core.c - hardware cryptographic accelerator for Allwinner A20 SoC
 *
 * Copyright (C) 2013-2014 Corentin LABBE <clabbe.montjoie@gmail.com>
 *
 * Core file which registers crypto algorithms supported by the SS.
 *
 * You could find a link for the datasheet in Documentation/arm/sunxi/README
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/clk.h>
#include <linux/crypto.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/interrupt.h>
#include <linux/delay.h>

#include "sunxi-ss.h"

struct sunxi_ss_ctx *ss;

/*
 * General notes for whole driver:
 *
 * After each request the device must be disabled with a write of 0 in SS_CTL
 *
 * For performance reason, we use writel_relaxed/read_relaxed for all
 * operations on RX and TX FIFO and also SS_FCSR.
 * Excepts for the last write on TX FIFO.
 * For all other registers, we use writel/readl.
 * See http://permalink.gmane.org/gmane.linux.ports.arm.kernel/117644
 * and http://permalink.gmane.org/gmane.linux.ports.arm.kernel/117640
 */

static struct ahash_alg sunxi_md5_alg = {
	.init = sunxi_hash_init,
	.update = sunxi_hash_update,
	.final = sunxi_hash_final,
	.finup = sunxi_hash_finup,
	.digest = sunxi_hash_digest,
	.halg = {
		.digestsize = MD5_DIGEST_SIZE,
		.base = {
			.cra_name = "md5",
			.cra_driver_name = "md5-sunxi-ss",
			.cra_priority = 300,
			.cra_alignmask = 3,
			.cra_flags = CRYPTO_ALG_TYPE_AHASH | CRYPTO_ALG_ASYNC,
			.cra_blocksize = MD5_HMAC_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct sunxi_req_ctx),
			.cra_module = THIS_MODULE,
			.cra_type = &crypto_ahash_type,
			.cra_init = sunxi_hash_crainit
		}
	}
};

static struct ahash_alg sunxi_sha1_alg = {
	.init = sunxi_hash_init,
	.update = sunxi_hash_update,
	.final = sunxi_hash_final,
	.finup = sunxi_hash_finup,
	.digest = sunxi_hash_digest,
	.halg = {
		.digestsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "sha1",
			.cra_driver_name = "sha1-sunxi-ss",
			.cra_priority = 300,
			.cra_alignmask = 3,
			.cra_flags = CRYPTO_ALG_TYPE_AHASH | CRYPTO_ALG_ASYNC,
			.cra_blocksize = SHA1_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct sunxi_req_ctx),
			.cra_module = THIS_MODULE,
			.cra_type = &crypto_ahash_type,
			.cra_init = sunxi_hash_crainit
		}
	}
};

static struct crypto_alg sunxi_cipher_algs[] = {
{
	.cra_name = "cbc(aes)",
	.cra_driver_name = "cbc-aes-sunxi-ss",
	.cra_priority = 300,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER,
	.cra_ctxsize = sizeof(struct sunxi_tfm_ctx),
	.cra_module = THIS_MODULE,
	.cra_alignmask = 3,
	.cra_type = &crypto_ablkcipher_type,
	.cra_init = sunxi_ss_cipher_init,
	.cra_u = {
		.ablkcipher = {
			.min_keysize    = AES_MIN_KEY_SIZE,
			.max_keysize    = AES_MAX_KEY_SIZE,
			.ivsize         = AES_BLOCK_SIZE,
			.setkey         = sunxi_ss_aes_setkey,
			.encrypt        = sunxi_ss_cipher_encrypt,
			.decrypt        = sunxi_ss_cipher_decrypt,
		}
	}
}, {
	.cra_name = "cbc(des)",
	.cra_driver_name = "cbc-des-sunxi-ss",
	.cra_priority = 300,
	.cra_blocksize = DES_BLOCK_SIZE,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER,
	.cra_ctxsize = sizeof(struct sunxi_req_ctx),
	.cra_module = THIS_MODULE,
	.cra_alignmask = 3,
	.cra_type = &crypto_ablkcipher_type,
	.cra_init = sunxi_ss_cipher_init,
	.cra_u.ablkcipher = {
		.min_keysize    = DES_KEY_SIZE,
		.max_keysize    = DES_KEY_SIZE,
		.ivsize         = DES_BLOCK_SIZE,
		.setkey         = sunxi_ss_des_setkey,
		.encrypt        = sunxi_ss_cipher_encrypt,
		.decrypt        = sunxi_ss_cipher_decrypt,
	}
}, {
	.cra_name = "cbc(des3_ede)",
	.cra_driver_name = "cbc-des3-sunxi-ss",
	.cra_priority = 300,
	.cra_blocksize = DES3_EDE_BLOCK_SIZE,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER,
	.cra_ctxsize = sizeof(struct sunxi_req_ctx),
	.cra_module = THIS_MODULE,
	.cra_alignmask = 3,
	.cra_type = &crypto_ablkcipher_type,
	.cra_init = sunxi_ss_cipher_init,
	.cra_u.ablkcipher = {
		.min_keysize    = DES3_EDE_KEY_SIZE,
		.max_keysize    = DES3_EDE_KEY_SIZE,
		.ivsize         = DES3_EDE_BLOCK_SIZE,
		.setkey         = sunxi_ss_des3_setkey,
		.encrypt        = sunxi_ss_cipher_encrypt,
		.decrypt        = sunxi_ss_cipher_decrypt,
	}
}
};

static int sunxi_ss_probe(struct platform_device *pdev)
{
	struct resource *res;
	u32 v;
	int err;
	unsigned long cr;
	const unsigned long cr_ahb = 24 * 1000 * 1000;
	const unsigned long cr_mod = 150 * 1000 * 1000;

	if (!pdev->dev.of_node)
		return -ENODEV;

	ss = devm_kzalloc(&pdev->dev, sizeof(*ss), GFP_KERNEL);
	if (ss == NULL)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	ss->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(ss->base)) {
		dev_err(&pdev->dev, "Cannot request MMIO\n");
		return PTR_ERR(ss->base);
	}

	ss->ssclk = devm_clk_get(&pdev->dev, "mod");
	if (IS_ERR(ss->ssclk)) {
		err = PTR_ERR(ss->ssclk);
		dev_err(&pdev->dev, "Cannot get SS clock err=%d\n", err);
		return err;
	}
	dev_dbg(&pdev->dev, "clock ss acquired\n");

	ss->busclk = devm_clk_get(&pdev->dev, "ahb");
	if (IS_ERR(ss->busclk)) {
		err = PTR_ERR(ss->busclk);
		dev_err(&pdev->dev, "Cannot get AHB SS clock err=%d\n", err);
		return err;
	}
	dev_dbg(&pdev->dev, "clock ahb_ss acquired\n");

	/* Enable both clocks */
	err = clk_prepare_enable(ss->busclk);
	if (err != 0) {
		dev_err(&pdev->dev, "Cannot prepare_enable busclk\n");
		return err;
	}
	err = clk_prepare_enable(ss->ssclk);
	if (err != 0) {
		dev_err(&pdev->dev, "Cannot prepare_enable ssclk\n");
		clk_disable_unprepare(ss->busclk);
		return err;
	}

	/*
	 * Check that clock have the correct rates gived in the datasheet
	 * Try to set the clock to the maximum allowed
	 */
	err = clk_set_rate(ss->ssclk, cr_mod);
	if (err != 0) {
		dev_err(&pdev->dev, "Cannot set clock rate to ssclk\n");
		clk_disable_unprepare(ss->ssclk);
		clk_disable_unprepare(ss->busclk);
		return err;
	}

	cr = clk_get_rate(ss->busclk);
	if (cr >= cr_ahb)
		dev_dbg(&pdev->dev, "Clock bus %lu (%lu MHz) (must be >= %lu)\n",
				cr, cr / 1000000, cr_ahb);
	else
		dev_warn(&pdev->dev, "Clock bus %lu (%lu MHz) (must be >= %lu)\n",
				cr, cr / 1000000, cr_ahb);

	cr = clk_get_rate(ss->ssclk);
	if (cr <= cr_mod)
		if (cr < cr_mod)
			dev_info(&pdev->dev, "Clock ss %lu (%lu MHz) (must be <= %lu)\n",
					cr, cr / 1000000, cr_mod);
		else
			dev_dbg(&pdev->dev, "Clock ss %lu (%lu MHz) (must be <= %lu)\n",
					cr, cr / 1000000, cr_mod);
	else
		dev_warn(&pdev->dev, "Clock ss is at %lu (%lu MHz) (must be <= %lu)\n",
				cr, cr / 1000000, cr_mod);

	/*
	 * Datasheet named it "Die Bonding ID"
	 * I expect to be a sort of Security System Revision number.
	 * Since the A80 seems to have an other version of SS
	 * this info could be useful
	 */
	writel(SS_ENABLED, ss->base + SS_CTL);
	v = readl(ss->base + SS_CTL);
	v >>= 16;
	v &= 0x07;
	dev_info(&pdev->dev, "Die ID %d\n", v);
	writel(0, ss->base + SS_CTL);

	ss->dev = &pdev->dev;

	mutex_init(&ss->lock);
	mutex_init(&ss->bufin_lock);
	mutex_init(&ss->bufout_lock);

	err = crypto_register_ahash(&sunxi_md5_alg);
	if (err)
		goto error_md5;
	err = crypto_register_ahash(&sunxi_sha1_alg);
	if (err)
		goto error_sha1;
	err = crypto_register_algs(sunxi_cipher_algs,
			ARRAY_SIZE(sunxi_cipher_algs));
	if (err)
		goto error_ciphers;

	return 0;
error_ciphers:
	crypto_unregister_ahash(&sunxi_sha1_alg);
error_sha1:
	crypto_unregister_ahash(&sunxi_md5_alg);
error_md5:
	clk_disable_unprepare(ss->ssclk);
	clk_disable_unprepare(ss->busclk);
	return err;
}

static int __exit sunxi_ss_remove(struct platform_device *pdev)
{
	if (!pdev->dev.of_node)
		return 0;

	crypto_unregister_ahash(&sunxi_md5_alg);
	crypto_unregister_ahash(&sunxi_sha1_alg);
	crypto_unregister_algs(sunxi_cipher_algs,
			ARRAY_SIZE(sunxi_cipher_algs));

	if (ss->buf_in != NULL)
		kfree(ss->buf_in);
	if (ss->buf_out != NULL)
		kfree(ss->buf_out);

	writel(0, ss->base + SS_CTL);
	clk_disable_unprepare(ss->busclk);
	clk_disable_unprepare(ss->ssclk);
	return 0;
}

static const struct of_device_id a20ss_crypto_of_match_table[] = {
	{ .compatible = "allwinner,sun7i-a20-crypto" },
	{}
};
MODULE_DEVICE_TABLE(of, a20ss_crypto_of_match_table);

static struct platform_driver sunxi_ss_driver = {
	.probe          = sunxi_ss_probe,
	.remove         = __exit_p(sunxi_ss_remove),
	.driver         = {
		.owner          = THIS_MODULE,
		.name           = "sunxi-ss",
		.of_match_table	= a20ss_crypto_of_match_table,
	},
};

module_platform_driver(sunxi_ss_driver);

MODULE_DESCRIPTION("Allwinner Security System cryptographic accelerator");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Corentin LABBE <clabbe.montjoie@gmail.com>");
