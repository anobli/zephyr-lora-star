/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>

#include <psa/crypto.h>

#include <zephyr/ztest.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/gpio/gpio_emul.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/lora_fake.h>

#include <lora_star/lora_star.h>
#include <lora_star/mac.h>
#include <lora_star/frame.h>
#include <lora_star/crypto.h>
#include <lora_star/coord.h>
#include <lora_star/pairing.h>
#include <lora_star/pairing_button.h>

/*
 * Exercises the devicetree-configured pairing button (subsys/lora_star/pairing_button.c):
 * a GPIO edge on the "lora_star,pairing-button" node must open a coordinator
 * pairing window with no test code ever calling ls_pairing_coord_start()
 * directly.
 */

static const struct gpio_dt_spec btn =
	GPIO_DT_SPEC_GET(DT_NODELABEL(pairing_button), gpios);

static const uint8_t test_dev_eui[LS_DEV_EUI_SIZE] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

/*
 * Generate an ephemeral X25519 keypair via PSA.
 * Keeps the test independent of the ls_crypto layer.
 */
static int test_ecdh_gen_keypair(uint8_t pub[LS_PUBKEY_SIZE], uint8_t priv[LS_PUBKEY_SIZE])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	size_t olen;
	psa_status_t st;

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attr, 255);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

	st = psa_generate_key(&attr, &key_id);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	st = psa_export_key(key_id, priv, LS_PUBKEY_SIZE, &olen);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_export_public_key(key_id, pub, LS_PUBKEY_SIZE, &olen);

out:
	psa_destroy_key(key_id);
	return (st == PSA_SUCCESS) ? 0 : -EIO;
}

/*
 * Derive the JOIN_REQ MIC key from the DevEUI.
 * Mirrors pairing_join_req_mic_key() in pairing.c.
 */
static void test_join_req_mic_key(const uint8_t dev_eui[LS_DEV_EUI_SIZE],
				   uint8_t key[LS_NETWORK_KEY_SIZE])
{
	memset(key, 0, LS_NETWORK_KEY_SIZE);
	memcpy(key, dev_eui, LS_DEV_EUI_SIZE);
}

/*
 * Encode a complete, MIC-signed JOIN_REQ frame into buf[].
 */
static void build_join_req(uint8_t *buf, size_t buf_size,
			   const uint8_t dev_eui[LS_DEV_EUI_SIZE],
			   const uint8_t node_pub[LS_PUBKEY_SIZE],
			   const uint8_t nonce[LS_NONCE_SIZE])
{
	struct ls_join_req_payload jr;
	struct ls_frame frame;
	uint8_t jr_key[LS_NETWORK_KEY_SIZE];
	int ret;

	zassert_true(buf_size >= LS_FRAME_SIZE(LS_JOIN_REQ_PAYLOAD_SIZE),
		     "output buffer too small");

	memcpy(jr.dev_eui,      dev_eui,   LS_DEV_EUI_SIZE);
	memcpy(jr.node_pub_key, node_pub,  LS_PUBKEY_SIZE);
	memcpy(jr.nonce,        nonce,     LS_NONCE_SIZE);

	ls_frame_init(&frame);
	ls_frame_set_type(&frame, LS_TYPE_JOIN_REQ);
	ls_frame_set_src(&frame, LS_COORD_ADDR);
	ls_frame_set_dst(&frame, LS_BCAST_ADDR);
	ls_frame_set_fcnt(&frame, 0);
	ls_frame_set_flags(&frame, 0);
	ls_frame_set_payload(&frame, (const uint8_t *)&jr, LS_JOIN_REQ_PAYLOAD_SIZE);

	test_join_req_mic_key(dev_eui, jr_key);
	ret = ls_frame_sign(&frame, jr_key);
	zassert_equal(ret, 0, "ls_frame_sign failed: %d", ret);
	memset(jr_key, 0, sizeof(jr_key));

	memcpy(buf, frame.buf, LS_FRAME_SIZE(LS_JOIN_REQ_PAYLOAD_SIZE));
}

static void inject_valid_join_req(void)
{
	uint8_t node_pub[LS_PUBKEY_SIZE], node_priv[LS_PUBKEY_SIZE];
	static const uint8_t nonce[LS_NONCE_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t jr_buf[LS_FRAME_SIZE(LS_JOIN_REQ_PAYLOAD_SIZE)] = {0};
	int ret;

	ret = test_ecdh_gen_keypair(node_pub, node_priv);
	zassert_equal(ret, 0, "ECDH keygen failed: %d", ret);

	build_join_req(jr_buf, sizeof(jr_buf), test_dev_eui, node_pub, nonce);

	/* rssi = -40 dBm, above the -60 dBm default threshold */
	lora_fake_set_recv_data(jr_buf, sizeof(jr_buf), -40, 5);
	lora_fake_trigger_recv_async();
}

/*
 * Presses and releases the pairing button, then gives the system workqueue
 * time to run the pairing_button work item (which itself lazily initialises
 * pairing and opens the window — real ECDH keygen included).
 */
static void press_pairing_button(void)
{
	zassert_ok(gpio_emul_input_set_dt(&btn, 1));
	zassert_ok(gpio_emul_input_set_dt(&btn, 0));
	k_msleep(200);
}

static struct ls_ctx *g_ctx;

static void *pairing_button_suite_setup(void)
{
	g_ctx = ls_init(lora_fake_get_device());
	zassert_not_null(g_ctx, "ls_init failed");
	zassert_ok(ls_init_coord(g_ctx));

	return NULL;
}

static void pairing_button_before(void *fixture)
{
	ARG_UNUSED(fixture);

	lora_fake_reset();
	ls_mac_recv(g_ctx);
}

ZTEST(lora_star_pairing_button, test_press_opens_pairing_window)
{
	uint32_t sent_len;
	const uint8_t *sent;

	press_pairing_button();
	inject_valid_join_req();

	/* JOIN_ACCEPT involves an ECDH agreement + HKDF; give it real time to run. */
	k_msleep(500);

	sent = lora_fake_get_sent_data(&sent_len);
	zassert_not_null(sent, "button press should have opened a pairing window "
				"that accepted the JOIN_REQ");
	zassert_equal(sent[0], LS_TYPE_JOIN_ACCEPT,
		      "expected a JOIN_ACCEPT frame, got type 0x%02x", sent[0]);
}

ZTEST(lora_star_pairing_button, test_no_press_no_pairing_window)
{
	uint32_t sent_len;

	inject_valid_join_req();
	k_msleep(200);

	zassert_is_null(lora_fake_get_sent_data(&sent_len),
			"a JOIN_REQ must be ignored while the pairing button hasn't been pressed");
}

ZTEST_SUITE(lora_star_pairing_button, NULL, pairing_button_suite_setup,
	    pairing_button_before, NULL, NULL);
