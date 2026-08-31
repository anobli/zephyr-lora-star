/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>

#include <psa/crypto.h>

#include <zephyr/ztest.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/lora_fake.h>

#include <lora_star/lora_star.h>
#include <lora_star/mac.h>
#include <lora_star/frame.h>
#include <lora_star/crypto.h>
#include <lora_star/coord.h>
#include <lora_star/pairing.h>

/* --------------------------------------------------------------------------
 * Shared test vectors
 * -------------------------------------------------------------------------- */

static const uint8_t test_dev_eui[LS_DEV_EUI_SIZE] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

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

/* --------------------------------------------------------------------------
 * Suite 1: Wire format / struct layout
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_pairing_format, test_join_req_payload_size)
{
	zassert_equal(sizeof(struct ls_join_req_payload), LS_JOIN_REQ_PAYLOAD_SIZE,
		      "struct size %zu != macro %d",
		      sizeof(struct ls_join_req_payload), LS_JOIN_REQ_PAYLOAD_SIZE);
}

ZTEST(lora_star_pairing_format, test_join_accept_payload_size)
{
	zassert_equal(sizeof(struct ls_join_accept_payload), LS_JOIN_ACCEPT_PAYLOAD_SIZE,
		      "struct size %zu != macro %d",
		      sizeof(struct ls_join_accept_payload), LS_JOIN_ACCEPT_PAYLOAD_SIZE);
}

ZTEST(lora_star_pairing_format, test_join_req_frame_total_size)
{
	zassert_equal(LS_FRAME_SIZE(LS_JOIN_REQ_PAYLOAD_SIZE),
		      LS_OVERHEAD_SIZE + LS_JOIN_REQ_PAYLOAD_SIZE);
}

ZTEST(lora_star_pairing_format, test_join_accept_frame_total_size)
{
	zassert_equal(LS_FRAME_SIZE(LS_JOIN_ACCEPT_PAYLOAD_SIZE),
		      LS_OVERHEAD_SIZE + LS_JOIN_ACCEPT_PAYLOAD_SIZE);
}

ZTEST(lora_star_pairing_format, test_join_req_payload_field_offsets)
{
	struct ls_join_req_payload jr;

	/* dev_eui at offset 0 */
	zassert_equal(offsetof(struct ls_join_req_payload, dev_eui), 0);
	/* node_pub_key immediately after dev_eui */
	zassert_equal(offsetof(struct ls_join_req_payload, node_pub_key), LS_DEV_EUI_SIZE);
	/* nonce immediately after node_pub_key */
	zassert_equal(offsetof(struct ls_join_req_payload, nonce),
		      LS_DEV_EUI_SIZE + LS_PUBKEY_SIZE);
	/* total struct size matches sum of fields */
	zassert_equal(sizeof(jr), LS_DEV_EUI_SIZE + LS_PUBKEY_SIZE + LS_NONCE_SIZE);
}

ZTEST(lora_star_pairing_format, test_join_accept_payload_field_offsets)
{
	struct ls_join_accept_payload ja;
	size_t enc_size = sizeof(uint16_t) + LS_NETWORK_KEY_SIZE;

	/* coord_pub_key at offset 0 */
	zassert_equal(offsetof(struct ls_join_accept_payload, coord_pub_key), 0);
	/* enc_payload immediately after coord_pub_key */
	zassert_equal(offsetof(struct ls_join_accept_payload, enc_payload), LS_PUBKEY_SIZE);
	/* total struct size matches sum of fields */
	zassert_equal(sizeof(ja), LS_PUBKEY_SIZE + enc_size);
}

ZTEST_SUITE(lora_star_pairing_format, NULL, NULL, NULL, NULL, NULL);

/* --------------------------------------------------------------------------
 * Suite 2: Coordinator pairing integration
 * -------------------------------------------------------------------------- */

static struct ls_ctx              *g_ctx;
static struct ls_coord_pairing_ctx g_pair_ctx;
static struct k_sem                g_join_sem;
static uint16_t                    g_joined_addr;

static void test_join_cb(struct ls_ctx *ctx, uint16_t short_addr,
			  const uint8_t dev_eui[LS_DEV_EUI_SIZE], void *user_data)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(dev_eui);
	ARG_UNUSED(user_data);

	g_joined_addr = short_addr;
	k_sem_give(&g_join_sem);
}

static void *pairing_suite_setup(void)
{
	int ret;

	g_ctx = ls_init(lora_fake_get_device());
	zassert_not_null(g_ctx, "ls_init failed");
	ret = ls_init_coord(g_ctx);
	zassert_equal(ret, 0, "ls_init_coord failed: %d", ret);

	ret = ls_pairing_coord_init(g_ctx, &g_pair_ctx, test_join_cb, NULL);
	zassert_equal(ret, 0, "ls_pairing_coord_init failed: %d", ret);

	return NULL;
}

static void coord_before(void *fixture)
{
	int ret;

	ARG_UNUSED(fixture);

	k_sem_init(&g_join_sem, 0, 1);
	g_joined_addr = 0;

	lora_fake_reset();
	ls_mac_recv(g_ctx);

	ret = ls_pairing_coord_start(&g_pair_ctx);
	zassert_equal(ret, 0, "ls_pairing_coord_start failed: %d", ret);
}

static void coord_after(void *fixture)
{
	ARG_UNUSED(fixture);

	if (g_pair_ctx._pairing_open) {
		ls_unregister_frame_cb(g_ctx, g_pair_ctx._join_req_hdl);
		g_pair_ctx._join_req_hdl = NULL;
		g_pair_ctx._pairing_open = false;
		k_work_cancel_delayable(&g_pair_ctx._close_work);
	}
}

ZTEST(lora_star_pairing_coord, test_coord_init_next_addr)
{
	zassert_equal(ls_coord_get()->next_addr, LS_ADDR_MIN,
		      "next_addr should be LS_ADDR_MIN after init, got 0x%04x",
		      ls_coord_get()->next_addr);
}

ZTEST(lora_star_pairing_coord, test_coord_init_network_key_nonzero)
{
	static const uint8_t zeros[LS_NETWORK_KEY_SIZE] = {0};

	zassert_false(memcmp(g_ctx->network_key, zeros, LS_NETWORK_KEY_SIZE) == 0,
		      "coordinator network key must not be all zeros after init");
}

ZTEST(lora_star_pairing_coord, test_coord_start_pairing_open)
{
	zassert_true(g_pair_ctx._pairing_open,
		     "pairing window should be open after ls_pairing_coord_start");
	zassert_not_null(g_pair_ctx._join_req_hdl,
			 "JOIN_REQ frame handler should be registered");
}

ZTEST(lora_star_pairing_coord, test_coord_join_rssi_rejected)
{
	uint8_t node_pub[LS_PUBKEY_SIZE], node_priv[LS_PUBKEY_SIZE];
	uint8_t nonce[LS_NONCE_SIZE] = {0x11, 0x22, 0x33, 0x44};
	uint8_t jr_buf[LS_FRAME_SIZE(LS_JOIN_REQ_PAYLOAD_SIZE)] = {0};
	int ret;

	ret = test_ecdh_gen_keypair(node_pub, node_priv);
	zassert_equal(ret, 0, "ECDH keygen failed: %d", ret);

	build_join_req(jr_buf, sizeof(jr_buf), test_dev_eui, node_pub, nonce);

	/* rssi = -80 dBm, below the -60 dBm default threshold */
	lora_fake_set_recv_data(jr_buf, sizeof(jr_buf), -80, 5);
	lora_fake_trigger_recv_async();

	ret = k_sem_take(&g_join_sem, K_MSEC(200));
	zassert_equal(ret, -EAGAIN,
		      "JOIN_REQ below RSSI threshold must be rejected (semaphore should not fire)");
}

ZTEST(lora_star_pairing_coord, test_coord_join_bad_mic)
{
	uint8_t node_pub[LS_PUBKEY_SIZE], node_priv[LS_PUBKEY_SIZE];
	uint8_t nonce[LS_NONCE_SIZE] = {0x55, 0x66, 0x77, 0x88};
	uint8_t jr_buf[LS_FRAME_SIZE(LS_JOIN_REQ_PAYLOAD_SIZE)] = {0};
	int ret;

	ret = test_ecdh_gen_keypair(node_pub, node_priv);
	zassert_equal(ret, 0, "ECDH keygen failed: %d", ret);

	build_join_req(jr_buf, sizeof(jr_buf), test_dev_eui, node_pub, nonce);

	/* Flip the last byte of the MIC to invalidate the integrity check */
	jr_buf[sizeof(jr_buf) - 1] ^= 0xFF;

	lora_fake_set_recv_data(jr_buf, sizeof(jr_buf), -40, 5);
	lora_fake_trigger_recv_async();

	ret = k_sem_take(&g_join_sem, K_MSEC(200));
	zassert_equal(ret, -EAGAIN,
		      "JOIN_REQ with corrupted MIC must be rejected");
}

ZTEST(lora_star_pairing_coord, test_coord_join_valid_req)
{
	uint8_t node_pub[LS_PUBKEY_SIZE], node_priv[LS_PUBKEY_SIZE];
	uint8_t nonce[LS_NONCE_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t jr_buf[LS_FRAME_SIZE(LS_JOIN_REQ_PAYLOAD_SIZE)] = {0};
	int ret;

	ret = test_ecdh_gen_keypair(node_pub, node_priv);
	zassert_equal(ret, 0, "ECDH keygen failed: %d", ret);

	build_join_req(jr_buf, sizeof(jr_buf), test_dev_eui, node_pub, nonce);

	/* rssi = -40 dBm, above the -60 dBm threshold */
	lora_fake_set_recv_data(jr_buf, sizeof(jr_buf), -40, 5);
	lora_fake_trigger_recv_async();

	ret = k_sem_take(&g_join_sem, K_MSEC(1000));
	zassert_equal(ret, 0, "join callback did not fire within timeout");
	zassert_equal(g_joined_addr, LS_ADDR_MIN,
		      "first node should receive LS_ADDR_MIN (0x%04x), got 0x%04x",
		      LS_ADDR_MIN, g_joined_addr);

	/* pairing_close_window() is called before _join_cb, so window is already shut */
	zassert_false(g_pair_ctx._pairing_open,
		      "pairing window must close immediately after a successful join");
}

ZTEST(lora_star_pairing_coord, test_coord_join_repair)
{
	/*
	 * Re-pairing: the same node DevEUI sends another JOIN_REQ.
	 * The coordinator must recognise it as a repair and return the
	 * already-assigned short address, not allocate a new one.
	 *
	 * This test is self-contained: it first performs a fresh join to
	 * populate the node table, then re-opens the pairing window and
	 * sends a second JOIN_REQ with the same DevEUI to exercise the
	 * re-pair path.  The alphabetical test order means we cannot rely
	 * on test_coord_join_valid_req having run first.
	 */
	uint8_t node_pub[LS_PUBKEY_SIZE], node_priv[LS_PUBKEY_SIZE];
	uint8_t nonce[LS_NONCE_SIZE]  = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t nonce2[LS_NONCE_SIZE] = {0x12, 0x34, 0x56, 0x78};
	uint8_t jr_buf[LS_FRAME_SIZE(LS_JOIN_REQ_PAYLOAD_SIZE)] = {0};
	uint16_t next_addr_before;
	int ret;

	/* Step 1: fresh join — register the node in the coordinator table */
	ret = test_ecdh_gen_keypair(node_pub, node_priv);
	zassert_equal(ret, 0);
	build_join_req(jr_buf, sizeof(jr_buf), test_dev_eui, node_pub, nonce);
	lora_fake_set_recv_data(jr_buf, sizeof(jr_buf), -40, 5);
	lora_fake_trigger_recv_async();
	ret = k_sem_take(&g_join_sem, K_MSEC(1000));
	zassert_equal(ret, 0, "initial join did not complete");

	/* Step 2: re-open the pairing window for the re-pair attempt */
	k_sem_init(&g_join_sem, 0, 1);
	g_joined_addr = 0;
	ret = ls_pairing_coord_start(&g_pair_ctx);
	zassert_equal(ret, 0, "re-open pairing failed: %d", ret);

	next_addr_before = ls_coord_get()->next_addr;

	/* Step 3: same DevEUI, fresh ephemeral keys and nonce */
	ret = test_ecdh_gen_keypair(node_pub, node_priv);
	zassert_equal(ret, 0);
	memset(jr_buf, 0, sizeof(jr_buf));
	build_join_req(jr_buf, sizeof(jr_buf), test_dev_eui, node_pub, nonce2);
	lora_fake_set_recv_data(jr_buf, sizeof(jr_buf), -40, 5);
	lora_fake_trigger_recv_async();

	ret = k_sem_take(&g_join_sem, K_MSEC(1000));
	zassert_equal(ret, 0, "re-pair join callback did not fire");
	zassert_equal(g_joined_addr, LS_ADDR_MIN,
		      "re-paired node must keep its original short address");
	zassert_equal(ls_coord_get()->next_addr, next_addr_before,
		      "next_addr must not change on re-pair");
}

ZTEST_SUITE(lora_star_pairing_coord, NULL, pairing_suite_setup,
	    coord_before, coord_after, NULL);
