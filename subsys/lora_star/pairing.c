/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>

#include <psa/crypto.h>
#include <mbedtls/constant_time.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/byteorder.h>

#include <lora_star/lora_star.h>
#include <lora_star/mac.h>
#include <lora_star/crypto.h>
#include <lora_star/pairing.h>

#include "storage.h"
#include "event.h"

LOG_MODULE_REGISTER(ls_pairing, CONFIG_LORA_STAR_LOG_LEVEL);

/* --------------------------------------------------------------------------
 * Pairing-specific crypto helpers
 * -------------------------------------------------------------------------- */

/*
 * Derive the MIC key for a JOIN_REQ frame.
 *
 * No shared secret exists yet at JOIN_REQ time, so we cannot use a proper
 * network key.  The DevEUI is used as a public device identifier: it is
 * zero-padded to 16 bytes and fed into AES-CMAC as a key.  This gives
 * integrity (the coordinator can verify the frame was built by a device
 * claiming that DevEUI) without requiring any prior setup.  It does NOT
 * provide confidentiality — JOIN_REQ is intentionally sent in the clear.
 */
static void pairing_join_req_mic_key(const uint8_t dev_eui[LS_DEV_EUI_SIZE],
				     uint8_t key[LS_NETWORK_KEY_SIZE])
{
	memset(key, 0, LS_NETWORK_KEY_SIZE);
	memcpy(key, dev_eui, LS_DEV_EUI_SIZE);
}

/*
 * Generate an ephemeral Curve25519 (X25519) keypair.
 *
 * X25519 is a Diffie-Hellman function: each side generates a random 32-byte
 * private key and derives a 32-byte public key from it.  The public key can
 * be transmitted openly — it reveals nothing about the private key.
 *
 * Using ephemeral keys (freshly generated per pairing attempt) provides
 * forward secrecy: a future compromise of a session key cannot be used to
 * decrypt past sessions, because each session's shared secret was computed
 * from a different private key that has since been erased.
 */
static int pairing_ecdh_gen_keypair(uint8_t pub[LS_PUBKEY_SIZE],
				    uint8_t priv[LS_PUBKEY_SIZE])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	size_t olen;
	psa_status_t st;

	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attr, 255);
	/*
	 * DERIVE: needed to compute the shared secret later via
	 *         psa_raw_key_agreement().
	 * EXPORT: needed to extract the private scalar so it can be stored in
	 *         the pairing context for use when the peer's response arrives.
	 */
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

	/*
	 * For Curve25519, PSA exports the public key as a raw 32-byte
	 * x-coordinate with no encoding prefix (unlike other curves).
	 */
	st = psa_export_public_key(key_id, pub, LS_PUBKEY_SIZE, &olen);

out:
	psa_destroy_key(key_id);
	return (st == PSA_SUCCESS) ? 0 : -EIO;
}

/*
 * Compute the X25519 shared secret.
 *
 * Both sides compute shared = X25519(own_private, peer_public).  The
 * Diffie-Hellman property guarantees both sides arrive at the same 32-byte
 * value without ever transmitting their private keys.
 *
 * The raw shared secret is NOT used directly as a key because X25519 outputs
 * have low-entropy structure (small subgroup contributions, etc.).  It must
 * pass through HKDF first.
 */
static int pairing_ecdh_shared(const uint8_t priv[LS_PUBKEY_SIZE],
				const uint8_t peer_pub[LS_PUBKEY_SIZE],
				uint8_t shared[LS_PUBKEY_SIZE])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	size_t olen;
	psa_status_t st;

	/*
	 * Re-import the stored private scalar.  DERIVE is the required usage
	 * flag for psa_raw_key_agreement().
	 */
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attr, 255);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

	st = psa_import_key(&attr, priv, LS_PUBKEY_SIZE, &key_id);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	st = psa_raw_key_agreement(PSA_ALG_ECDH, key_id,
				   peer_pub, LS_PUBKEY_SIZE,
				   shared, LS_PUBKEY_SIZE, &olen);
	psa_destroy_key(key_id);
	return (st == PSA_SUCCESS) ? 0 : -EIO;
}

/*
 * Derive the 16-byte ephemeral pairing key using HKDF-SHA256 (RFC 5869).
 *
 * This key is used exclusively for the JOIN_ACCEPT exchange: it encrypts the
 * short address and network key via AES-CTR, and authenticates the frame via
 * AES-CMAC.  It is discarded after pairing; the network key recovered from
 * the JOIN_ACCEPT is what the node uses for all subsequent DATA/ACK frames.
 *
 * HKDF construction:
 *   Extract: PRK = HMAC-SHA256(salt=DevEUI||Nonce, IKM=shared_secret)
 *     Ties PRK to this specific device and pairing attempt.
 *   Expand: PairingKey = first 16 bytes of HMAC-SHA256(PRK, "lora_star_v1")
 *     Protocol-version domain separator prevents key reuse with other uses.
 *
 * Both sides perform this derivation independently and arrive at the same
 * value, because all inputs (shared secret, DevEUI, Nonce, info string) are
 * identical on both sides.
 */
static int pairing_hkdf_pairing_key(const uint8_t shared[LS_PUBKEY_SIZE],
				    const uint8_t dev_eui[LS_DEV_EUI_SIZE],
				    const uint8_t nonce[LS_NONCE_SIZE],
				    uint8_t key[LS_NETWORK_KEY_SIZE])
{
	uint8_t salt[LS_DEV_EUI_SIZE + LS_NONCE_SIZE];
	const uint8_t info[] = "lora_star_v1";
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t ikm_id = PSA_KEY_ID_NULL;
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_status_t st;

	memcpy(salt, dev_eui, LS_DEV_EUI_SIZE);
	memcpy(salt + LS_DEV_EUI_SIZE, nonce, LS_NONCE_SIZE);

	/*
	 * PSA requires the HKDF secret (IKM) to be a key handle, not raw
	 * bytes.  Importing as KEY_TYPE_DERIVE enforces that the raw shared
	 * secret never leaves PSA as application-visible bytes via this path.
	 */
	psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_bits(&attr, LS_PUBKEY_SIZE * 8);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));

	st = psa_import_key(&attr, shared, LS_PUBKEY_SIZE, &ikm_id);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (st != PSA_SUCCESS) {
		goto out;
	}

	/* HKDF extract step: salt binds PRK to this device and pairing attempt. */
	st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
					    salt, sizeof(salt));
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm_id);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	/* HKDF expand step: info provides protocol-level domain separation. */
	st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
					    info, sizeof(info) - 1);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_key_derivation_output_bytes(&op, key, LS_NETWORK_KEY_SIZE);

out:
	psa_key_derivation_abort(&op);
	psa_destroy_key(ikm_id);
	return (st == PSA_SUCCESS) ? 0 : -EIO;
}

/* --------------------------------------------------------------------------
 * Coordinator side
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LORA_STAR_COORDINATOR

static void pairing_on_node_loaded(uint16_t short_addr,
				   const struct ls_node_record *rec,
				   void *user_data)
{
	struct ls_coord_pairing_ctx *pair_ctx = user_data;
	int i;

	for (i = 0; i < CONFIG_LORA_STAR_MAX_NODES; i++) {
		if (!pair_ctx->nodes[i].active) {
			pair_ctx->nodes[i].active     = true;
			pair_ctx->nodes[i].short_addr = short_addr;
			pair_ctx->nodes[i].rec        = *rec;
			return;
		}
	}
	LOG_WRN("Node table full — dropping addr 0x%04x", short_addr);
}

static void pairing_close_window(struct ls_coord_pairing_ctx *pair_ctx)
{
	ls_unregister_frame_cb(pair_ctx->_ctx, pair_ctx->_join_req_hdl);
	pair_ctx->_join_req_hdl = NULL;
	pair_ctx->_pairing_open = false;
	LOG_INF("Pairing window closed");
}

static void pairing_close_work_handler(struct k_work *work)
{
	struct ls_coord_pairing_ctx *pair_ctx =
		CONTAINER_OF(work, struct ls_coord_pairing_ctx, _close_work.work);

	pairing_close_window(pair_ctx);
}

static int pairing_find_node_by_eui(struct ls_coord_pairing_ctx *pair_ctx,
				    const uint8_t dev_eui[LS_DEV_EUI_SIZE])
{
	int i;

	for (i = 0; i < CONFIG_LORA_STAR_MAX_NODES; i++) {
		if (pair_ctx->nodes[i].active &&
		    memcmp(pair_ctx->nodes[i].rec.dev_eui, dev_eui, LS_DEV_EUI_SIZE) == 0) {
			return i;
		}
	}
	return -1;
}

static int pairing_alloc_node(struct ls_coord_pairing_ctx *pair_ctx)
{
	int i;

	for (i = 0; i < CONFIG_LORA_STAR_MAX_NODES; i++) {
		if (!pair_ctx->nodes[i].active) {
			return i;
		}
	}
	return -1;
}

static int pairing_join_req_cb(struct ls_ctx *ctx, struct ls_frame *frame,
			       void *user_data)
{
	struct ls_coord_pairing_ctx *pair_ctx = user_data;
	uint8_t *payload;
	size_t payload_len;
	const struct ls_join_req_payload *jr;
	uint8_t jr_key[LS_NETWORK_KEY_SIZE];
	uint8_t shared[LS_PUBKEY_SIZE];
	uint8_t pairing_key[LS_NETWORK_KEY_SIZE];
	uint8_t enc_buf[sizeof(uint16_t) + LS_NETWORK_KEY_SIZE];
	uint8_t ctr_nonce[LS_CTR_NONCE_SIZE];
	uint16_t short_addr;
	struct ls_join_accept_payload ja;
	struct ls_frame resp;
	uint8_t resp_buf[LS_FRAME_SIZE(LS_JOIN_ACCEPT_PAYLOAD_SIZE)];
	struct ls_node_record rec;
	int slot;
	bool is_repair;
	int ret;

	if (!pair_ctx->_pairing_open) {
		return 0;
	}

	if (frame->rssi < CONFIG_LORA_STAR_PAIRING_RSSI_THRESHOLD_DBM) {
		LOG_DBG("JOIN_REQ rejected: RSSI %d dBm < threshold %d dBm",
			frame->rssi,
			CONFIG_LORA_STAR_PAIRING_RSSI_THRESHOLD_DBM);
		return 0;
	}

	ls_frame_get_payload(frame, &payload, &payload_len);

	if (payload_len != LS_JOIN_REQ_PAYLOAD_SIZE) {
		return 0;
	}

	jr = (const struct ls_join_req_payload *)payload;

	/*
	 * Verify the JOIN_REQ MIC with the DevEUI-derived key.  Because the
	 * key is derived from a public identifier (DevEUI), this check provides
	 * integrity only — it confirms the frame was assembled by a device that
	 * knows its own DevEUI, which defends against trivially spoofed frames.
	 */
	pairing_join_req_mic_key(jr->dev_eui, jr_key);
	ret = ls_frame_check_signature(frame, jr_key);
	memset(jr_key, 0, sizeof(jr_key));
	if (ret < 0) {
		LOG_WRN("JOIN_REQ MIC mismatch");
		return 0;
	}

	slot = pairing_find_node_by_eui(pair_ctx, jr->dev_eui);
	is_repair = (slot >= 0);

	if (!is_repair) {
		slot = pairing_alloc_node(pair_ctx);
		if (slot < 0) {
			LOG_ERR("Node table full");
			return 0;
		}
	}

	/*
	 * Compute the X25519 shared secret from our ephemeral private key and
	 * the node's ephemeral public key.  Both sides compute the same value.
	 */
	ret = pairing_ecdh_shared(pair_ctx->_priv_key, jr->node_pub_key, shared);
	if (ret < 0) {
		LOG_ERR("ECDH failed");
		return 0;
	}

	/*
	 * Derive the ephemeral pairing key via HKDF.  This key is used only
	 * for this JOIN_ACCEPT: to encrypt the payload and sign the frame.
	 * It is discarded after; the network key inside the payload is what
	 * the node will use for all subsequent DATA/ACK frames.
	 */
	ret = pairing_hkdf_pairing_key(shared, jr->dev_eui, jr->nonce, pairing_key);
	memset(shared, 0, sizeof(shared));
	if (ret < 0) {
		LOG_ERR("Key derivation failed");
		return 0;
	}

	if (is_repair) {
		short_addr = pair_ctx->nodes[slot].short_addr;
	} else {
		if (pair_ctx->next_addr > LS_ADDR_MAX) {
			LOG_ERR("Address space exhausted");
			memset(pairing_key, 0, sizeof(pairing_key));
			return 0;
		}
		short_addr = pair_ctx->next_addr;
	}

	/*
	 * Build enc_buf = short_addr_LE(2) || network_key(16), then encrypt
	 * in-place with AES-CTR.  The node decrypts this to recover its
	 * assigned address and the shared network key.
	 */
	sys_put_le16(short_addr, enc_buf);
	memcpy(enc_buf + sizeof(uint16_t), ctx->network_key, LS_NETWORK_KEY_SIZE);
	memset(ctr_nonce, 0, sizeof(ctr_nonce));
	memcpy(ctr_nonce, jr->nonce, LS_NONCE_SIZE);
	ret = ls_crypto_ctr(enc_buf, sizeof(enc_buf), pairing_key, ctr_nonce, true);
	if (ret < 0) {
		LOG_ERR("Payload encryption failed");
		memset(pairing_key, 0, sizeof(pairing_key));
		return 0;
	}

	memcpy(ja.coord_pub_key, pair_ctx->_pub_key, LS_PUBKEY_SIZE);
	memcpy(ja.enc_payload, enc_buf, sizeof(enc_buf));

	ret = ls_frame_init(&resp, LS_JOIN_ACCEPT_PAYLOAD_SIZE,
			    resp_buf, sizeof(resp_buf));
	if (ret < 0) {
		memset(pairing_key, 0, sizeof(pairing_key));
		return 0;
	}

	ls_frame_set_type(&resp, LS_TYPE_JOIN_ACCEPT);
	ls_frame_set_src(&resp, LS_COORD_ADDR);
	ls_frame_set_dst(&resp, LS_BCAST_ADDR);
	ls_frame_set_fcnt(&resp, ctx->fcnt++);
	ls_frame_set_flags(&resp, 0);
	ls_frame_set_payload(&resp, (const uint8_t *)&ja);

	/*
	 * Sign with the ephemeral pairing key.  The node verifies this MIC
	 * using the same derived key, which authenticates the coordinator and
	 * binds the JOIN_ACCEPT to the specific ECDH exchange.
	 */
	ret = ls_frame_sign(&resp, pairing_key);
	memset(pairing_key, 0, sizeof(pairing_key));
	if (ret < 0) {
		LOG_ERR("JOIN_ACCEPT sign failed");
		return 0;
	}

	ls_mac_send(ctx, &resp);

	memset(pair_ctx->_priv_key, 0, sizeof(pair_ctx->_priv_key));
	memset(pair_ctx->_pub_key, 0, sizeof(pair_ctx->_pub_key));

	memset(&rec, 0, sizeof(rec));
	memcpy(rec.dev_eui, jr->dev_eui, LS_DEV_EUI_SIZE);
	rec.fcnt_last = 0;

	pair_ctx->nodes[slot].active     = true;
	pair_ctx->nodes[slot].short_addr = short_addr;
	pair_ctx->nodes[slot].rec        = rec;

	if (!is_repair) {
		pair_ctx->next_addr++;
	}

	ls_storage_coord_save_node(short_addr, &rec);
	if (!is_repair) {
		ls_storage_coord_save_next_addr(ctx, pair_ctx->next_addr);
	}
	ls_storage_save_fcnt(ctx);

	pairing_close_window(pair_ctx);
	k_work_cancel_delayable(&pair_ctx->_close_work);

	LOG_INF("Node 0x%04x %s", short_addr, is_repair ? "re-paired" : "joined");

	if (pair_ctx->_join_cb) {
		pair_ctx->_join_cb(ctx, short_addr, jr->dev_eui, pair_ctx->_join_cb_ud);
	}

	return -1;
}

int ls_pairing_coord_init(struct ls_ctx *ctx, struct ls_coord_pairing_ctx *pair_ctx,
			  ls_pairing_join_cb cb, void *user_data)
{
	memset(pair_ctx, 0, sizeof(*pair_ctx));
	pair_ctx->next_addr   = LS_ADDR_MIN;
	pair_ctx->_ctx        = ctx;
	pair_ctx->_join_cb    = cb;
	pair_ctx->_join_cb_ud = user_data;

	k_work_init_delayable(&pair_ctx->_close_work, pairing_close_work_handler);

	return ls_storage_coord_load(ctx, &pair_ctx->next_addr,
				     pairing_on_node_loaded, pair_ctx);
}

int ls_pairing_coord_start(struct ls_coord_pairing_ctx *pair_ctx)
{
	static const struct ls_frame_filter jr_filter = {
		.type = LS_TYPE_JOIN_REQ,
		.src  = LS_BCAST_ADDR,
		.dst  = LS_BCAST_ADDR,
	};
	int ret;

	ret = pairing_ecdh_gen_keypair(pair_ctx->_pub_key, pair_ctx->_priv_key);
	if (ret < 0) {
		LOG_ERR("ECDH keygen failed");
		return ret;
	}

	pair_ctx->_join_req_hdl = ls_register_frame_cb(pair_ctx->_ctx, &jr_filter,
							pairing_join_req_cb, pair_ctx);
	if (!pair_ctx->_join_req_hdl) {
		memset(pair_ctx->_priv_key, 0, sizeof(pair_ctx->_priv_key));
		memset(pair_ctx->_pub_key, 0, sizeof(pair_ctx->_pub_key));
		return -ENOMEM;
	}

	pair_ctx->_pairing_open = true;
	k_work_schedule(&pair_ctx->_close_work,
			K_SECONDS(CONFIG_LORA_STAR_PAIRING_WINDOW_S));

	LOG_INF("Pairing window open (%d s)", CONFIG_LORA_STAR_PAIRING_WINDOW_S);
	return 0;
}

#endif /* CONFIG_LORA_STAR_COORDINATOR */

/* --------------------------------------------------------------------------
 * Node side
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LORA_STAR_NODE

/*
 * Called by the LoRa Star thread (from ls_dispatch_frame) when a JOIN_ACCEPT
 * arrives.  Verifies the pairing MIC, recovers the session key and short
 * address, and stores the result in pair_ctx->_result.  Returns -1 to consume
 * the frame on success or crypto error; returns 0 (not consumed) if the MIC
 * does not match (e.g. a JOIN_ACCEPT from a different coordinator or network),
 * which tells the thread to restart the retry timer and keep waiting.
 */
static int pairing_join_accept_cb(struct ls_ctx *ctx, struct ls_frame *frame,
				  void *user_data)
{
	struct ls_node_pairing_ctx *pair_ctx = user_data;
	uint8_t *payload;
	size_t payload_len;
	const struct ls_join_accept_payload *ja;
	uint8_t shared[LS_PUBKEY_SIZE];
	uint8_t pairing_key[LS_NETWORK_KEY_SIZE];
	uint8_t dec_buf[sizeof(uint16_t) + LS_NETWORK_KEY_SIZE];
	uint8_t ctr_nonce[LS_CTR_NONCE_SIZE];
	uint8_t network_key[LS_NETWORK_KEY_SIZE];
	uint16_t short_addr;
	int ret;

	ls_frame_get_payload(frame, &payload, &payload_len);

	if (ls_frame_get_src(frame) != LS_COORD_ADDR ||
	    payload_len != LS_JOIN_ACCEPT_PAYLOAD_SIZE) {
		return 0;
	}

	ja = (const struct ls_join_accept_payload *)payload;

	ret = pairing_ecdh_shared(pair_ctx->_priv_key, ja->coord_pub_key, shared);
	if (ret < 0) {
		LOG_ERR("ECDH failed");
		goto fail;
	}

	ret = pairing_hkdf_pairing_key(shared, pair_ctx->dev_eui, pair_ctx->_nonce,
				       pairing_key);
	memset(shared, 0, sizeof(shared));
	if (ret < 0) {
		LOG_ERR("Key derivation failed");
		goto fail;
	}

	/*
	 * Verify the JOIN_ACCEPT MIC using the freshly derived pairing key.
	 * Return 0 (not consumed) on mismatch so the thread restarts the retry
	 * timer and keeps waiting — this JOIN_ACCEPT was not for us.
	 */
	ret = ls_frame_check_signature(frame, pairing_key);
	if (ret < 0) {
		LOG_WRN("JOIN_ACCEPT MIC mismatch — ignoring frame");
		memset(pairing_key, 0, sizeof(pairing_key));
		return 0;
	}

	memcpy(dec_buf, ja->enc_payload, sizeof(dec_buf));
	memset(ctr_nonce, 0, sizeof(ctr_nonce));
	memcpy(ctr_nonce, pair_ctx->_nonce, LS_NONCE_SIZE);
	ret = ls_crypto_ctr(dec_buf, sizeof(dec_buf), pairing_key, ctr_nonce, true);
	memset(pairing_key, 0, sizeof(pairing_key));
	if (ret < 0) {
		LOG_ERR("Payload decryption failed");
		goto fail;
	}

	short_addr = sys_get_le16(dec_buf);
	memcpy(network_key, dec_buf + sizeof(uint16_t), LS_NETWORK_KEY_SIZE);
	memset(dec_buf, 0, sizeof(dec_buf));

	memset(pair_ctx->_priv_key, 0, sizeof(pair_ctx->_priv_key));
	memset(pair_ctx->_pub_key, 0, sizeof(pair_ctx->_pub_key));

	ls_set_network_key(ctx, network_key);
	ls_set_own_addr(ctx, short_addr);
	memset(network_key, 0, sizeof(network_key));

	ls_storage_save_all(ctx);

	LOG_INF("Joined — ShortAddr 0x%04x", short_addr);
	pair_ctx->_result = 0;
	return -1;

fail:
	pair_ctx->_result = (ret < 0) ? ret : -EIO;
	return -1;
}

/*
 * Called by the LoRa Star thread after a JOIN_ACCEPT was received and
 * dispatched (ret=0), or after all retries are exhausted (ret=-ETIMEDOUT),
 * or after a hard send failure (ret<0).  Delivers the final result to the
 * application via pair_ctx->done_cb.
 */
static void pairing_node_done_cb(int ret, void *user_data)
{
	struct ls_node_pairing_ctx *pair_ctx = user_data;
	int result = (ret == 0) ? pair_ctx->_result : ret;

	ls_unregister_frame_cb(pair_ctx->_ctx, pair_ctx->_join_accept_hdl);
	pair_ctx->_join_accept_hdl = NULL;

	if (pair_ctx->done_cb) {
		pair_ctx->done_cb(pair_ctx->_ctx, result, pair_ctx->done_user_data);
	}
}

/**
 * @brief Start node pairing asynchronously.
 *
 * Generates a fresh ECDH keypair and nonce, builds and signs a JOIN_REQ frame
 * (all synchronous crypto happens in the caller's context), then posts a
 * LS_EVENT_TX_RAW event to the LoRa Star queue.  The thread handles
 * transmission, response waiting, and retries transparently.  The result is
 * delivered via pair_ctx->done_cb from the LoRa Star thread context.
 */
int ls_pairing_node_start(struct ls_ctx *ctx, struct ls_node_pairing_ctx *pair_ctx)
{
	static const struct ls_frame_filter ja_filter = {
		.type = LS_TYPE_JOIN_ACCEPT,
		.src  = LS_COORD_ADDR,
		.dst  = LS_BCAST_ADDR,
	};
	struct ls_join_req_payload jr;
	struct ls_frame frame;
	uint8_t frame_buf[LS_FRAME_SIZE(LS_JOIN_REQ_PAYLOAD_SIZE)];
	uint8_t jr_key[LS_NETWORK_KEY_SIZE];
	uint32_t window_ms;
	int ret;

	if (ctx == NULL || pair_ctx == NULL) {
		return -EINVAL;
	}

	pair_ctx->_ctx    = ctx;
	pair_ctx->_result = -ETIMEDOUT;

	ret = sys_csrand_get(pair_ctx->_nonce, sizeof(pair_ctx->_nonce));
	if (ret < 0) {
		return ret;
	}

	ret = pairing_ecdh_gen_keypair(pair_ctx->_pub_key, pair_ctx->_priv_key);
	if (ret < 0) {
		return ret;
	}

	pair_ctx->_join_accept_hdl = ls_register_frame_cb(ctx, &ja_filter,
							   pairing_join_accept_cb,
							   pair_ctx);
	if (!pair_ctx->_join_accept_hdl) {
		memset(pair_ctx->_priv_key, 0, sizeof(pair_ctx->_priv_key));
		memset(pair_ctx->_pub_key, 0, sizeof(pair_ctx->_pub_key));
		return -ENOMEM;
	}

	memcpy(jr.dev_eui,      pair_ctx->dev_eui,  LS_DEV_EUI_SIZE);
	memcpy(jr.node_pub_key, pair_ctx->_pub_key, LS_PUBKEY_SIZE);
	memcpy(jr.nonce,        pair_ctx->_nonce,   LS_NONCE_SIZE);

	pairing_join_req_mic_key(pair_ctx->dev_eui, jr_key);

	ret = ls_frame_init(&frame, LS_JOIN_REQ_PAYLOAD_SIZE,
			    frame_buf, sizeof(frame_buf));
	if (ret < 0) {
		goto cleanup;
	}

	ls_frame_set_type(&frame, LS_TYPE_JOIN_REQ);
	ls_frame_set_src(&frame, LS_BCAST_ADDR);
	ls_frame_set_dst(&frame, LS_BCAST_ADDR);
	ls_frame_set_fcnt(&frame, 0);
	ls_frame_set_flags(&frame, 0);
	ls_frame_set_payload(&frame, (const uint8_t *)&jr);

	/*
	 * Sign with the DevEUI-based MIC key.  Both sides derive the same key
	 * from the public DevEUI; this provides frame integrity without a
	 * pre-shared secret.
	 */
	ret = ls_frame_sign(&frame, jr_key);
	memset(jr_key, 0, sizeof(jr_key));
	if (ret < 0) {
		goto cleanup;
	}

	/*
	 * RX window: coordinator ECDH processing + JOIN_ACCEPT airtime + guard.
	 * The thread uses this as the per-attempt timeout (retried up to
	 * CONFIG_LORA_STAR_TX_MAX_RETRIES times).
	 */
	window_ms = ls_mac_airtime_ms(ctx, LS_FRAME_SIZE(LS_JOIN_ACCEPT_PAYLOAD_SIZE))
		  + CONFIG_LORA_STAR_ACK_GUARD_MS
		  + CONFIG_LORA_STAR_PAIRING_CRYPTO_GUARD_MS;

	ret = ls_send_raw_async(ctx, frame_buf, sizeof(frame_buf),
				true, LS_TYPE_JOIN_ACCEPT, LS_COORD_ADDR,
				window_ms, pairing_node_done_cb, pair_ctx);
	if (ret == 0) {
		return 0;
	}

cleanup:
	memset(jr_key, 0, sizeof(jr_key));
	ls_unregister_frame_cb(ctx, pair_ctx->_join_accept_hdl);
	pair_ctx->_join_accept_hdl = NULL;
	memset(pair_ctx->_priv_key, 0, sizeof(pair_ctx->_priv_key));
	memset(pair_ctx->_pub_key, 0, sizeof(pair_ctx->_pub_key));
	return ret;
}

#endif /* CONFIG_LORA_STAR_NODE */
