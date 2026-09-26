/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <psa/crypto.h>
#include <mbedtls/constant_time.h>
#include <zephyr/sys/byteorder.h>

#include <lora_star/crypto.h>

/*
 * AES-128-CTR encrypt/decrypt
 *
 * CTR (Counter) mode turns AES into a stream cipher: the block cipher is
 * applied to a unique nonce/counter value to produce a keystream, which is
 * then XOR-ed with the plaintext.  Because XOR is its own inverse, the same
 * operation encrypts and decrypts — only the PSA setup call differs.
 *
 * Security requirement: the nonce must be unique for every (key, frame) pair.
 * It does NOT need to be secret — an attacker who knows the nonce but not the
 * key still cannot compute the keystream (AES(key, counter) requires the key).
 * This is the same approach used by TLS 1.3, QUIC, and LoRaWAN.
 *
 * Nonce construction (16 bytes, matching the AES block size):
 *   [0..3]  FCNT, little-endian  — strictly monotonic per sender; ensures
 *                                   every frame gets a different nonce
 *   [4..5]  SRC,  little-endian  — prevents two peers encrypting with the
 *                                   same key from sharing a nonce
 *   [6..15] 0x00                 — padding to fill the 128-bit nonce
 *
 * Uniqueness guarantee: as long as (FCNT, SRC) never repeats for a given
 * session key, the nonce never repeats and CTR remains secure.  FCNT is
 * strictly monotonic within a session and every session uses a fresh key
 * (see the rejoin handshake), so this holds without needing FCNT itself to
 * survive a reboot.
 *
 * The caller's buffer is overwritten with the encrypted (or decrypted) bytes.
 */
int ls_crypto_ctr(uint8_t *buf, size_t len, const uint8_t key[LS_NETWORK_KEY_SIZE],
		  const uint8_t nonce[LS_CTR_NONCE_SIZE], int encrypt)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
	/*
	 * PSA's CTR implementation may process data in full AES blocks (16 bytes)
	 * internally.  psa_cipher_update() requires an output buffer of at least
	 * ROUND_UP(input_length, 16) bytes even when fewer bytes are produced;
	 * passing an input-sized buffer for sub-block inputs returns
	 * PSA_ERROR_BUFFER_TOO_SMALL.  Use a separate, block-aligned staging
	 * buffer and copy the result back into buf afterwards.
	 *
	 * Sized for the largest possible payload plus one extra block for any
	 * bytes flushed by psa_cipher_finish().
	 */
	uint8_t tmp[PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(LS_MAX_PAYLOAD_SIZE) +
		    PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE];
	size_t olen;
	size_t flen;
	psa_status_t st;

	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	/*
	 * Grant both directions so the same imported key handle works for
	 * encrypt and decrypt without re-importing.
	 */
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);

	st = psa_import_key(&attr, key, LS_NETWORK_KEY_SIZE, &key_id);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	/*
	 * For CTR the encrypt and decrypt keystreams are mathematically
	 * identical.  PSA still requires the matching setup call so that it
	 * can enforce key-usage policy correctly.
	 */
	if (encrypt) {
		st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CTR);
	} else {
		st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CTR);
	}
	if (st != PSA_SUCCESS) {
		goto out;
	}

	/* Supply our hand-crafted nonce instead of letting PSA generate one. */
	st = psa_cipher_set_iv(&op, nonce, LS_CTR_NONCE_SIZE);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_cipher_update(&op, buf, len, tmp, sizeof(tmp), &olen);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	/*
	 * psa_cipher_finish() flushes any bytes buffered during update.  For
	 * CTR with no padding the total output (olen + flen) always equals len.
	 */
	st = psa_cipher_finish(&op, tmp + olen, sizeof(tmp) - olen, &flen);
	if (st == PSA_SUCCESS) {
		memcpy(buf, tmp, olen + flen);
	}

out:
	psa_cipher_abort(&op);
	psa_destroy_key(key_id);
	return (st == PSA_SUCCESS) ? 0 : -EIO;
}

/*
 * HKDF-SHA256 (RFC 5869), two-step extract-then-expand:
 *   Extract: PRK = HMAC-SHA256(salt, IKM)
 *   Expand:  output = first LS_NETWORK_KEY_SIZE bytes of HMAC-SHA256(PRK, info)
 *
 * Generic derivation shared by the pairing and rejoin handshakes, each of
 * which supplies a different secret as IKM (an ECDH shared secret, or the
 * long-term network key) and different salt/info to keep the outputs of the
 * two protocols from ever coinciding.
 */
int ls_crypto_hkdf(const uint8_t *ikm, size_t ikm_len,
		   const uint8_t *salt, size_t salt_len,
		   const uint8_t *info, size_t info_len,
		   uint8_t key[LS_NETWORK_KEY_SIZE])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t ikm_id = PSA_KEY_ID_NULL;
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_status_t st;

	/*
	 * PSA requires the HKDF secret (IKM) to be a key handle, not raw
	 * bytes.  Importing as KEY_TYPE_DERIVE enforces that it never leaves
	 * PSA as application-visible bytes via this path.
	 */
	psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_bits(&attr, ikm_len * 8);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));

	st = psa_import_key(&attr, ikm, ikm_len, &ikm_id);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
					    salt, salt_len);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm_id);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
					    info, info_len);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_key_derivation_output_bytes(&op, key, LS_NETWORK_KEY_SIZE);

out:
	psa_key_derivation_abort(&op);
	psa_destroy_key(ikm_id);
	return (st == PSA_SUCCESS) ? 0 : -EIO;
}

int ls_frame_crypto_ctr(struct ls_frame *frame, const uint8_t key[LS_NETWORK_KEY_SIZE],
			 int encrypt)
{
	uint8_t nonce[16] = {0};
	uint8_t *payload;
	size_t payload_len;

	/* Build the per-frame nonce from fields already present in the header. */
	sys_put_le32(ls_frame_get_fcnt(frame), nonce);
	sys_put_le16(ls_frame_get_src(frame), nonce + 4);
	/* bytes 6-15 remain zero from the initialiser above */

	ls_frame_get_payload(frame, &payload, &payload_len);

	return ls_crypto_ctr(payload, payload_len, key, nonce, encrypt);
}

int ls_frame_encrypt(struct ls_frame *frame, const uint8_t key[LS_NETWORK_KEY_SIZE])
{
	return ls_frame_crypto_ctr(frame, key, 1);
}

int ls_frame_decrypt(struct ls_frame *frame, const uint8_t key[LS_NETWORK_KEY_SIZE])
{
	return ls_frame_crypto_ctr(frame, key, 0);
}

static int ls_crypto_compute_mic(const uint8_t *buf, size_t buf_len,
				 const uint8_t key[LS_NETWORK_KEY_SIZE],
				 uint8_t mic[LS_MIC_SIZE])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
	uint8_t tag[16];
	size_t olen;
	psa_status_t st;

	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_CMAC);

	st = psa_import_key(&attr, key, LS_NETWORK_KEY_SIZE, &key_id);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	st = psa_mac_sign_setup(&op, key_id, PSA_ALG_CMAC);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_mac_update(&op, buf, buf_len);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_mac_sign_finish(&op, tag, sizeof(tag), &olen);
	if (st == PSA_SUCCESS) {
		memcpy(mic, tag, LS_MIC_SIZE);
	}

out:
	psa_mac_abort(&op);
	psa_destroy_key(key_id);
	return (st == PSA_SUCCESS) ? 0 : -EIO;
}

int ls_frame_sign(struct ls_frame *frame, const uint8_t key[LS_NETWORK_KEY_SIZE])
{
	uint8_t mic[LS_MIC_SIZE];
	int ret;

	ret = ls_crypto_compute_mic(frame->buf, ls_frame_content_size(frame), key, mic);
	if (ret < 0) {
		return ret;
	}

	ls_frame_set_mic(frame, mic);

	return 0;
}

int ls_frame_check_signature(struct ls_frame *frame, const uint8_t key[LS_NETWORK_KEY_SIZE])
{
	uint8_t exp_mic[LS_MIC_SIZE];
	uint8_t rx_mic[LS_MIC_SIZE];
	int ret;

	ls_frame_get_mic(frame, rx_mic);
	ret = ls_crypto_compute_mic(frame->buf, ls_frame_content_size(frame), key, exp_mic);
	if (ret < 0) {
		return ret;
	}

	if (mbedtls_ct_memcmp(rx_mic, exp_mic, LS_MIC_SIZE) != 0) {
		return -EIO;
	}

	return 0;
}
