#include <string.h>
#include <errno.h>
#include <zephyr/sys/byteorder.h>
#include <psa/crypto.h>
#include <lora_star/ls_frame.h>
#include <lora_star/ls_crypto.h>

/* --------------------------------------------------------------------------
 * ECDH — Curve25519 (X25519)
 * -------------------------------------------------------------------------- */

int ls_crypto_ecdh_gen_keypair(uint8_t pub[LS_PUBKEY_SIZE],
			       uint8_t priv[LS_PUBKEY_SIZE])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	size_t olen;
	psa_status_t st;

	psa_set_key_type(&attr,
		PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attr, 255);
	psa_set_key_usage_flags(&attr,
		PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

	st = psa_generate_key(&attr, &key_id);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	st = psa_export_key(key_id, priv, LS_PUBKEY_SIZE, &olen);
	if (st != PSA_SUCCESS || olen != LS_PUBKEY_SIZE) {
		psa_destroy_key(key_id);
		return -EIO;
	}

	st = psa_export_public_key(key_id, pub, LS_PUBKEY_SIZE, &olen);
	psa_destroy_key(key_id);
	return (st == PSA_SUCCESS && olen == LS_PUBKEY_SIZE) ? 0 : -EIO;
}

int ls_crypto_ecdh_shared(const uint8_t priv[LS_PUBKEY_SIZE],
			   const uint8_t peer_pub[LS_PUBKEY_SIZE],
			   uint8_t shared[LS_PUBKEY_SIZE])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	size_t olen;
	psa_status_t st;

	psa_set_key_type(&attr,
		PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
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
	return (st == PSA_SUCCESS && olen == LS_PUBKEY_SIZE) ? 0 : -EIO;
}

/* --------------------------------------------------------------------------
 * HKDF-SHA256 session key derivation
 * -------------------------------------------------------------------------- */

int ls_crypto_derive_session_key(const uint8_t shared[LS_PUBKEY_SIZE],
				 const uint8_t dev_eui[LS_DEV_EUI_SIZE],
				 const uint8_t nonce[LS_NONCE_SIZE],
				 uint8_t session_key[LS_SESSION_KEY_SIZE])
{
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	uint8_t salt[LS_DEV_EUI_SIZE + LS_NONCE_SIZE];
	static const uint8_t info[] = "lora_star_v1";
	psa_status_t st;

	memcpy(salt, dev_eui, LS_DEV_EUI_SIZE);
	memcpy(salt + LS_DEV_EUI_SIZE, nonce, LS_NONCE_SIZE);

	psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	psa_set_key_bits(&attr, LS_PUBKEY_SIZE * 8);

	st = psa_import_key(&attr, shared, LS_PUBKEY_SIZE, &key_id);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_key_derivation_input_bytes(&op,
		PSA_KEY_DERIVATION_INPUT_SALT, salt, sizeof(salt));
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_key_derivation_input_key(&op,
		PSA_KEY_DERIVATION_INPUT_SECRET, key_id);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_key_derivation_input_bytes(&op,
		PSA_KEY_DERIVATION_INPUT_INFO, info, sizeof(info) - 1);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_key_derivation_output_bytes(&op, session_key,
					     LS_SESSION_KEY_SIZE);

out:
	psa_key_derivation_abort(&op);
	psa_destroy_key(key_id);
	return (st == PSA_SUCCESS) ? 0 : -EIO;
}

/* --------------------------------------------------------------------------
 * AES-128-CTR helpers
 * -------------------------------------------------------------------------- */

static int aes_ctr(const uint8_t key[LS_SESSION_KEY_SIZE],
		   const uint8_t *seed, size_t seed_len,
		   const uint8_t *in, uint8_t *out, uint8_t len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
	/* Extra headroom: PSA may buffer up to one AES block before flushing */
	uint8_t tmp[LS_MAX_PAYLOAD_SIZE + 16];
	uint8_t iv[16] = {0};
	size_t olen = 0, flen = 0;
	psa_status_t st;

	if (len > LS_MAX_PAYLOAD_SIZE) {
		return -EINVAL;
	}

	memcpy(iv, seed, seed_len);

	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);

	st = psa_import_key(&attr, key, LS_SESSION_KEY_SIZE, &key_id);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CTR);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_cipher_set_iv(&op, iv, sizeof(iv));
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_cipher_update(&op, in, len, tmp, sizeof(tmp), &olen);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_cipher_finish(&op, tmp + olen, sizeof(tmp) - olen, &flen);
	if (st == PSA_SUCCESS) {
		memcpy(out, tmp, len);
	}

out:
	psa_cipher_abort(&op);
	psa_destroy_key(key_id);
	return (st == PSA_SUCCESS) ? 0 : -EIO;
}

int ls_crypto_encrypt_short_addr(const uint8_t shared[LS_PUBKEY_SIZE],
				 const uint8_t nonce[LS_NONCE_SIZE],
				 uint16_t plain, uint16_t *cipher_out)
{
	uint8_t p[2], c[2];

	sys_put_le16(plain, p);
	int ret = aes_ctr(shared, nonce, LS_NONCE_SIZE, p, c, sizeof(p));

	if (ret == 0) {
		*cipher_out = sys_get_le16(c);
	}
	return ret;
}

int ls_crypto_decrypt_short_addr(const uint8_t shared[LS_PUBKEY_SIZE],
				 const uint8_t nonce[LS_NONCE_SIZE],
				 uint16_t cipher, uint16_t *plain_out)
{
	return ls_crypto_encrypt_short_addr(shared, nonce, cipher, plain_out);
}

int ls_crypto_payload_crypt(const uint8_t session_key[LS_SESSION_KEY_SIZE],
			    uint32_t fcnt, uint16_t src,
			    const uint8_t *in, uint8_t *out, uint8_t len)
{
	uint8_t seed[6];

	sys_put_le32(fcnt, &seed[0]);
	sys_put_le16(src,  &seed[4]);

	return aes_ctr(session_key, seed, sizeof(seed), in, out, len);
}

/* --------------------------------------------------------------------------
 * AES-CMAC MIC
 * -------------------------------------------------------------------------- */

int ls_crypto_compute_mic(const uint8_t key[LS_SESSION_KEY_SIZE],
			  const uint8_t *header, uint8_t header_len,
			  const uint8_t *payload, uint8_t payload_len,
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

	st = psa_import_key(&attr, key, LS_SESSION_KEY_SIZE, &key_id);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	st = psa_mac_sign_setup(&op, key_id, PSA_ALG_CMAC);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	st = psa_mac_update(&op, header, header_len);
	if (st != PSA_SUCCESS) {
		goto out;
	}

	if (payload_len > 0) {
		st = psa_mac_update(&op, payload, payload_len);
		if (st != PSA_SUCCESS) {
			goto out;
		}
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

void ls_crypto_join_req_key(const uint8_t dev_eui[LS_DEV_EUI_SIZE],
			    uint8_t key[LS_SESSION_KEY_SIZE])
{
	memcpy(key, dev_eui, LS_DEV_EUI_SIZE);
	memset(key + LS_DEV_EUI_SIZE, 0, LS_SESSION_KEY_SIZE - LS_DEV_EUI_SIZE);
}
