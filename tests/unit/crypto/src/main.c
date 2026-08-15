/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <string.h>
#include <lora_star/ls_frame.h>
#include <lora_star/ls_crypto.h>

static const uint8_t test_dev_eui[LS_DEV_EUI_SIZE]  = {0x01, 0x02, 0x03, 0x04,
							 0x05, 0x06, 0x07, 0x08};
static const uint8_t test_nonce[LS_NONCE_SIZE]       = {0xAA, 0xBB, 0xCC, 0xDD};
static const uint8_t alt_nonce[LS_NONCE_SIZE]        = {0x11, 0x22, 0x33, 0x44};
static const uint8_t test_session_key[LS_SESSION_KEY_SIZE] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

/* --------------------------------------------------------------------------
 * Suite setup — initialise PSA once for all tests
 * -------------------------------------------------------------------------- */

static void *crypto_setup(void)
{
	return NULL;
}

/* --------------------------------------------------------------------------
 * JOIN_REQ integrity key
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_crypto, test_join_req_key_format)
{
	uint8_t key[LS_SESSION_KEY_SIZE];

	ls_crypto_join_req_key(test_dev_eui, key);

	zassert_mem_equal(key, test_dev_eui, LS_DEV_EUI_SIZE);
	for (int i = LS_DEV_EUI_SIZE; i < LS_SESSION_KEY_SIZE; i++) {
		zassert_equal(key[i], 0, "byte %d not zero", i);
	}
}

/* --------------------------------------------------------------------------
 * ECDH
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_crypto, test_ecdh_keypair_gen_nonzero)
{
	uint8_t pub[LS_PUBKEY_SIZE]  = {0};
	uint8_t priv[LS_PUBKEY_SIZE] = {0};
	uint8_t zeros[LS_PUBKEY_SIZE] = {0};

	int ret = ls_crypto_ecdh_gen_keypair(pub, priv);

	zassert_equal(ret, 0, "keypair gen failed: %d", ret);
	zassert_false(memcmp(pub,  zeros, LS_PUBKEY_SIZE) == 0, "public key is all zeros");
	zassert_false(memcmp(priv, zeros, LS_PUBKEY_SIZE) == 0, "private key is all zeros");
}

ZTEST(lora_star_crypto, test_ecdh_keypairs_differ)
{
	uint8_t pub_a[LS_PUBKEY_SIZE], priv_a[LS_PUBKEY_SIZE];
	uint8_t pub_b[LS_PUBKEY_SIZE], priv_b[LS_PUBKEY_SIZE];

	zassert_equal(ls_crypto_ecdh_gen_keypair(pub_a, priv_a), 0);
	zassert_equal(ls_crypto_ecdh_gen_keypair(pub_b, priv_b), 0);

	zassert_false(memcmp(pub_a, pub_b, LS_PUBKEY_SIZE) == 0,
		      "two generated public keys should not be equal");
}

ZTEST(lora_star_crypto, test_ecdh_shared_secret_symmetric)
{
	uint8_t pub_a[LS_PUBKEY_SIZE], priv_a[LS_PUBKEY_SIZE];
	uint8_t pub_b[LS_PUBKEY_SIZE], priv_b[LS_PUBKEY_SIZE];
	uint8_t shared_ab[LS_PUBKEY_SIZE];
	uint8_t shared_ba[LS_PUBKEY_SIZE];

	zassert_equal(ls_crypto_ecdh_gen_keypair(pub_a, priv_a), 0);
	zassert_equal(ls_crypto_ecdh_gen_keypair(pub_b, priv_b), 0);

	zassert_equal(ls_crypto_ecdh_shared(priv_a, pub_b, shared_ab), 0,
		      "A->B shared secret failed");
	zassert_equal(ls_crypto_ecdh_shared(priv_b, pub_a, shared_ba), 0,
		      "B->A shared secret failed");

	zassert_mem_equal(shared_ab, shared_ba, LS_PUBKEY_SIZE,
			  "shared secrets do not match");
}

/* --------------------------------------------------------------------------
 * Session key derivation
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_crypto, test_session_key_deterministic)
{
	uint8_t shared[LS_PUBKEY_SIZE];
	uint8_t key_a[LS_SESSION_KEY_SIZE];
	uint8_t key_b[LS_SESSION_KEY_SIZE];

	memset(shared, 0x42, sizeof(shared));

	zassert_equal(ls_crypto_derive_session_key(shared, test_dev_eui, test_nonce, key_a), 0);
	zassert_equal(ls_crypto_derive_session_key(shared, test_dev_eui, test_nonce, key_b), 0);

	zassert_mem_equal(key_a, key_b, LS_SESSION_KEY_SIZE,
			  "same inputs must produce the same session key");
}

ZTEST(lora_star_crypto, test_session_key_differs_by_nonce)
{
	uint8_t shared[LS_PUBKEY_SIZE];
	uint8_t key_a[LS_SESSION_KEY_SIZE];
	uint8_t key_b[LS_SESSION_KEY_SIZE];

	memset(shared, 0x42, sizeof(shared));

	zassert_equal(ls_crypto_derive_session_key(shared, test_dev_eui, test_nonce, key_a), 0);
	zassert_equal(ls_crypto_derive_session_key(shared, test_dev_eui, alt_nonce,  key_b), 0);

	zassert_false(memcmp(key_a, key_b, LS_SESSION_KEY_SIZE) == 0,
		      "different nonces must produce different session keys");
}

ZTEST(lora_star_crypto, test_session_key_nonzero)
{
	uint8_t shared[LS_PUBKEY_SIZE];
	uint8_t key[LS_SESSION_KEY_SIZE];
	uint8_t zeros[LS_SESSION_KEY_SIZE] = {0};

	memset(shared, 0x42, sizeof(shared));
	zassert_equal(ls_crypto_derive_session_key(shared, test_dev_eui, test_nonce, key), 0);
	zassert_false(memcmp(key, zeros, LS_SESSION_KEY_SIZE) == 0,
		      "derived session key must not be all zeros");
}

/* --------------------------------------------------------------------------
 * Short-address encrypt / decrypt
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_crypto, test_short_addr_encrypt_decrypt_roundtrip)
{
	uint8_t shared[LS_PUBKEY_SIZE];
	uint16_t plain = 0x0042;
	uint16_t cipher, recovered;

	memset(shared, 0x5A, sizeof(shared));

	zassert_equal(ls_crypto_encrypt_short_addr(shared, test_nonce, plain, &cipher), 0);
	zassert_equal(ls_crypto_decrypt_short_addr(shared, test_nonce, cipher, &recovered), 0);
	zassert_equal(recovered, plain, "decrypted address 0x%04x != original 0x%04x",
		      recovered, plain);
}

ZTEST(lora_star_crypto, test_short_addr_cipher_differs_from_plain)
{
	uint8_t shared[LS_PUBKEY_SIZE];
	uint16_t plain = 0x0001;
	uint16_t cipher;

	memset(shared, 0x5A, sizeof(shared));
	zassert_equal(ls_crypto_encrypt_short_addr(shared, test_nonce, plain, &cipher), 0);
	zassert_not_equal(cipher, plain, "cipher should differ from plaintext");
}

/* --------------------------------------------------------------------------
 * Payload AES-128-CTR
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_crypto, test_payload_crypt_roundtrip)
{
	uint8_t plain[16]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
	uint8_t cipher[16] = {0};
	uint8_t recover[16] = {0};
	uint16_t fcnt = 100, src = 0x0001;

	zassert_equal(ls_crypto_payload_crypt(test_session_key, fcnt, src, plain, cipher,
					      sizeof(plain)), 0);
	zassert_equal(ls_crypto_payload_crypt(test_session_key, fcnt, src, cipher, recover,
					      sizeof(cipher)), 0);
	zassert_mem_equal(recover, plain, sizeof(plain), "decrypted payload does not match");
}

ZTEST(lora_star_crypto, test_payload_crypt_differs_by_fcnt)
{
	uint8_t plain[8]   = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
	uint8_t cipher_a[8] = {0};
	uint8_t cipher_b[8] = {0};

	zassert_equal(ls_crypto_payload_crypt(test_session_key, 1, 0x0001, plain, cipher_a,
					      sizeof(plain)), 0);
	zassert_equal(ls_crypto_payload_crypt(test_session_key, 2, 0x0001, plain, cipher_b,
					      sizeof(plain)), 0);
	zassert_false(memcmp(cipher_a, cipher_b, sizeof(plain)) == 0,
		      "different FCNT must produce different ciphertext");
}

ZTEST(lora_star_crypto, test_payload_crypt_differs_by_src)
{
	uint8_t plain[8]   = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	uint8_t cipher_a[8] = {0};
	uint8_t cipher_b[8] = {0};

	zassert_equal(ls_crypto_payload_crypt(test_session_key, 1, 0x0001, plain, cipher_a,
					      sizeof(plain)), 0);
	zassert_equal(ls_crypto_payload_crypt(test_session_key, 1, 0x0002, plain, cipher_b,
					      sizeof(plain)), 0);
	zassert_false(memcmp(cipher_a, cipher_b, sizeof(plain)) == 0,
		      "different SRC must produce different ciphertext");
}

/* --------------------------------------------------------------------------
 * AES-CMAC MIC
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_crypto, test_mic_deterministic)
{
	uint8_t header[LS_HEADER_SIZE] = {LS_TYPE_DATA, 0x01, 0x00, 0x00, 0x00,
					   0x01, 0x00, 0x00, 0x00, LS_FLAG_ACK_REQ};
	uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};
	uint8_t mic_a[LS_MIC_SIZE], mic_b[LS_MIC_SIZE];

	zassert_equal(ls_crypto_compute_mic(test_session_key, header, sizeof(header),
					    payload, sizeof(payload), mic_a), 0);
	zassert_equal(ls_crypto_compute_mic(test_session_key, header, sizeof(header),
					    payload, sizeof(payload), mic_b), 0);
	zassert_mem_equal(mic_a, mic_b, LS_MIC_SIZE, "MIC not deterministic");
}

ZTEST(lora_star_crypto, test_mic_differs_by_payload)
{
	uint8_t header[LS_HEADER_SIZE] = {LS_TYPE_DATA, 0x01, 0x00, 0x00, 0x00,
					   0x01, 0x00, 0x00, 0x00, 0x00};
	uint8_t payload_a[4] = {0xDE, 0xAD, 0xBE, 0xEF};
	uint8_t payload_b[4] = {0xDE, 0xAD, 0xBE, 0xFE};
	uint8_t mic_a[LS_MIC_SIZE], mic_b[LS_MIC_SIZE];

	zassert_equal(ls_crypto_compute_mic(test_session_key, header, sizeof(header),
					    payload_a, sizeof(payload_a), mic_a), 0);
	zassert_equal(ls_crypto_compute_mic(test_session_key, header, sizeof(header),
					    payload_b, sizeof(payload_b), mic_b), 0);
	zassert_false(memcmp(mic_a, mic_b, LS_MIC_SIZE) == 0,
		      "different payloads must produce different MICs");
}

ZTEST(lora_star_crypto, test_mic_nonzero)
{
	uint8_t header[LS_HEADER_SIZE] = {LS_TYPE_DATA, 0x01, 0x00, 0x00, 0x00,
					   0x01, 0x00, 0x00, 0x00, 0x00};
	uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	uint8_t mic[LS_MIC_SIZE] = {0};
	uint8_t zeros[LS_MIC_SIZE] = {0};

	zassert_equal(ls_crypto_compute_mic(test_session_key, header, sizeof(header),
					    payload, sizeof(payload), mic), 0);
	zassert_false(memcmp(mic, zeros, LS_MIC_SIZE) == 0, "MIC must not be all zeros");
}

ZTEST(lora_star_crypto, test_mic_no_payload)
{
	uint8_t header[LS_HEADER_SIZE] = {LS_TYPE_ACK, 0x00, 0x00, 0x01, 0x00,
					   0x05, 0x00, 0x00, 0x00, 0x00};
	uint8_t mic[LS_MIC_SIZE] = {0};

	/* Must succeed with NULL payload (header-only frame like ACK) */
	int ret = ls_crypto_compute_mic(test_session_key, header, sizeof(header),
					NULL, 0, mic);

	zassert_equal(ret, 0);
}

/* --------------------------------------------------------------------------
 * End-to-end: ECDH pairing + session key + encrypt + MIC
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_crypto, test_full_pairing_key_derivation)
{
	uint8_t node_pub[LS_PUBKEY_SIZE], node_priv[LS_PUBKEY_SIZE];
	uint8_t coord_pub[LS_PUBKEY_SIZE], coord_priv[LS_PUBKEY_SIZE];
	uint8_t shared_node[LS_PUBKEY_SIZE], shared_coord[LS_PUBKEY_SIZE];
	uint8_t key_node[LS_SESSION_KEY_SIZE], key_coord[LS_SESSION_KEY_SIZE];

	zassert_equal(ls_crypto_ecdh_gen_keypair(node_pub, node_priv), 0);
	zassert_equal(ls_crypto_ecdh_gen_keypair(coord_pub, coord_priv), 0);

	zassert_equal(ls_crypto_ecdh_shared(node_priv, coord_pub, shared_node), 0);
	zassert_equal(ls_crypto_ecdh_shared(coord_priv, node_pub, shared_coord), 0);

	zassert_mem_equal(shared_node, shared_coord, LS_PUBKEY_SIZE,
			  "shared secrets must agree");

	zassert_equal(ls_crypto_derive_session_key(shared_node,  test_dev_eui, test_nonce,
						    key_node), 0);
	zassert_equal(ls_crypto_derive_session_key(shared_coord, test_dev_eui, test_nonce,
						    key_coord), 0);

	zassert_mem_equal(key_node, key_coord, LS_SESSION_KEY_SIZE,
			  "both sides must derive the same session key");
}

ZTEST_SUITE(lora_star_crypto, NULL, crypto_setup, NULL, NULL, NULL);
