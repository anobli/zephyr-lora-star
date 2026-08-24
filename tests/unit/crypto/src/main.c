/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <string.h>
#include <errno.h>
#include <lora_star/frame.h>
#include <lora_star/crypto.h>


static const uint8_t test_key[LS_NETWORK_KEY_SIZE] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

static const uint8_t alt_key[LS_NETWORK_KEY_SIZE] = {
	0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
	0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
};

/* Full 16-byte CTR nonces (AES block size). */
static const uint8_t ctr_nonce_a[16] = {
	0x01, 0x00, 0x00, 0x00,  /* FCNT = 1, LE */
	0x01, 0x00,              /* SRC  = 1, LE */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t ctr_nonce_b[16] = {
	0x02, 0x00, 0x00, 0x00,  /* FCNT = 2, LE */
	0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static void build_frame(struct ls_frame *frame, uint8_t *buf, size_t buf_size,
			uint16_t src, uint16_t dst, uint32_t fcnt,
			const uint8_t *payload, size_t payload_len)
{
	ls_frame_init(frame, payload_len, buf, buf_size);
	ls_frame_set_type(frame, LS_TYPE_DATA);
	ls_frame_set_src(frame, src);
	ls_frame_set_dst(frame, dst);
	ls_frame_set_fcnt(frame, fcnt);
	ls_frame_set_flags(frame, 0);
	if (payload && payload_len > 0) {
		ls_frame_set_payload(frame, payload);
	}
}

/* --------------------------------------------------------------------------
 * ls_crypto_ctr — raw AES-128-CTR
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_crypto, test_ctr_roundtrip)
{
	uint8_t plain[16]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			      0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
	uint8_t buf[16];
	uint8_t recover[16];

	memcpy(buf, plain, sizeof(plain));
	zassert_equal(ls_crypto_ctr(buf, sizeof(buf), test_key, ctr_nonce_a, 1), 0,
		      "encrypt failed");

	memcpy(recover, buf, sizeof(buf));
	zassert_equal(ls_crypto_ctr(recover, sizeof(recover), test_key, ctr_nonce_a, 0), 0,
		      "decrypt failed");

	zassert_mem_equal(recover, plain, sizeof(plain), "roundtrip mismatch");
}

ZTEST(lora_star_crypto, test_ctr_cipher_differs_from_plain)
{
	uint8_t buf[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
	uint8_t plain[16];

	memcpy(plain, buf, sizeof(buf));
	zassert_equal(ls_crypto_ctr(buf, sizeof(buf), test_key, ctr_nonce_a, 1), 0);
	zassert_false(memcmp(buf, plain, sizeof(plain)) == 0,
		      "ciphertext must differ from plaintext");
}

ZTEST(lora_star_crypto, test_ctr_nonce_changes_ciphertext)
{
	uint8_t plain[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
	uint8_t cipher_a[8];
	uint8_t cipher_b[8];

	memcpy(cipher_a, plain, sizeof(plain));
	memcpy(cipher_b, plain, sizeof(plain));

	zassert_equal(ls_crypto_ctr(cipher_a, sizeof(cipher_a), test_key, ctr_nonce_a, 1), 0);
	zassert_equal(ls_crypto_ctr(cipher_b, sizeof(cipher_b), test_key, ctr_nonce_b, 1), 0);

	zassert_false(memcmp(cipher_a, cipher_b, sizeof(plain)) == 0,
		      "different nonces must produce different ciphertext");
}

ZTEST(lora_star_crypto, test_ctr_key_changes_ciphertext)
{
	uint8_t plain[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
	uint8_t cipher_a[8];
	uint8_t cipher_b[8];

	memcpy(cipher_a, plain, sizeof(plain));
	memcpy(cipher_b, plain, sizeof(plain));

	zassert_equal(ls_crypto_ctr(cipher_a, sizeof(cipher_a), test_key, ctr_nonce_a, 1), 0);
	zassert_equal(ls_crypto_ctr(cipher_b, sizeof(cipher_b), alt_key,  ctr_nonce_a, 1), 0);

	zassert_false(memcmp(cipher_a, cipher_b, sizeof(plain)) == 0,
		      "different keys must produce different ciphertext");
}

/* --------------------------------------------------------------------------
 * ls_frame_encrypt / ls_frame_decrypt
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_crypto, test_frame_encrypt_decrypt_roundtrip)
{
	uint8_t plain[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	uint8_t buf[LS_FRAME_SIZE(sizeof(plain))];
	struct ls_frame frame;
	uint8_t *payload;
	size_t payload_len;

	build_frame(&frame, buf, sizeof(buf), 0x0001, LS_COORD_ADDR, 42,
		    plain, sizeof(plain));

	zassert_equal(ls_frame_encrypt(&frame, test_key), 0, "encrypt failed");
	zassert_equal(ls_frame_decrypt(&frame, test_key), 0, "decrypt failed");

	ls_frame_get_payload(&frame, &payload, &payload_len);
	zassert_equal(payload_len, sizeof(plain));
	zassert_mem_equal(payload, plain, sizeof(plain), "roundtrip mismatch");
}

ZTEST(lora_star_crypto, test_frame_encrypt_modifies_payload)
{
	uint8_t plain[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
	uint8_t buf[LS_FRAME_SIZE(sizeof(plain))];
	struct ls_frame frame;
	uint8_t *payload;
	size_t payload_len;

	build_frame(&frame, buf, sizeof(buf), 0x0001, LS_COORD_ADDR, 1,
		    plain, sizeof(plain));

	zassert_equal(ls_frame_encrypt(&frame, test_key), 0);

	ls_frame_get_payload(&frame, &payload, &payload_len);
	zassert_false(memcmp(payload, plain, sizeof(plain)) == 0,
		      "encrypted payload must differ from plaintext");
}

ZTEST(lora_star_crypto, test_frame_encrypt_fcnt_changes_ciphertext)
{
	uint8_t plain[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	uint8_t buf_a[LS_FRAME_SIZE(sizeof(plain))];
	uint8_t buf_b[LS_FRAME_SIZE(sizeof(plain))];
	struct ls_frame frame_a, frame_b;
	uint8_t *payload_a, *payload_b;
	size_t payload_len;

	build_frame(&frame_a, buf_a, sizeof(buf_a), 0x0001, LS_COORD_ADDR, 1,
		    plain, sizeof(plain));
	build_frame(&frame_b, buf_b, sizeof(buf_b), 0x0001, LS_COORD_ADDR, 2,
		    plain, sizeof(plain));

	zassert_equal(ls_frame_encrypt(&frame_a, test_key), 0);
	zassert_equal(ls_frame_encrypt(&frame_b, test_key), 0);

	ls_frame_get_payload(&frame_a, &payload_a, &payload_len);
	ls_frame_get_payload(&frame_b, &payload_b, &payload_len);

	zassert_false(memcmp(payload_a, payload_b, sizeof(plain)) == 0,
		      "different FCNT must produce different ciphertext");
}

ZTEST(lora_star_crypto, test_frame_encrypt_src_changes_ciphertext)
{
	uint8_t plain[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
	uint8_t buf_a[LS_FRAME_SIZE(sizeof(plain))];
	uint8_t buf_b[LS_FRAME_SIZE(sizeof(plain))];
	struct ls_frame frame_a, frame_b;
	uint8_t *payload_a, *payload_b;
	size_t payload_len;

	build_frame(&frame_a, buf_a, sizeof(buf_a), 0x0001, LS_COORD_ADDR, 5,
		    plain, sizeof(plain));
	build_frame(&frame_b, buf_b, sizeof(buf_b), 0x0002, LS_COORD_ADDR, 5,
		    plain, sizeof(plain));

	zassert_equal(ls_frame_encrypt(&frame_a, test_key), 0);
	zassert_equal(ls_frame_encrypt(&frame_b, test_key), 0);

	ls_frame_get_payload(&frame_a, &payload_a, &payload_len);
	ls_frame_get_payload(&frame_b, &payload_b, &payload_len);

	zassert_false(memcmp(payload_a, payload_b, sizeof(plain)) == 0,
		      "different SRC must produce different ciphertext");
}

/* --------------------------------------------------------------------------
 * ls_frame_sign / ls_frame_check_signature
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_crypto, test_sign_and_verify_success)
{
	uint8_t plain[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	uint8_t buf[LS_FRAME_SIZE(sizeof(plain))];
	struct ls_frame frame;

	build_frame(&frame, buf, sizeof(buf), 0x0001, LS_COORD_ADDR, 10,
		    plain, sizeof(plain));

	zassert_equal(ls_frame_sign(&frame, test_key), 0, "sign failed");
	zassert_equal(ls_frame_check_signature(&frame, test_key), 0, "verify failed");
}

ZTEST(lora_star_crypto, test_verify_wrong_key_fails)
{
	uint8_t plain[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	uint8_t buf[LS_FRAME_SIZE(sizeof(plain))];
	struct ls_frame frame;

	build_frame(&frame, buf, sizeof(buf), 0x0001, LS_COORD_ADDR, 10,
		    plain, sizeof(plain));

	zassert_equal(ls_frame_sign(&frame, test_key), 0);
	zassert_not_equal(ls_frame_check_signature(&frame, alt_key), 0,
			  "wrong key must fail verification");
}

ZTEST(lora_star_crypto, test_verify_tampered_payload_fails)
{
	uint8_t plain[8] = {0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4};
	uint8_t buf[LS_FRAME_SIZE(sizeof(plain))];
	struct ls_frame frame;
	uint8_t *payload;
	size_t payload_len;

	build_frame(&frame, buf, sizeof(buf), 0x0001, LS_COORD_ADDR, 7,
		    plain, sizeof(plain));
	zassert_equal(ls_frame_sign(&frame, test_key), 0);

	ls_frame_get_payload(&frame, &payload, &payload_len);
	payload[0] ^= 0xFF;

	zassert_not_equal(ls_frame_check_signature(&frame, test_key), 0,
			  "tampered payload must fail verification");
}

ZTEST(lora_star_crypto, test_verify_tampered_mic_fails)
{
	uint8_t plain[8] = {0xCA, 0xFE, 0xBA, 0xBE, 5, 6, 7, 8};
	uint8_t buf[LS_FRAME_SIZE(sizeof(plain))];
	struct ls_frame frame;
	uint8_t mic[LS_MIC_SIZE];

	build_frame(&frame, buf, sizeof(buf), 0x0001, LS_COORD_ADDR, 3,
		    plain, sizeof(plain));
	zassert_equal(ls_frame_sign(&frame, test_key), 0);

	ls_frame_get_mic(&frame, mic);
	mic[0] ^= 0x01;
	ls_frame_set_mic(&frame, mic);

	zassert_not_equal(ls_frame_check_signature(&frame, test_key), 0,
			  "tampered MIC must fail verification");
}

ZTEST(lora_star_crypto, test_mic_is_nonzero)
{
	uint8_t plain[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	uint8_t buf[LS_FRAME_SIZE(sizeof(plain))];
	uint8_t zeros[LS_MIC_SIZE] = {0};
	uint8_t mic[LS_MIC_SIZE];
	struct ls_frame frame;

	build_frame(&frame, buf, sizeof(buf), 0x0001, LS_COORD_ADDR, 1,
		    plain, sizeof(plain));
	zassert_equal(ls_frame_sign(&frame, test_key), 0);

	ls_frame_get_mic(&frame, mic);
	zassert_false(memcmp(mic, zeros, LS_MIC_SIZE) == 0, "MIC must not be all zeros");
}

ZTEST(lora_star_crypto, test_mic_is_deterministic)
{
	uint8_t plain[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	uint8_t buf_a[LS_FRAME_SIZE(sizeof(plain))];
	uint8_t buf_b[LS_FRAME_SIZE(sizeof(plain))];
	uint8_t mic_a[LS_MIC_SIZE];
	uint8_t mic_b[LS_MIC_SIZE];
	struct ls_frame frame_a, frame_b;

	build_frame(&frame_a, buf_a, sizeof(buf_a), 0x0001, LS_COORD_ADDR, 10,
		    plain, sizeof(plain));
	build_frame(&frame_b, buf_b, sizeof(buf_b), 0x0001, LS_COORD_ADDR, 10,
		    plain, sizeof(plain));

	zassert_equal(ls_frame_sign(&frame_a, test_key), 0);
	zassert_equal(ls_frame_sign(&frame_b, test_key), 0);

	ls_frame_get_mic(&frame_a, mic_a);
	ls_frame_get_mic(&frame_b, mic_b);

	zassert_mem_equal(mic_a, mic_b, LS_MIC_SIZE, "same inputs must yield the same MIC");
}

ZTEST(lora_star_crypto, test_mic_differs_by_payload)
{
	uint8_t plain_a[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	uint8_t plain_b[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89};
	uint8_t buf_a[LS_FRAME_SIZE(sizeof(plain_a))];
	uint8_t buf_b[LS_FRAME_SIZE(sizeof(plain_b))];
	uint8_t mic_a[LS_MIC_SIZE];
	uint8_t mic_b[LS_MIC_SIZE];
	struct ls_frame frame_a, frame_b;

	build_frame(&frame_a, buf_a, sizeof(buf_a), 0x0001, LS_COORD_ADDR, 1,
		    plain_a, sizeof(plain_a));
	build_frame(&frame_b, buf_b, sizeof(buf_b), 0x0001, LS_COORD_ADDR, 1,
		    plain_b, sizeof(plain_b));

	zassert_equal(ls_frame_sign(&frame_a, test_key), 0);
	zassert_equal(ls_frame_sign(&frame_b, test_key), 0);

	ls_frame_get_mic(&frame_a, mic_a);
	ls_frame_get_mic(&frame_b, mic_b);

	zassert_false(memcmp(mic_a, mic_b, LS_MIC_SIZE) == 0,
		      "different payloads must produce different MICs");
}

ZTEST(lora_star_crypto, test_sign_zero_payload_frame)
{
	uint8_t buf[LS_FRAME_SIZE(0)];
	struct ls_frame frame;

	build_frame(&frame, buf, sizeof(buf), LS_COORD_ADDR, 0x0001, 5, NULL, 0);

	zassert_equal(ls_frame_sign(&frame, test_key), 0, "sign with empty payload failed");
	zassert_equal(ls_frame_check_signature(&frame, test_key), 0,
		      "verify with empty payload failed");
}

/* --------------------------------------------------------------------------
 * End-to-end: encrypt-then-sign / verify-then-decrypt
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_crypto, test_encrypt_then_sign_verify_then_decrypt)
{
	uint8_t plain[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
	uint8_t buf[LS_FRAME_SIZE(sizeof(plain))];
	struct ls_frame frame;
	uint8_t *payload;
	size_t payload_len;

	build_frame(&frame, buf, sizeof(buf), 0x0001, LS_COORD_ADDR, 100,
		    plain, sizeof(plain));

	/* Sender side: encrypt then MAC. */
	zassert_equal(ls_frame_encrypt(&frame, test_key), 0, "encrypt failed");
	zassert_equal(ls_frame_sign(&frame, test_key), 0, "sign failed");

	/* Receiver side: verify then decrypt. */
	zassert_equal(ls_frame_check_signature(&frame, test_key), 0, "verify failed");
	zassert_equal(ls_frame_decrypt(&frame, test_key), 0, "decrypt failed");

	ls_frame_get_payload(&frame, &payload, &payload_len);
	zassert_equal(payload_len, sizeof(plain));
	zassert_mem_equal(payload, plain, sizeof(plain), "plaintext mismatch after full roundtrip");
}

ZTEST(lora_star_crypto, test_e2e_tampered_payload_fails_verify)
{
	uint8_t plain[8] = {0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF};
	uint8_t buf[LS_FRAME_SIZE(sizeof(plain))];
	struct ls_frame frame;
	uint8_t *payload;
	size_t payload_len;

	build_frame(&frame, buf, sizeof(buf), 0x0001, LS_COORD_ADDR, 50,
		    plain, sizeof(plain));

	zassert_equal(ls_frame_encrypt(&frame, test_key), 0);
	zassert_equal(ls_frame_sign(&frame, test_key), 0);

	/* Simulate a bit-flip in transit. */
	ls_frame_get_payload(&frame, &payload, &payload_len);
	payload[3] ^= 0x80;

	zassert_not_equal(ls_frame_check_signature(&frame, test_key), 0,
			  "corrupted frame must fail signature check");
}

ZTEST_SUITE(lora_star_crypto, NULL, NULL, NULL, NULL, NULL);
