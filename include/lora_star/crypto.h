/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LORA_STAR_LS_CRYPTO_H
#define LORA_STAR_LS_CRYPTO_H

#include <lora_star/frame.h>

#define LS_NETWORK_KEY_SIZE 16U
/** AES-128 block size; CTR mode requires a full-block IV. */
#define LS_CTR_NONCE_SIZE   16U

int ls_crypto_ctr(uint8_t *buf, size_t len, const uint8_t key[LS_NETWORK_KEY_SIZE],
		  const uint8_t nonce[LS_CTR_NONCE_SIZE], int encrypt);

/**
 * @brief Encrypt the frame payload in-place using AES-128-CTR.
 *
 * The CTR nonce is derived deterministically as FCNT (4B LE) || SRC (2B LE) || 0x00…(10B).
 * The nonce does not need to be secret; it only needs to be unique per (key, frame),
 * which is guaranteed by FCNT monotonicity.  Must be called before ls_frame_sign()
 * to honour encrypt-then-MAC ordering.
 * @param frame Pointer to the frame.
 * @param key   16-byte session key.
 * @return 0 or a negative number in case of error.
 */
int ls_frame_encrypt(struct ls_frame *frame, const uint8_t key[LS_NETWORK_KEY_SIZE]);

/**
 * @brief Decrypt the frame payload in-place using AES-128-CTR.
 *
 * The CTR nonce is derived deterministically as FCNT (4B LE) || SRC (2B LE) || 0x00…(10B).
 * Must be called after ls_frame_check_signature() passes (verify-then-decrypt).
 * @param frame Pointer to the frame.
 * @param key   16-byte session key.
 * @return 0 or a negative number in case of error.
 */
int ls_frame_decrypt(struct ls_frame *frame, const uint8_t key[LS_NETWORK_KEY_SIZE]);

/**
 * @brief Compute and add MIC to the frame.
 * @param frame Pointer to the frame.
 * @param key   16-byte session key.
 * @return 0 or a negative number in case of error.
 */
int ls_frame_sign(struct ls_frame *frame, const uint8_t key[LS_NETWORK_KEY_SIZE]);

/**
 * @brief Compute the MIC and test it against the one in the frame.
 * @param frame Pointer to the frame.
 * @param key   16-byte session key.
 * @return 0 if frame MIC is valid or a negative number in case of error.
 */
int ls_frame_check_signature(struct ls_frame *frame, const uint8_t key[LS_NETWORK_KEY_SIZE]);

#endif /* LORA_STAR_LS_CRYPTO_H */
