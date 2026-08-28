/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LORA_STAR_MAC_H
#define LORA_STAR_MAC_H

#include <lora_star/lora_star.h>

/**
 * @brief Initialise the MAC layer.
 *
 * Initialises the radio for transmission via @ref ls_radio_init(). Call
 * once, after @ref ls_init(), before any send or receive operation.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on failure.
 */
int ls_mac_init(struct ls_ctx *ctx);

/**
 * @brief Transmit a frame.
 *
 * Behaviour depends on frame type:
 *
 * - DATA / ACK: stamps FCNT from @p ctx->fcnt (pre-increment, so the first
 *   value sent is 1), encrypts the payload with AES-128-CTR, then
 *   authenticates the frame with AES-CMAC.  Uses @p key when non-NULL,
 *   otherwise falls back to @p ctx->network_key.
 *
 * - JOIN_ACCEPT: stamps FCNT from @p ctx->fcnt (pre-increment), then signs
 *   the frame with AES-CMAC using @p key.  No payload encryption.
 *
 * - JOIN_REQ: leaves FCNT unchanged (caller sets it to 0), then signs the
 *   frame with AES-CMAC using @p key.  No payload encryption.
 *
 * The SRC field is never modified; the caller must set it before this call.
 * When @p ctx->always_on_rx is true, async RX is stopped before transmission
 * and resumed immediately after.
 *
 * @param ctx   LoRa Star context.
 * @param frame Frame to transmit.  Modified in place (FCNT, crypto).
 * @param key   Signing/encryption key.  NULL uses @p ctx->network_key (valid
 *              only for DATA and ACK).  Must be non-NULL for JOIN frames.
 * @return 0 on success, negative errno on failure.
 */
int ls_mac_send(struct ls_ctx *ctx, struct ls_frame *frame, const uint8_t *key);

/**
 * @brief Start asynchronous frame reception.
 *
 * Configures the radio for async RX.  Each received frame is validated: DATA
 * and ACK frames have their MIC verified (frames with an invalid MIC are
 * silently dropped) and their payload decrypted before being pushed into
 * @p ctx->_msgq.  JOIN_REQ and JOIN_ACCEPT frames are pushed as-is.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on failure.
 */
int ls_mac_recv(struct ls_ctx *ctx);

/**
 * @brief Stop asynchronous frame reception.
 *
 * Cancels any pending async RX.  Safe to call when RX is not running.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on failure.
 */
int ls_mac_rx_stop(struct ls_ctx *ctx);

/**
 * @brief Compute on-air time for a frame of the given length.
 *
 * @param ctx        LoRa Star context.
 * @param frame_len  Total frame length in bytes.
 * @return Time on air in milliseconds, rounded up.
 */
uint32_t ls_mac_airtime_ms(struct ls_ctx *ctx, size_t frame_len);

#endif /* LORA_STAR_MAC_H */
