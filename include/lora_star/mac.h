/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LORA_STAR_MAC_H
#define LORA_STAR_MAC_H

#include <lora_star/lora_star.h>

int ls_mac_init(struct ls_ctx *ctx);

/**
 * @brief Transmit a frame.
 *
 * Stamps @p frame with SRC from @p ctx->own_addr and FCNT from @p ctx->fcnt
 * (which is incremented after stamping).  DATA and ACK frames are encrypted
 * then signed with @p ctx->session_key before transmission.  JOIN_REQ and
 * JOIN_ACCEPT frames are transmitted as-is.  When @p ctx->always_on_rx is
 * true, async RX is stopped before transmission and resumed immediately after.
 *
 * @param ctx   LoRa Star context.
 * @param frame Frame to transmit.  Header fields and payload are modified in place.
 * @return 0 on success, negative errno on failure.
 */
int ls_mac_send(struct ls_ctx *ctx, struct ls_frame *frame);

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
