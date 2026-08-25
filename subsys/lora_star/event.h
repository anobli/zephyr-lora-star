/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LORA_STAR_EVENT_H
#define LORA_STAR_EVENT_H

#include <lora_star/lora_star.h>
#include <lora_star/frame.h>

/**
 * @brief Discriminant for unified protocol events.
 *
 * All protocol events flow through the same queue.  LS_EVENT_TIMEOUT is
 * posted by the ACK timer on response-window expiry; LS_EVENT_RETRY is posted
 * by the backoff timer when it is time to re-send.  The other three originate
 * from the application or the MAC receive path.
 */
enum ls_event_type {
	/** Frame received from the radio and verified by the MAC layer. */
	LS_EVENT_RX,
	/** Request to transmit a DATA frame (payload copied into the event). */
	LS_EVENT_TX_DATA,
	/**
	 * Request to transmit a pre-built, pre-signed frame verbatim.
	 * Used by the pairing layer for JOIN_REQ / JOIN_ACCEPT frames that
	 * require pairing-specific crypto the MAC layer does not know about.
	 */
	LS_EVENT_TX_RAW,
	/** ACK timer expired; decrement retry count or report timeout. */
	LS_EVENT_TIMEOUT,
	/** Backoff timer expired; re-transmit the saved frame. */
	LS_EVENT_RETRY,
};

/**
 * @brief Unified protocol event enqueued between MAC and application layers.
 *
 * The @p type field selects which union member is valid.
 */
struct ls_event {
	enum ls_event_type type;
	union {
		/** LS_EVENT_RX: received frame.  The heap-allocated @c buf is
		 *  owned by the event; the thread must call ls_frame_free_buf(). */
		struct ls_frame rx;

		/** LS_EVENT_TX_DATA: build and transmit a DATA frame. */
		struct {
			uint8_t    payload[LS_MAX_PAYLOAD_SIZE];
			size_t     payload_len;
			uint16_t   dst;
			uint8_t    flags;
			bool       want_ack;
			ls_send_cb done_cb;
			void      *user_data;
		} tx_data;

		/** LS_EVENT_TX_RAW: transmit a pre-built frame verbatim. */
		struct {
			uint8_t    buf[LS_MAX_FRAME_SIZE];
			size_t     buf_len;
			/** When true, arm the retry timer and wait for a response. */
			bool       want_resp;
			/** Frame type of the expected response (LS_TYPE_*). */
			uint8_t    resp_type;
			/**
			 * Source address of the expected response.
			 * Use LS_BCAST_ADDR to match any source.
			 */
			uint16_t   resp_src;
			/**
			 * Response window in milliseconds.  A value of 0 falls
			 * back to the default ACK timeout computation.
			 */
			uint32_t   timeout_ms;
			ls_send_cb done_cb;
			void      *user_data;
		} tx_raw;
	};
};

/**
 * @brief Transmit a pre-built frame and optionally wait for a typed response.
 *
 * Copies @p len bytes from @p buf into a @ref LS_EVENT_TX_RAW event and
 * enqueues it for the LoRa Star thread.  If @p want_resp is true the thread
 * arms a retry timer and waits for a frame of @p resp_type from @p resp_src
 * before calling @p done_cb.  Retries up to
 * @c CONFIG_LORA_STAR_TX_MAX_RETRIES times on timeout.
 *
 * @note This is an internal API used by the pairing layer.
 *
 * @param ctx        LoRa Star context.
 * @param buf        Pre-built frame bytes.
 * @param len        Total frame length in bytes.
 * @param want_resp  Wait for a response frame after sending.
 * @param resp_type  Expected response frame type (ignored when !want_resp).
 * @param resp_src   Expected response source address (ignored when !want_resp).
 * @param timeout_ms Response window; 0 uses the default ACK timeout.
 * @param done_cb    Completion callback; 0 on response received, -ETIMEDOUT
 *                   if retries exhausted, negative errno on hard failure.
 * @param user_data  Forwarded to @p done_cb.
 * @return 0 on success, -ENOMEM if the queue is full, -EINVAL on bad args.
 */
int ls_send_raw_async(struct ls_ctx *ctx,
		      const uint8_t *buf, size_t len,
		      bool want_resp, uint8_t resp_type, uint16_t resp_src,
		      uint32_t timeout_ms,
		      ls_send_cb done_cb, void *user_data);

#endif /* LORA_STAR_EVENT_H */
