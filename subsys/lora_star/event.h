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
 * by the backoff timer when it is time to re-send.  The other two originate
 * from the application or the MAC receive path.
 */
enum ls_event_type {
	/** Frame received from the radio and verified by the MAC layer. */
	LS_EVENT_RX,
	/** Request to transmit a pre-built frame. */
	LS_EVENT_TX,
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
		/** LS_EVENT_RX: received frame. */
		struct ls_frame rx;

		/** LS_EVENT_TX: transmit a frame. */
		struct {
			/** Pre-built frame; FCNT and MIC are stamped by the MAC at send time. */
			struct ls_frame  frame;
			/** Signing/encryption key, pre-resolved at enqueue time. */
			uint8_t          key[LS_NETWORK_KEY_SIZE];
			/** When true, arm the retry timer and wait for a response. */
			bool             want_resp;
			/** Frame type of the expected response (LS_TYPE_*). */
			uint8_t          resp_type;
			/**
			 * Source address of the expected response.
			 * Use LS_BCAST_ADDR to match any source.
			 */
			uint16_t         resp_src;
			/**
			 * Response window in milliseconds.  A value of 0 falls
			 * back to the default ACK timeout computation.
			 */
			uint32_t         timeout_ms;
			ls_send_cb       done_cb;
			void            *user_data;
		} tx;
	};
};

#endif /* LORA_STAR_EVENT_H */
