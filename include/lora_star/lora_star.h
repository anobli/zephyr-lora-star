/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LORA_STAR_H
#define LORA_STAR_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <lora_star/frame.h>
#include <lora_star/crypto.h>

/** Device EUI length in bytes (EUI-64). */
#define LS_DEV_EUI_SIZE 8U

struct ls_ctx;

/**
 * @brief Filter criteria for a registered frame callback.
 *
 * Each field acts as a wildcard when set to 0 (type) or @ref LS_BCAST_ADDR
 * (src, dst), matching any value in that position.
 */
struct ls_frame_filter {
	/** Frame type to match, or 0 to match any type. */
	uint8_t  type;
	/** Source address to match, or @ref LS_BCAST_ADDR to match any source. */
	uint16_t src;
	/** Destination address to match, or @ref LS_BCAST_ADDR to match any destination. */
	uint16_t dst;
};

/**
 * @brief Frame receive callback type.
 *
 * Invoked from the LoRa Star thread when a received frame matches a registered
 * filter.  The callback must not block for long.
 *
 * @param ctx        LoRa Star context.
 * @param frame      Received frame.  Valid only for the duration of the call.
 * @param user_data  Opaque pointer supplied at registration time.
 * @return 0 to continue dispatching to other matching handlers,
 *         negative to stop dispatching this frame.
 */
typedef int (*ls_frame_cb)(struct ls_ctx *ctx, struct ls_frame *frame,
			   void *user_data);

/**
 * @brief One entry in the frame handler registry.
 *
 * @note Internal — use @ref ls_register_frame_cb() to register handlers.
 */
struct ls_frame_handler {
	/** Filter that selects which frames trigger this handler. */
	struct ls_frame_filter filter;
	/** Callback to invoke on a matching frame. */
	ls_frame_cb            cb;
	/** Opaque pointer forwarded to @p cb. */
	void                  *user_data;
};

/**
 * @brief LoRa Star protocol context.
 *
 * Holds the radio device, addressing state, session key, RX frame queue, and
 * the frame handler registry.  Obtain a pointer via @ref ls_init(); do not
 * allocate or copy this struct directly.
 *
 * @note Fields prefixed with @c _ are internal; access them only through the
 *       public API.
 */
struct ls_ctx {
	/** LoRa radio device used for all TX and RX operations. */
	const struct device *radio_dev;

	/** Own short address stamped as SRC on every transmitted frame. */
	uint16_t own_addr;

	bool addr_found;

	/** Monotonic TX frame counter, stamped as FCNT on every transmitted frame. */
	uint32_t fcnt;

	/** Network key used by the MAC layer to encrypt and sign DATA and ACK frames. */
	uint8_t network_key[LS_NETWORK_KEY_SIZE];
	bool network_key_found;

	/**
	 * Keep the radio in continuous receive mode.
	 *
	 * When true, @ref ls_mac_send() stops RX before every transmission and
	 * restarts it immediately after.  Set by the coordinator role during
	 * @ref ls_pairing_coord_init(); leave false for nodes that manage their own
	 * RX windows via @ref ls_send_data_ack().
	 */
	bool always_on_rx;

	/** @cond INTERNAL */
	struct k_msgq  _msgq;
	uint8_t        _msgq_buf[CONFIG_LORA_STAR_MSGQ_DEPTH * sizeof(struct ls_frame)];
	struct ls_frame_handler _handlers[CONFIG_LORA_STAR_MAX_FRAME_CBS];
	struct k_mutex          _handlers_lock;
	/** @endcond */
};

/**
 * @brief Initialise the LoRa Star stack.
 *
 * Configures the radio, initialises the RX queue, and starts the protocol
 * thread.  Attempts to restore a previously persisted node session from
 * Settings; if found, @ref ls_is_paired() returns true immediately.  When
 * async RX is not started here; call @ref ls_mac_recv() when you are ready to receive.
 *
 * @param lora_dev  LoRa radio device (e.g. @c DEVICE_DT_GET(DT_ALIAS(lora0))).
 * @return Pointer to the static @ref ls_ctx instance, or NULL on failure.
 */
struct ls_ctx *ls_init(const struct device *lora_dev);

#ifdef CONFIG_LORA_STAR_COORDINATOR

/**
 * @brief Per-node record persisted by the coordinator.
 *
 * Stored in Settings under @c ls/coord/node/<addr> and mirrored in the
 * in-RAM node table.  The MAC layer uses @c fcnt_last for replay protection
 * on every received uplink.
 */
struct ls_node_record {
	/** Device EUI — uniquely identifies the node across pairing sessions. */
	uint8_t  dev_eui[LS_DEV_EUI_SIZE];
	/** Last accepted frame counter; updated on every valid uplink. */
	uint32_t fcnt_last;
} __packed;

/**
 * @brief Entry in the coordinator's in-RAM node table.
 */
struct coord_node {
	/** Slot is occupied. */
	bool                  active;
	/** Assigned short address. */
	uint16_t              short_addr;
	/** Persistent record: DevEUI and last-seen FCNT. */
	struct ls_node_record rec;
};

int ls_init_coord(struct ls_ctx *ctx);
#endif

#ifdef CONFIG_LORA_STAR_NODE
int ls_init_node(struct ls_ctx *ctx);
#endif

/**
 * @brief Check whether the device has an active session.
 *
 * Returns true if both the session key is non-zero and the device has been
 * assigned a node short address (i.e. it is not the coordinator address).
 * This covers both the post-pairing case and the boot-from-storage case.
 *
 * @param ctx  LoRa Star context.
 * @return true if paired, false otherwise.
 */
bool ls_is_paired(const struct ls_ctx *ctx);
bool ls_is_network_key_set(const struct ls_ctx *ctx);
/**
 * @brief Set the network key.
 *
 * Called by the pairing application after the network key has been received and
 * decrypted from the JOIN_ACCEPT.  The key is subsequently used by the MAC layer
 * to encrypt and sign DATA and ACK frames.
 *
 * @param ctx  LoRa Star context.
 * @param key  16-byte network key.
 */
void ls_set_network_key(struct ls_ctx *ctx, const uint8_t key[LS_NETWORK_KEY_SIZE]);

/**
 * @brief Set the device's own short address.
 *
 * Called by the pairing application on the node side after a successful
 * JOIN_ACCEPT.  The address is stamped as SRC on all subsequent transmitted
 * frames.
 *
 * @param ctx   LoRa Star context.
 * @param addr  Short address to assign (use @ref LS_COORD_ADDR for coordinator).
 */
void ls_set_own_addr(struct ls_ctx *ctx, uint16_t addr);

/**
 * @brief Register a frame receive callback with a filter.
 *
 * The callback is invoked from the LoRa Star thread whenever a received frame
 * matches all non-wildcard fields in @p filter.  Up to
 * @c CONFIG_LORA_STAR_MAX_FRAME_CBS handlers may be registered simultaneously.
 *
 * @param ctx        LoRa Star context.
 * @param filter     Match criteria; zero or @ref LS_BCAST_ADDR fields act as wildcards.
 * @param cb         Callback to invoke on a matching frame.
 * @param user_data  Opaque pointer forwarded to @p cb.
 * @return Pointer to the registered handler on success, NULL if the registry is full.
 *         Pass this pointer to @ref ls_unregister_frame_cb() to remove the handler.
 */
struct ls_frame_handler *ls_register_frame_cb(struct ls_ctx *ctx,
					      const struct ls_frame_filter *filter,
					      ls_frame_cb cb, void *user_data);

/**
 * @brief Convenience wrapper to register a DATA frame callback.
 *
 * Equivalent to @ref ls_register_frame_cb() with a filter of type
 * @ref LS_TYPE_DATA, any source, and the given destination.  Pass
 * @ref LS_BCAST_ADDR as @p dst to receive DATA frames addressed to any node
 * (useful on the coordinator).
 *
 * @param ctx        LoRa Star context.
 * @param dst        Destination address to match, or @ref LS_BCAST_ADDR for any.
 * @param cb         Callback to invoke on a matching frame.
 * @param user_data  Opaque pointer forwarded to @p cb.
 * @return Pointer to the registered handler on success, NULL if the registry is full.
 */
struct ls_frame_handler *ls_register_data_cb(struct ls_ctx *ctx, uint16_t dst,
					     ls_frame_cb cb, void *user_data);

/**
 * @brief Unregister a frame callback.
 *
 * Removes the handler previously returned by @ref ls_register_frame_cb().
 * Passing a NULL or already-removed handler is safe and has no effect.
 *
 * @param ctx      LoRa Star context.
 * @param handler  Pointer returned by @ref ls_register_frame_cb().
 */
void ls_unregister_frame_cb(struct ls_ctx *ctx, struct ls_frame_handler *handler);

/**
 * @brief Send an ACK frame to the given destination.
 *
 * Used by the coordinator (or a peer) to acknowledge a DATA frame that was
 * sent with @ref LS_FLAG_ACK_REQ.  The MAC layer stamps SRC and FCNT and
 * authenticates the frame with AES-CMAC.
 *
 * @param ctx  LoRa Star context.
 * @param dst  Destination short address (usually the node that sent the DATA).
 * @return 0 on success, negative errno on failure.
 */
int ls_send_ack(struct ls_ctx *ctx, uint16_t dst);

/**
 * @brief Send a DATA frame without waiting for an acknowledgement.
 *
 * Blocking: returns once the frame has been transmitted.  The MAC layer stamps
 * SRC and FCNT, encrypts the payload with AES-CTR, and appends a CMAC MIC.
 *
 * @warning Blocks for the full radio transmission time (tens to hundreds of
 * milliseconds).  Do not call from the system workqueue, a k_work handler, or
 * an ISR.  Use @ref ls_send_data_async() instead.
 *
 * @param ctx   LoRa Star context.
 * @param dst   Destination short address.
 * @param data  Application payload buffer.
 * @param len   Payload length in bytes.
 * @return 0 on success, negative errno on failure.
 */
int ls_send_data(struct ls_ctx *ctx, uint16_t dst, const uint8_t *data, size_t len);

/**
 * @brief Send a DATA frame and wait for an ACK.
 *
 * Blocking: opens an RX window after each attempt and waits for an ACK.
 * The window duration is computed from the on-air time of the DATA frame,
 * the on-air time of the expected ACK, and @c CONFIG_LORA_STAR_ACK_GUARD_MS.
 * Retries up to @c CONFIG_LORA_STAR_TX_MAX_RETRIES times with
 * @c CONFIG_LORA_STAR_TX_RETRY_BACKOFF_MS base backoff plus random jitter.
 *
 * @warning Can block for multiple seconds across retries.  Do not call from
 * the system workqueue, a k_work handler, or an ISR.  Use
 * @ref ls_send_data_ack_async() instead.
 *
 * @param ctx   LoRa Star context.
 * @param dst   Destination short address.
 * @param data  Application payload buffer.
 * @param len   Payload length in bytes.
 * @return 0 on ACK received, -ETIMEDOUT if all retries are exhausted,
 *         negative errno on other failures.
 */
int ls_send_data_ack(struct ls_ctx *ctx, uint16_t dst, const uint8_t *data, size_t len);

/**
 * @brief Completion callback type for async send operations.
 *
 * Invoked from the LoRa Star TX thread once the send has completed (or
 * failed).  The callback must not block for long.
 *
 * @param ret        0 on success, negative errno on failure, or -ETIMEDOUT
 *                   when @ref ls_send_data_ack_async() exhausts all retries.
 * @param user_data  Opaque pointer supplied at registration time.
 */
typedef void (*ls_send_cb)(int ret, void *user_data);

/**
 * @brief Send a DATA frame without waiting for an acknowledgement (async).
 *
 * Copies @p data into an internal TX queue and returns immediately.
 * @p done_cb is invoked from the TX thread once the frame has been
 * transmitted (or on failure).
 *
 * Safe to call from any context including ISRs, GPIO callbacks, and the
 * system workqueue.
 *
 * @param ctx        LoRa Star context.
 * @param dst        Destination short address.
 * @param data       Application payload buffer, or NULL when @p len is 0.
 * @param len        Payload length in bytes (0 to @ref LS_MAX_PAYLOAD_SIZE).
 * @param done_cb    Completion callback, or NULL.
 * @param user_data  Opaque pointer forwarded to @p done_cb.
 * @return 0 on success, -ENOMEM if the TX queue is full,
 *         -EINVAL on invalid arguments.
 */
int ls_send_data_async(struct ls_ctx *ctx,
		       uint16_t dst, const uint8_t *data, size_t len,
		       ls_send_cb done_cb, void *user_data);

/**
 * @brief Send a DATA frame and wait for an ACK (async).
 *
 * Copies @p data into an internal TX queue and returns immediately.
 * @p done_cb is invoked from the TX thread with the result (0 on ACK,
 * -ETIMEDOUT after all retries, negative errno on other failures).
 *
 * Safe to call from any context including ISRs, GPIO callbacks, and the
 * system workqueue.
 *
 * @param ctx        LoRa Star context.
 * @param dst        Destination short address.
 * @param data       Application payload buffer, or NULL when @p len is 0.
 * @param len        Payload length in bytes (0 to @ref LS_MAX_PAYLOAD_SIZE).
 * @param done_cb    Completion callback, or NULL.
 * @param user_data  Opaque pointer forwarded to @p done_cb.
 * @return 0 on success, -ENOMEM if the TX queue is full,
 *         -EINVAL on invalid arguments.
 */
int ls_send_data_ack_async(struct ls_ctx *ctx,
			   uint16_t dst, const uint8_t *data, size_t len,
			   ls_send_cb done_cb, void *user_data);

#endif /* LORA_STAR_H */
