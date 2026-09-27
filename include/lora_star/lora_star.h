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

	/**
	 * Monotonic TX frame counter, stamped as FCNT on every transmitted frame.
	 *
	 * Session-scoped RAM state, not persisted: reset to 0 every time the
	 * rejoin handshake (see lora_star/rejoin.h) establishes a fresh session
	 * key.  Replay protection comes from the session key being new each
	 * time, not from FCNT surviving a reboot.
	 */
	uint32_t fcnt;

	/**
	 * Long-term network key, persisted to Settings.
	 *
	 * Delivered to a node via pairing (@ref ls_set_network_key()) or a
	 * fixed compile-time value.  Used only to bootstrap the rejoin
	 * handshake (signing REJOIN_REQ, deriving the session key) — actual
	 * DATA/ACK traffic is protected by the derived @c _session_key instead.
	 */
	uint8_t network_key[LS_NETWORK_KEY_SIZE];
	bool network_key_found;

	/**
	 * Keep the radio in continuous receive mode.
	 *
	 * When true, @ref ls_mac_send() stops RX before every transmission and
	 * restarts it immediately after.  Set by the coordinator role during
	 * @ref ls_init_coord(); leave false for nodes that manage their own
	 * RX windows via @ref ls_send_data_ack().
	 */
	bool always_on_rx;

	/** @cond INTERNAL */
	struct k_msgq          *_msgq;
	struct ls_frame_handler _handlers[CONFIG_LORA_STAR_MAX_FRAME_CBS];
	struct k_mutex          _handlers_lock;
	uint8_t                 _session_key[LS_NETWORK_KEY_SIZE];
	uint32_t                _session_rx_fcnt;
	bool                    _session_active;
	/** @endcond */
};

/**
 * @brief Initialise the LoRa Star stack.
 *
 * Configures the radio, initialises the RX queue, and starts the protocol
 * thread.  Attempts to restore a previously persisted node identity (network
 * key + short address) from Settings; if found, @ref ls_is_paired() returns
 * true immediately and (on @c CONFIG_LORA_STAR_NODE builds) the rejoin
 * handshake is started automatically to establish a fresh session — see
 * lora_star/rejoin.h.  Async RX is not started here; call @ref ls_mac_recv()
 * when you are ready to receive.
 *
 * @param lora_dev  LoRa radio device (e.g. @c DEVICE_DT_GET(DT_ALIAS(lora0))).
 * @return Pointer to the static @ref ls_ctx instance, or NULL on failure.
 */
struct ls_ctx *ls_init(const struct device *lora_dev);

/**
 * @brief Get the LoRa Star protocol context.
 *
 * @return Pointer to the static @ref ls_ctx instance, initialised by @ref ls_init().
 */
struct ls_ctx *ls_get_ctx(void);

#ifdef CONFIG_LORA_STAR_COORDINATOR

struct ls_coord_ctx;

/**
 * @brief Per-node record persisted by the coordinator.
 *
 * Stored in Settings under @c ls/coord/node/<addr> and mirrored in the
 * in-RAM node table.  Only long-lived identity lives here — the anti-replay
 * checkpoint and session key are RAM-only (see @ref coord_node) and reset on
 * every rejoin, so they are deliberately not part of this persisted record.
 * Populated either by pairing (@ref ls_pairing_coord_init()) or directly via
 * @c ls_coord_add_node() for nodes provisioned out of band.
 */
struct ls_node_record {
	/** Device EUI — uniquely identifies the node across pairing sessions. */
	uint8_t dev_eui[LS_DEV_EUI_SIZE];
} __packed;

/**
 * @brief Entry in the coordinator's in-RAM node table.
 *
 * @c session_key, @c session_fcnt_last, and @c session_active are installed
 * by @c ls_coord_set_session() when a node completes the rejoin handshake
 * (see lora_star/rejoin.h) and are never persisted — they exist only for as
 * long as the coordinator stays up and the node's session remains fresh.
 */
struct coord_node {
	/** Slot is occupied. */
	bool                  active;
	/** Assigned short address. */
	uint16_t              short_addr;
	/** Persistent record: DevEUI. */
	struct ls_node_record rec;
	/** Current session key, valid only while @c session_active is true. */
	uint8_t               session_key[LS_NETWORK_KEY_SIZE];
	/** Anti-replay checkpoint for the current session; reset to 0 on rejoin. */
	uint32_t              session_fcnt_last;
	/** True once this node has completed the rejoin handshake. */
	bool                  session_active;
	/**
	 * Uptime (ms) of the last SESSION_UNKNOWN notice sent to this node, or 0
	 * if none has been sent yet. RAM-only; rate-limits @ref ls_coord_notify_allowed()
	 * so a spoofed SRC cannot force repeated rejoin traffic from a real node.
	 */
	int64_t               last_notify_uptime;
};

/**
 * @brief Complete coordinator-role initialisation.
 *
 * Loads or generates the network key, sets @p ctx->own_addr to
 * @ref LS_COORD_ADDR, enables @p ctx->always_on_rx, starts async RX, and
 * initialises the node table (see @c ls_coord_init() in lora_star/coord.h)
 * — restoring it from Settings — and registers the always-on rejoin handler
 * (see lora_star/rejoin.h) so any node holding the network key can announce
 * itself and establish a session, independent of whether pairing is used.
 * Call once after @ref ls_init() to fully bring up the coordinator service;
 * the node table itself is owned internally and reachable via
 * @c ls_coord_get().
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on failure.
 */
int ls_init_coord(struct ls_ctx *ctx);
#endif

/**
 * @brief Check whether the device holds long-term network credentials.
 *
 * Returns true if both the network key is non-zero and the device has been
 * assigned a node short address (i.e. it is not the coordinator address).
 * This covers both the post-pairing case and the boot-from-storage case.
 * Does @b not mean the device currently has a working session — a freshly
 * booted node is paired immediately but only gets DATA/ACK connectivity once
 * the automatic rejoin handshake completes; see @ref ls_is_session_active().
 *
 * @param ctx  LoRa Star context.
 * @return true if paired, false otherwise.
 */
bool ls_is_paired(const struct ls_ctx *ctx);

/**
 * @brief Check whether the network key has been set.
 *
 * @param ctx  LoRa Star context.
 * @return true if @p ctx->network_key has been set, false otherwise.
 */
bool ls_is_network_key_set(const struct ls_ctx *ctx);

/**
 * @brief Check whether a working session is currently active.
 *
 * True once the rejoin handshake has installed a session key that DATA/ACK
 * traffic can actually use — @ref ls_send_data() and friends fail with
 * @c -ENOTCONN before this is true.  A node is paired (see @ref ls_is_paired())
 * before it necessarily has a session; the two are established separately.
 *
 * @param ctx  LoRa Star context.
 * @return true if a session key is currently installed, false otherwise.
 */
bool ls_is_session_active(const struct ls_ctx *ctx);

/**
 * @brief Set the network key.
 *
 * Called by the pairing application after the network key has been received
 * and decrypted from the JOIN_ACCEPT. The key is subsequently used to
 * bootstrap the rejoin handshake (see lora_star/rejoin.h) — not for DATA/ACK
 * traffic directly, which uses a session key derived during that handshake.
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

#ifdef CONFIG_LORA_STAR_COORDINATOR

/**
 * @brief Queue a downlink payload for a paired node.
 *
 * The payload is buffered and delivered on the next uplink ACK
 * (ACK_PENDING flag).  Only one pending downlink per node is kept;
 * a second call overwrites the first.
 *
 * @param ctx         Coordinator context.
 * @param short_addr  Destination node short address (0x0001–0xFFFE).
 * @param data        Payload buffer (max 114 bytes).
 * @param len         Payload length in bytes.
 * @return 0 on success, -ENOENT if address unknown, -EINVAL if len > 114.
 */
int ls_coord_send(struct ls_coord_ctx *ctx, uint16_t short_addr,
		  const uint8_t *data, uint8_t len);

/**
 * @brief Send a downlink to a paired node via an immediate coordinator DATA frame.
 *
 * Unlike ls_coord_send(), which buffers the payload for delivery on the next
 * node uplink ACK, this function marks the downlink for direct transmission.
 * The coordinator thread sends it within its next poll cycle (≤ 500 ms).
 *
 * Intended for nodes built with CONFIG_LORA_STAR_NODE_ALWAYS_RX=y that are
 * continuously listening. On duty-cycled nodes the frame may be missed if the
 * node is not in RX at the time of transmission.
 *
 * Only one pending direct downlink per node is kept; a second call overwrites
 * the first. Direct downlinks are never ACK-piggybacked; use ls_coord_send()
 * for that behaviour.
 *
 * @param ctx         Coordinator context.
 * @param short_addr  Destination node short address (0x0001–0xFFFE).
 * @param data        Payload buffer (max 114 bytes).
 * @param len         Payload length in bytes.
 * @return 0 on success, -ENOENT if address unknown, -EINVAL if len > 114.
 */
int ls_coord_send_direct(struct ls_coord_ctx *ctx, uint16_t short_addr,
			  const uint8_t *data, uint8_t len);

/**
 * @brief Callback invoked on each received uplink.
 *
 * Called from the protocol thread; must not block for long.
 *
 * @param ctx        Coordinator context.
 * @param short_addr Source node address.
 * @param data       Decrypted application payload.
 * @param len        Payload length.
 */
typedef void (*ls_coord_recv_cb)(struct ls_coord_ctx *ctx, uint16_t short_addr,
				 const uint8_t *data, uint8_t len);

/**
 * @brief Callback invoked when a new node completes pairing.
 *
 * @param ctx        Coordinator context.
 * @param short_addr Assigned short address.
 * @param dev_eui    Node DevEUI (8 bytes).
 */
typedef void (*ls_coord_join_cb)(struct ls_coord_ctx *ctx, uint16_t short_addr,
				 const uint8_t *dev_eui);

/** @brief Register the uplink receive callback. */
void ls_coord_set_recv_cb(struct ls_coord_ctx *ctx, ls_coord_recv_cb cb);

/** @brief Register the join (new node paired) callback. */
void ls_coord_set_join_cb(struct ls_coord_ctx *ctx, ls_coord_join_cb cb);

#endif /* CONFIG_LORA_STAR_COORDINATOR */

/* --------------------------------------------------------------------------
 * Node API
 * -------------------------------------------------------------------------- */

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
 * authenticates the frame with AES-CMAC using @p dst's current session key.
 *
 * @param ctx  LoRa Star context.
 * @param dst  Destination short address (usually the node that sent the DATA).
 * @return 0 on success, -ENOTCONN if @p dst has no active session,
 *         negative errno on other failures.
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
 * @brief Low-level async frame send.
 *
 * Builds a frame with the given parameters, enqueues it for the LoRa Star
 * thread, and invokes @p done_cb when the send has completed (or failed).
 * Safe to call from any context including ISRs and the system workqueue.
 *
 * Frame type determines MAC behaviour:
 *
 * - DATA / ACK: stamps FCNT from @p ctx->fcnt (pre-increment, so the first
 *   value sent is 1), AES-128-CTR encrypts the payload, then AES-CMAC signs
 *   the frame.  Pass NULL for @p key to sign/encrypt with @p dst's current
 *   session key, resolved automatically (the node's own session key when
 *   sending to the coordinator, or the addressed node's session key when
 *   the coordinator is sending) — fails with -ENOTCONN if no session is
 *   active yet for that peer.
 *
 * - JOIN_ACCEPT / REJOIN_ACCEPT: stamps FCNT from @p ctx->fcnt
 *   (pre-increment), then AES-CMAC signs the frame with @p key, which must
 *   be supplied explicitly (there is no destination session to resolve yet
 *   — that is what these frames are establishing).  No encryption.
 *
 * - JOIN_REQ / REJOIN_REQ: leaves FCNT at 0 (caller convention), then
 *   AES-CMAC signs the frame with @p key (also required explicitly).  No
 *   encryption.
 *
 * @p src, @p dst, and @p flags are written into the frame header verbatim.
 * Pass @p ctx->own_addr as @p src for DATA and ACK frames.
 *
 * @param ctx         LoRa Star context.
 * @param type        Frame type (LS_TYPE_DATA, LS_TYPE_ACK, etc.).
 * @param src         Source address to write into the frame header.
 * @param dst         Destination address.
 * @param flags       Frame flags byte (combination of LS_FLAG_* constants).
 * @param payload     Payload buffer, or NULL when @p payload_len is 0.
 * @param payload_len Payload length in bytes (0 to @ref LS_MAX_PAYLOAD_SIZE).
 * @param key         Signing/encryption key.  NULL resolves @p dst's session
 *                    key automatically (valid only for DATA and ACK); must
 *                    be non-NULL for JOIN/REJOIN frames.
 * @param want_resp   When true, arm the retry timer and wait for a response.
 * @param resp_type   Expected response frame type; ignored when !want_resp.
 * @param resp_src    Expected response source address (@ref LS_BCAST_ADDR matches any).
 * @param timeout_ms  Response window in ms; 0 auto-computes from airtime.
 * @param done_cb     Invoked on completion: 0 on success, -ETIMEDOUT when all
 *                    retries are exhausted, negative errno on hard failure.
 *                    May be NULL.
 * @param user_data   Forwarded to @p done_cb.
 * @return 0 if the event was enqueued, -ENOMEM if the TX queue is full,
 *         -ENOTCONN if @p key is NULL and @p dst has no active session,
 *         -EINVAL on invalid arguments.
 */
int ls_send_async(struct ls_ctx *ctx,
		  uint8_t type, uint16_t src, uint16_t dst, uint8_t flags,
		  const uint8_t *payload, size_t payload_len,
		  const uint8_t *key,
		  bool want_resp, uint8_t resp_type, uint16_t resp_src,
		  uint32_t timeout_ms,
		  ls_send_cb done_cb, void *user_data);

/**
 * @brief Send a DATA frame without waiting for an acknowledgement (async).
 *
 * Convenience wrapper around @ref ls_send_async().  Copies @p data into the
 * internal TX queue and returns immediately.  @p done_cb is invoked from the
 * LoRa Star thread once the frame has been transmitted (or on failure).
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
 * Convenience wrapper around @ref ls_send_async().  Copies @p data into the
 * internal TX queue and returns immediately.  @p done_cb is invoked from the
 * LoRa Star thread with the result (0 on ACK received, -ETIMEDOUT after all
 * retries, negative errno on other failures).
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
