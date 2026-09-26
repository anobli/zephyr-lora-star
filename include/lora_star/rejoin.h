/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file rejoin.h
 * @brief Session (re)establishment handshake for already-keyed devices.
 *
 * A device that already holds the network key — because it was paired
 * earlier (see lora_star/pairing.h) or provisioned with a fixed key —
 * announces itself to the coordinator on every boot with REJOIN_REQ. The
 * coordinator challenges it to prove it holds the network key and, on
 * success, both sides derive a fresh session key and reset their frame
 * counters to 0. Because the session key is different every time, a frame
 * captured from a previous session fails MIC verification under the new
 * key — replay protection comes from session freshness, not from a saved
 * counter, so nothing about FCNT needs to be persisted on either side.
 *
 * This is a distinct handshake from pairing: pairing's ECDH exchange is how
 * a device gets the network key in the first place (once, requiring
 * physical proximity); rejoin is how it establishes a working session with
 * that key (every boot, no proximity requirement — trust comes from
 * already holding the key).
 *
 * A node rebooting is not the only way a session goes stale — the
 * coordinator's session state is RAM-only too, so a coordinator reboot
 * silently drops every node's session while the nodes themselves stay up
 * and none the wiser. Two network-key-signed notices close that gap without
 * either side persisting anything: LS_TYPE_SESSION_UNKNOWN, sent back to a
 * node whose DATA/ACK the coordinator can no longer verify, and
 * LS_TYPE_COORD_HELLO, broadcast a few times right after the coordinator
 * boots. Both are handled automatically by @ref ls_rejoin_node_init(); see
 * its doc comment for which failure mode each one covers.
 */

#ifndef LORA_STAR_REJOIN_H
#define LORA_STAR_REJOIN_H

#include <lora_star/lora_star.h>

/** Rejoin nonce length in bytes. */
#define LS_REJOIN_NONCE_SIZE 4U

/** REJOIN_REQ payload: DevEUI(8) + NodeNonce(4) = 12 bytes */
#define LS_REJOIN_REQ_PAYLOAD_SIZE (LS_DEV_EUI_SIZE + LS_REJOIN_NONCE_SIZE)

/**
 * @brief Wire format of the REJOIN_REQ payload.
 *
 * Sent by a node that already holds the network key to announce itself and
 * request a fresh session. Signed with the long-term network key — no
 * encryption, nothing here is secret.
 */
struct ls_rejoin_req_payload {
	/** Device EUI — identifies the node to the coordinator's node table. */
	uint8_t dev_eui[LS_DEV_EUI_SIZE];
	/** Fresh random nonce — contributes to this session's key derivation. */
	uint8_t node_nonce[LS_REJOIN_NONCE_SIZE];
} __packed;

/** REJOIN_ACCEPT payload: CoordNonce(4) + ShortAddr(2) = 6 bytes */
#define LS_REJOIN_ACCEPT_PAYLOAD_SIZE (LS_REJOIN_NONCE_SIZE + sizeof(uint16_t))

/**
 * @brief Wire format of the REJOIN_ACCEPT payload.
 *
 * Sent by the coordinator in response to a valid REJOIN_REQ. Signed with the
 * freshly derived session key itself: the node derives the same key
 * independently from @c coord_nonce plus its own @c node_nonce, so a
 * successful MIC check on this frame *is* mutual confirmation that both
 * sides agree on the new session key — no further round trip needed, same
 * trick @ref ls_join_accept_payload uses for pairing.
 */
struct ls_rejoin_accept_payload {
	/** Coordinator's contribution to the session key derivation. */
	uint8_t coord_nonce[LS_REJOIN_NONCE_SIZE];
	/** Assigned short address, little-endian on the wire. */
	uint8_t short_addr[sizeof(uint16_t)];
} __packed;

#ifdef CONFIG_LORA_STAR_COORDINATOR

/**
 * @brief Register the always-on rejoin handshake handler.
 *
 * Unlike pairing, there is no window to open: any device presenting a valid
 * REJOIN_REQ signed with the network key can establish a session at any
 * time. This is what lets a node provisioned with a fixed key — one that
 * never goes through ECDH pairing at all — become known to the coordinator
 * and get anti-replay protection, purely by holding the network key.
 * Call once, from @ref ls_init_coord().
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, -ENOMEM if the frame callback registry is full.
 */
int ls_rejoin_coord_init(struct ls_ctx *ctx);

#endif /* CONFIG_LORA_STAR_COORDINATOR */

#ifdef CONFIG_LORA_STAR_NODE

/**
 * @brief Register the node's session-recovery handlers.
 *
 * A node has no way to notice on its own that the coordinator rebooted and
 * dropped its session — nothing changes locally. This registers two
 * always-on handlers that react by re-running @ref ls_rejoin_start():
 *
 *  - LS_TYPE_SESSION_UNKNOWN: sent by the coordinator, addressed to this
 *    node specifically, when it rejects one of our DATA/ACK frames for lack
 *    of an active session. Only reaches us the next time we transmit.
 *  - LS_TYPE_COORD_HELLO: broadcast by the coordinator a few times right
 *    after it boots. Only reaches us if we happen to be listening at that
 *    moment (e.g. @c ctx->always_on_rx or an open RX window).
 *
 * Both are signed with the long-term network key (never with a session key,
 * since establishing a session is exactly what they trigger) and verified
 * here before @ref ls_rejoin_start() is called. Call once, from @ref
 * ls_init(); no application code is required.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, -ENOMEM if the frame callback registry is full.
 */
int ls_rejoin_node_init(struct ls_ctx *ctx);

/**
 * @brief Completion callback type for the rejoin handshake.
 *
 * Called from the LoRa Star thread context.
 *
 * @param ctx       LoRa Star context.
 * @param result    0 on success, -ETIMEDOUT if all retries were exhausted,
 *                  another negative errno on hard failure.
 * @param user_data Opaque pointer supplied to @ref ls_rejoin_start().
 */
typedef void (*ls_rejoin_done_cb)(struct ls_ctx *ctx, int result, void *user_data);

/**
 * @brief Start the rejoin handshake asynchronously.
 *
 * Generates a fresh nonce, broadcasts a REJOIN_REQ signed with the network
 * key, and waits for a valid REJOIN_ACCEPT. On success, installs a fresh
 * session key, resets @p ctx->fcnt and the RX anti-replay checkpoint to 0,
 * updates @p ctx->own_addr if the coordinator assigned a different one, and
 * persists the session (address + network key) to Settings. Retries up to
 * @c CONFIG_LORA_STAR_TX_MAX_RETRIES times with backoff, reusing the same
 * retry machinery as pairing and ordinary sends.
 *
 * Called automatically by @ref ls_init() when a previously paired session is
 * restored from Settings, and by the pairing handshake right after a fresh
 * pairing completes — most applications never need to call this directly.
 * It is exposed for an application that wants to manually re-establish a
 * session after detecting it has gone stale (e.g. repeated ACK timeouts
 * following a coordinator reboot).
 *
 * @param ctx        LoRa Star context; @p ctx->network_key must already be set.
 * @param dev_eui    This device's DevEUI (e.g. from @c hwinfo_get_device_id()).
 * @param done_cb    Called with the result; may be NULL.
 * @param user_data  Forwarded to @p done_cb.
 * @return 0 if the handshake was submitted, negative errno on error.
 */
int ls_rejoin_start(struct ls_ctx *ctx, const uint8_t dev_eui[LS_DEV_EUI_SIZE],
		    ls_rejoin_done_cb done_cb, void *user_data);

#endif /* CONFIG_LORA_STAR_NODE */

#endif /* LORA_STAR_REJOIN_H */
