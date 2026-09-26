/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LORA_STAR_COORD_H
#define LORA_STAR_COORD_H

#include <lora_star/lora_star.h>

#ifdef CONFIG_LORA_STAR_COORDINATOR

/**
 * @brief Coordinator node table and per-node anti-replay state.
 *
 * Tracks every node this coordinator knows about — its short address,
 * DevEUI, and last-accepted frame counter (@ref ls_node_record) — regardless
 * of how the node was provisioned: via pairing (@ref ls_pairing_coord_init())
 * or registered directly with @ref ls_coord_add_node() for a fixed-key
 * deployment that never uses pairing.  A single static instance is owned by
 * @c coord.c and initialised by @ref ls_init_coord(); obtain a pointer to it
 * via @ref ls_coord_get().
 *
 * The @c nodes array may be read directly by the coordinator application for
 * data-path lookups.
 */
struct ls_coord_ctx {
	/** Node table (index = slot; may be read by the coordinator app). */
	struct coord_node nodes[CONFIG_LORA_STAR_MAX_NODES];
	/** Next ShortAddr to auto-assign (used by pairing); starts at LS_ADDR_MIN. */
	uint16_t          next_addr;
};

/**
 * @brief Get the coordinator's node-table context.
 *
 * @return Pointer to the static @ref ls_coord_ctx instance, initialised by
 *         @ref ls_init_coord().
 */
struct ls_coord_ctx *ls_coord_get(void);

/**
 * @brief Look up a node by short address.
 *
 * @param short_addr  Address to search for.
 * @return Pointer to the node entry, or NULL if not found.
 */
struct coord_node *ls_coord_find_node(uint16_t short_addr);

/**
 * @brief Look up a node by DevEUI.
 *
 * @param dev_eui  DevEUI to search for.
 * @return Pointer to the node entry, or NULL if not found.
 */
struct coord_node *ls_coord_find_node_by_eui(const uint8_t dev_eui[LS_DEV_EUI_SIZE]);

/**
 * @brief Add or update a node in the coordinator's table.
 *
 * If @p dev_eui is non-NULL and already has an entry, that entry is updated
 * in place — its existing short address and anti-replay checkpoint are
 * preserved, and @p short_addr is ignored.  This is the pairing re-pair path:
 * it keeps the FCNT checkpoint intact across a re-pair of an already-known
 * node, so a captured old frame cannot be replayed after re-pairing resets
 * nothing.
 *
 * Otherwise a new slot is allocated: pass @ref LS_BCAST_ADDR as @p short_addr
 * to auto-assign the next sequential address (pairing's fresh-join path), or
 * a specific address in [@ref LS_ADDR_MIN, @ref LS_ADDR_MAX] to register a
 * node provisioned out of band, with no pairing required.  The record is
 * persisted to Settings before returning.
 *
 * @param ctx         LoRa Star context.
 * @param dev_eui     Node DevEUI, or NULL to register a node without EUI tracking.
 * @param short_addr  Address to assign, or @ref LS_BCAST_ADDR to auto-assign.
 * @param is_repair   Optional output: set to true if an existing DevEUI entry
 *                    was updated rather than a new slot allocated.  May be NULL.
 * @return The assigned short address on success, or 0 on failure (table full,
 *         or the auto-assign address space is exhausted).
 */
uint16_t ls_coord_add_node(struct ls_ctx *ctx, const uint8_t dev_eui[LS_DEV_EUI_SIZE],
			   uint16_t short_addr, bool *is_repair);

/**
 * @brief Initialise the coordinator's node table.
 *
 * Restores the node table and next auto-assign address from Settings. Call
 * once, from @ref ls_init_coord(); independent of whether pairing is used.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on storage failure.
 */
int ls_coord_init(struct ls_ctx *ctx);

/**
 * @brief Anti-replay check for a coordinator uplink (DATA/ACK from a node).
 *
 * Compares @p fcnt against @p src's in-RAM @c session_fcnt_last (reset to 0
 * every time @ref ls_coord_set_session() installs a fresh session key for
 * that node) and rejects unknown senders and non-increasing frame counters.
 * Nothing is persisted — a captured frame from a previous session fails MIC
 * verification under the node's new session key before this check ever
 * runs, so freshness comes from key rotation, not a saved checkpoint.
 * Called from the shared RX path in @c lora_star.c for every accepted
 * DATA/ACK frame when @c CONFIG_LORA_STAR_COORDINATOR is enabled.
 *
 * @param ctx   LoRa Star context.
 * @param src   Source address the frame claims to be from.
 * @param fcnt  Frame counter carried by the frame.
 * @return true to accept the frame, false to drop it as a replay.
 */
bool ls_coord_replay_check(struct ls_ctx *ctx, uint16_t src, uint32_t fcnt);

/**
 * @brief Look up a node's current session key.
 *
 * @param short_addr  Node short address.
 * @return Pointer to the node's session key, or NULL if the address is
 *         unknown or has no active session (see @ref ls_coord_set_session()).
 */
const uint8_t *ls_coord_get_session_key(uint16_t short_addr);

/**
 * @brief Install a freshly established session for a node.
 *
 * Called by the rejoin handshake once a node has proven it holds the
 * network key. Records @p session_key, resets the node's anti-replay
 * checkpoint to 0, and marks the session active. Never persisted — the
 * whole point of a session key is that it is fresh RAM-only state that
 * disappears on either side's reboot.
 *
 * @param short_addr   Node short address; must already exist in the table
 *                     (see @ref ls_coord_add_node()).
 * @param session_key  Freshly derived session key, @ref LS_NETWORK_KEY_SIZE bytes.
 */
void ls_coord_set_session(uint16_t short_addr, const uint8_t session_key[LS_NETWORK_KEY_SIZE]);

/**
 * @brief Rate-gate a SESSION_UNKNOWN notice for a node.
 *
 * Called from the MAC RX path (see @c mac.c) when a DATA/ACK frame claiming
 * to be from @p short_addr cannot be verified (no active session). Returns
 * true at most once per @c CONFIG_LORA_STAR_SESSION_UNKNOWN_COOLDOWN_MS for a
 * given, already-known node, and updates that node's timestamp as a side
 * effect when it does. Always false for an address with no table entry, so
 * this can't be used to make the coordinator respond to arbitrary spoofed
 * addresses.
 *
 * @param short_addr  Address the unverifiable frame claims to be from.
 * @return true if a SESSION_UNKNOWN notice should be sent now, false otherwise.
 */
bool ls_coord_notify_allowed(uint16_t short_addr);

#else /* !CONFIG_LORA_STAR_COORDINATOR */

/* Coordinator role not built — never called by ls_replay_check(), but keeps
 * that dispatch free of #ifdef.
 */
static inline bool ls_coord_replay_check(struct ls_ctx *ctx, uint16_t src, uint32_t fcnt)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(src);
	ARG_UNUSED(fcnt);
	return true;
}

/* Coordinator role not built — never called by mac.c's key resolution, but
 * keeps that dispatch free of #ifdef.
 */
static inline const uint8_t *ls_coord_get_session_key(uint16_t short_addr)
{
	ARG_UNUSED(short_addr);
	return NULL;
}

/* Coordinator role not built — never called by mac.c's RX path, but keeps
 * that dispatch free of #ifdef.
 */
static inline bool ls_coord_notify_allowed(uint16_t short_addr)
{
	ARG_UNUSED(short_addr);
	return false;
}

#endif /* CONFIG_LORA_STAR_COORDINATOR */

#endif /* LORA_STAR_COORD_H */
