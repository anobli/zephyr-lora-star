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
 * Looks up @p src's persisted @c fcnt_last, rejects unknown senders (no
 * entry in the node table — see @ref ls_coord_add_node()) and non-increasing
 * frame counters, and persists the new checkpoint on acceptance.  Called
 * from the shared RX path in @c lora_star.c for every accepted DATA/ACK
 * frame when @c CONFIG_LORA_STAR_COORDINATOR is enabled.
 *
 * @param ctx   LoRa Star context.
 * @param src   Source address the frame claims to be from.
 * @param fcnt  Frame counter carried by the frame.
 * @return true to accept the frame, false to drop it as a replay.
 */
bool ls_coord_replay_check(struct ls_ctx *ctx, uint16_t src, uint32_t fcnt);

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

#endif /* CONFIG_LORA_STAR_COORDINATOR */

#endif /* LORA_STAR_COORD_H */
