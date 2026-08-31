/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>
#include <lora_star/lora_star.h>

/**
 * @brief Initialise the Settings subsystem and register the LoRa Star handlers.
 *
 * Must be called once before any load or save function.
 *
 * @return 0 on success, negative errno on failure.
 */
int ls_storage_init(void);

/**
 * @brief Load the TX frame counter from Settings into @p ctx->fcnt.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on failure.
 */
int ls_storage_load_fcnt(struct ls_ctx *ctx);

/**
 * @brief Load the network key from Settings into @p ctx->network_key.
 *
 * Sets @p ctx->network_key_found if the key was stored.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on failure.
 */
int ls_storage_load_network_key(struct ls_ctx *ctx);

/**
 * @brief Load the short address from Settings into @p ctx->own_addr.
 *
 * Sets @p ctx->addr_found if the address was stored.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on failure.
 */
int ls_storage_load_addr(struct ls_ctx *ctx);

/**
 * @brief Load the last-accepted RX frame counter into @p ctx->_rx_fcnt_last.
 *
 * Used by the node role to restore the anti-replay checkpoint for frames
 * received from the coordinator. Defaults to 0 if never stored.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on failure.
 */
int ls_storage_load_rx_fcnt(struct ls_ctx *ctx);

/**
 * @brief Save @p ctx->_rx_fcnt_last to Settings.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on failure.
 */
int ls_storage_save_rx_fcnt(struct ls_ctx *ctx);

/**
 * @brief Load all common persistent state into @p ctx.
 *
 * Populates @p ctx->own_addr (sets @p ctx->addr_found if a stored address is
 * found), @p ctx->fcnt, and @p ctx->network_key (sets @p ctx->network_key_found
 * if a stored key is found).
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, -ENOENT if no address is stored (node never paired),
 *         negative errno on other failures.
 */
int ls_storage_load_all(struct ls_ctx *ctx);

/**
 * @brief Save @p ctx->fcnt to Settings.
 *
 * Also updates @p ctx->_fcnt_saved to @p ctx->fcnt on success, so callers
 * that gate saves on the delta between the two (see @c ls_mac_send()) see
 * the gap close immediately.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on failure.
 */
int ls_storage_save_fcnt(struct ls_ctx *ctx);

/**
 * @brief Save @p ctx->network_key to Settings.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on failure.
 */
int ls_storage_save_network_key(struct ls_ctx *ctx);

/**
 * @brief Save @p ctx->own_addr, @p ctx->fcnt, and @p ctx->network_key to Settings.
 *
 * @param ctx  LoRa Star context.
 * @return 0 on success, negative errno on first failure.
 */
int ls_storage_save_all(struct ls_ctx *ctx);

#ifdef CONFIG_LORA_STAR_COORDINATOR
/**
 * @brief Callback invoked for each node record loaded during coordinator startup.
 *
 * @param short_addr  Node short address.
 * @param rec         Persistent node record (valid only for the duration of the call).
 * @param user_data   Opaque pointer supplied at @ref ls_storage_coord_load() time.
 */
typedef void (*ls_storage_node_load_cb)(uint16_t short_addr,
					const struct ls_node_record *rec,
					void *user_data);

/**
 * @brief Load coordinator persistent state.
 *
 * Populates @p ctx->fcnt and @p ctx->network_key (sets @p ctx->network_key_found)
 * from common storage.  Populates @p next_addr from coordinator storage.
 * Invokes @p cb for every persisted node record.
 *
 * @param ctx        LoRa Star context.
 * @param next_addr  Receives the next ShortAddr to assign; defaults to LS_ADDR_MIN.
 * @param cb         Called for every persisted node record; may be NULL.
 * @param user_data  Forwarded to @p cb.
 * @return 0 on success, negative errno on failure.
 */
int ls_storage_coord_load(struct ls_ctx *ctx, uint16_t *next_addr,
			  ls_storage_node_load_cb cb, void *user_data);

/**
 * @brief Save the coordinator's next ShortAddr to Settings.
 *
 * @param ctx        LoRa Star context (reserved, not used).
 * @param next_addr  Next ShortAddr to persist.
 * @return 0 on success, negative errno on failure.
 */
int ls_storage_coord_save_next_addr(struct ls_ctx *ctx, uint16_t next_addr);

/**
 * @brief Persist a node record under @c ls/coord/node/<addr>.
 *
 * @param short_addr  Node short address.
 * @param rec         Node record to persist.
 * @return 0 on success, negative errno on failure.
 */
int ls_storage_coord_save_node(uint16_t short_addr, const struct ls_node_record *rec);
#endif

#endif /* STORAGE_H */
