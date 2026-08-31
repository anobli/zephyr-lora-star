/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LORA_STAR_PAIRING_BUTTON_H
#define LORA_STAR_PAIRING_BUTTON_H

#include <lora_star/lora_star.h>
#include <lora_star/pairing.h>

#ifdef CONFIG_LORA_STAR_COORDINATOR

/**
 * @brief Register a join callback for the devicetree-configured pairing button.
 *
 * Optional. Forwarded verbatim to @ref ls_pairing_coord_init() the first time
 * the button is pressed. Call this from the application before the first
 * press if join notifications are needed; the button works with no
 * application code at all otherwise.
 *
 * @param cb         Called when a node completes pairing; may be NULL.
 * @param user_data  Forwarded to @p cb.
 */
void ls_pairing_button_set_join_cb(ls_pairing_join_cb cb, void *user_data);

#endif /* CONFIG_LORA_STAR_COORDINATOR */

#ifdef CONFIG_LORA_STAR_NODE

/**
 * @brief Register a completion callback for the devicetree-configured pairing button.
 *
 * Optional. Forwarded verbatim to @ref ls_pairing_node_start() on every button
 * press. Call this from the application if it needs to know when pairing
 * finishes; the button works with no application code at all otherwise.
 *
 * @param cb         Called when pairing finishes; may be NULL.
 * @param user_data  Forwarded to @p cb.
 */
void ls_pairing_button_set_done_cb(ls_pairing_node_done_cb cb, void *user_data);

#endif /* CONFIG_LORA_STAR_NODE */

#if defined(CONFIG_LORA_STAR_COORDINATOR) && defined(CONFIG_LORA_STAR_NODE)

/**
 * @brief Tell the pairing button which role to trigger on the next press.
 *
 * Required only for dual-role builds (@c CONFIG_LORA_STAR_ROLE_DUAL), where
 * the role is chosen at runtime and cannot be inferred from @p ls_ctx::own_addr
 * (an unpaired node also sits at @ref LS_COORD_ADDR). Call once, as soon as
 * the application has decided its own role.
 *
 * @param is_coordinator  True to open a pairing window on press, false to
 *                        broadcast a JOIN_REQ on press.
 */
void ls_pairing_button_set_role(bool is_coordinator);

#endif /* CONFIG_LORA_STAR_COORDINATOR && CONFIG_LORA_STAR_NODE */

#endif /* LORA_STAR_PAIRING_BUTTON_H */
