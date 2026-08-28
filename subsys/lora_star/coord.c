/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <lora_star/coord.h>

#include "storage.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ls_coord, CONFIG_LORA_STAR_LOG_LEVEL);

static struct ls_coord_ctx coord_ctx_instance;

struct ls_coord_ctx *ls_coord_get(void)
{
	return &coord_ctx_instance;
}

static void coord_on_node_loaded(uint16_t short_addr, const struct ls_node_record *rec,
				 void *user_data)
{
	struct ls_coord_ctx *coord = user_data;
	int i;

	for (i = 0; i < CONFIG_LORA_STAR_MAX_NODES; i++) {
		if (!coord->nodes[i].active) {
			coord->nodes[i].active     = true;
			coord->nodes[i].short_addr = short_addr;
			coord->nodes[i].rec        = *rec;
			return;
		}
	}
	LOG_WRN("Node table full — dropping addr 0x%04x", short_addr);
}

struct coord_node *ls_coord_find_node(uint16_t short_addr)
{
	struct ls_coord_ctx *coord = &coord_ctx_instance;
	int i;

	for (i = 0; i < CONFIG_LORA_STAR_MAX_NODES; i++) {
		if (coord->nodes[i].active && coord->nodes[i].short_addr == short_addr) {
			return &coord->nodes[i];
		}
	}
	return NULL;
}

struct coord_node *ls_coord_find_node_by_eui(const uint8_t dev_eui[LS_DEV_EUI_SIZE])
{
	struct ls_coord_ctx *coord = &coord_ctx_instance;
	int i;

	for (i = 0; i < CONFIG_LORA_STAR_MAX_NODES; i++) {
		if (coord->nodes[i].active &&
		    memcmp(coord->nodes[i].rec.dev_eui, dev_eui, LS_DEV_EUI_SIZE) == 0) {
			return &coord->nodes[i];
		}
	}
	return NULL;
}

static int coord_alloc_slot(struct ls_coord_ctx *coord)
{
	int i;

	for (i = 0; i < CONFIG_LORA_STAR_MAX_NODES; i++) {
		if (!coord->nodes[i].active) {
			return i;
		}
	}
	return -1;
}

uint16_t ls_coord_add_node(struct ls_ctx *ctx, const uint8_t dev_eui[LS_DEV_EUI_SIZE],
			   uint16_t short_addr, bool *is_repair)
{
	struct ls_coord_ctx *coord = &coord_ctx_instance;
	struct coord_node *node;
	int slot;

	if (is_repair) {
		*is_repair = false;
	}

	if (dev_eui != NULL) {
		node = ls_coord_find_node_by_eui(dev_eui);
		if (node != NULL) {
			if (is_repair) {
				*is_repair = true;
			}
			return node->short_addr;
		}
	}

	if (short_addr == LS_BCAST_ADDR) {
		if (coord->next_addr > LS_ADDR_MAX) {
			LOG_ERR("Address space exhausted");
			return 0;
		}
		short_addr = coord->next_addr++;
		ls_storage_coord_save_next_addr(ctx, coord->next_addr);
	} else if (short_addr < LS_ADDR_MIN || short_addr > LS_ADDR_MAX) {
		LOG_ERR("Invalid short address 0x%04x", short_addr);
		return 0;
	}

	slot = coord_alloc_slot(coord);
	if (slot < 0) {
		LOG_ERR("Node table full");
		return 0;
	}

	coord->nodes[slot].active     = true;
	coord->nodes[slot].short_addr = short_addr;
	memset(&coord->nodes[slot].rec, 0, sizeof(coord->nodes[slot].rec));
	if (dev_eui != NULL) {
		memcpy(coord->nodes[slot].rec.dev_eui, dev_eui, LS_DEV_EUI_SIZE);
	}

	ls_storage_coord_save_node(short_addr, &coord->nodes[slot].rec);
	return short_addr;
}

bool ls_coord_replay_check(struct ls_ctx *ctx, uint16_t src, uint32_t fcnt)
{
	struct coord_node *node;

	ARG_UNUSED(ctx);

	node = ls_coord_find_node(src);
	if (node == NULL || fcnt <= node->rec.fcnt_last) {
		return false;
	}

	node->rec.fcnt_last = fcnt;
	ls_storage_coord_save_node(src, &node->rec);
	return true;
}

int ls_coord_init(struct ls_ctx *ctx)
{
	struct ls_coord_ctx *coord = &coord_ctx_instance;
	int ret;

	memset(coord, 0, sizeof(*coord));
	coord->next_addr = LS_ADDR_MIN;

	ret = ls_storage_coord_load(ctx, &coord->next_addr, coord_on_node_loaded, coord);
	if (ret < 0) {
		return ret;
	}

	return 0;
}
