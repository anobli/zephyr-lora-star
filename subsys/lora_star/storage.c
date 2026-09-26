/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zephyr/settings/settings.h>
#include <zephyr/logging/log.h>
#include "storage.h"

LOG_MODULE_REGISTER(ls_storage, CONFIG_LORA_STAR_LOG_LEVEL);

#define KEY_COMMON_ROOT    "ls/common"
#define KEY_COMMON_ADDR    "ls/common/addr"
#define KEY_COMMON_NETKEY  "ls/common/netkey"

#define KEY_COORD_ROOT      "ls/coord"
#define KEY_COORD_NEXT_ADDR "ls/coord/next_addr"
#define KEY_COORD_NODE_FMT  "ls/coord/node/%04x"

static struct ls_ctx *g_ctx;

#ifdef CONFIG_LORA_STAR_COORDINATOR
static struct {
	uint16_t               *next_addr;
	ls_storage_node_load_cb cb;
	void                   *user_data;
} g_coord;

static int coord_h_set(const char *key, size_t len,
		       settings_read_cb read_cb, void *cb_arg)
{
	ssize_t n;

	if (strcmp(key, "next_addr") == 0) {
		if (!g_coord.next_addr) {
			return 0;
		}
		n = read_cb(cb_arg, g_coord.next_addr, sizeof(uint16_t));
		if (n != sizeof(uint16_t)) {
			LOG_ERR("short read for next_addr: %zd", n);
			return -EINVAL;
		}
	} else if (strncmp(key, "node/", 5) == 0) {
		uint16_t addr = (uint16_t)strtoul(key + 5, NULL, 16);
		struct ls_node_record rec;

		n = read_cb(cb_arg, &rec, sizeof(rec));
		if (n == sizeof(rec) && g_coord.cb) {
			g_coord.cb(addr, &rec, g_coord.user_data);
		}
	}

	return 0;
}

static struct settings_handler coord_handler = {
	.name  = KEY_COORD_ROOT,
	.h_set = coord_h_set,
};
#endif

static int common_h_set(const char *key, size_t len,
			 settings_read_cb read_cb, void *cb_arg)
{
	ssize_t n;

	if (!g_ctx) {
		return 0;
	}

	if (strcmp(key, "addr") == 0) {
		n = read_cb(cb_arg, &g_ctx->own_addr, sizeof(uint16_t));
		if (n != sizeof(uint16_t)) {
			LOG_ERR("short read for addr: %zd", n);
			return -EINVAL;
		}
		g_ctx->addr_found = true;
	} else if (strcmp(key, "netkey") == 0) {
		n = read_cb(cb_arg, g_ctx->network_key, LS_NETWORK_KEY_SIZE);
		if (n != LS_NETWORK_KEY_SIZE) {
			LOG_ERR("short read for netkey: %zd", n);
			return -EINVAL;
		}

		/* TODO: improve the way to load key and manage override default key */
		if (ls_is_network_key_set(g_ctx))
			g_ctx->network_key_found = true;
	}

	return 0;
}

static struct settings_handler common_handler = {
	.name  = KEY_COMMON_ROOT,
	.h_set = common_h_set,
};

int ls_storage_init(void)
{
	static bool initialized;
	int ret;

	if (initialized) {
		return 0;
	}

	ret = settings_subsys_init();
	if (ret < 0) {
		return ret;
	}

	ret = settings_register(&common_handler);
	if (ret < 0) {
		return ret;
	}

#ifdef CONFIG_LORA_STAR_COORDINATOR
	ret = settings_register(&coord_handler);
	if (ret < 0) {
		return ret;
	}
#endif

	initialized = true;
	return 0;
}

int ls_storage_load_network_key(struct ls_ctx *ctx)
{
	int ret;

	g_ctx = ctx;
	ret = settings_load_subtree(KEY_COMMON_NETKEY);
	g_ctx = NULL;
	return ret;
}

int ls_storage_load_addr(struct ls_ctx *ctx)
{
	int ret;

	g_ctx = ctx;
	ret = settings_load_subtree(KEY_COMMON_ADDR);
	g_ctx = NULL;
	return ret;
}

int ls_storage_load_all(struct ls_ctx *ctx)
{
	int ret;

	ret = ls_storage_load_network_key(ctx);
	if (ret < 0) {
		return ret;
	}

	ret = ls_storage_load_addr(ctx);
	if (ret < 0) {
		return ret;
	}

	return ctx->addr_found ? 0 : -ENOENT;
}

int ls_storage_save_network_key(struct ls_ctx *ctx)
{
	return settings_save_one(KEY_COMMON_NETKEY, ctx->network_key, LS_NETWORK_KEY_SIZE);
}

int ls_storage_save_all(struct ls_ctx *ctx)
{
	int ret;

	ret = settings_save_one(KEY_COMMON_ADDR, &ctx->own_addr, sizeof(ctx->own_addr));
	if (ret < 0) {
		return ret;
	}

	return settings_save_one(KEY_COMMON_NETKEY, ctx->network_key, LS_NETWORK_KEY_SIZE);
}

#ifdef CONFIG_LORA_STAR_COORDINATOR
int ls_storage_coord_load(struct ls_ctx *ctx, uint16_t *next_addr,
			  ls_storage_node_load_cb cb, void *user_data)
{
	int ret;

	ARG_UNUSED(ctx);
	*next_addr = LS_ADDR_MIN;

	g_coord.next_addr = next_addr;
	g_coord.cb        = cb;
	g_coord.user_data = user_data;

	ret = settings_load_subtree(KEY_COORD_ROOT);

	g_coord.next_addr = NULL;
	g_coord.cb        = NULL;
	g_coord.user_data = NULL;

	return ret;
}

int ls_storage_coord_save_next_addr(struct ls_ctx *ctx, uint16_t next_addr)
{
	ARG_UNUSED(ctx);
	return settings_save_one(KEY_COORD_NEXT_ADDR, &next_addr, sizeof(next_addr));
}

int ls_storage_coord_save_node(uint16_t short_addr, const struct ls_node_record *rec)
{
	char key[32];

	snprintf(key, sizeof(key), KEY_COORD_NODE_FMT, short_addr);
	return settings_save_one(key, rec, sizeof(*rec));
}
#endif
