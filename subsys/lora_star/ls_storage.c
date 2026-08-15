#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zephyr/settings/settings.h>
#include <zephyr/logging/log.h>
#include <lora_star/ls_frame.h>
#include "ls_storage.h"

LOG_MODULE_REGISTER(ls_storage, CONFIG_LORA_STAR_LOG_LEVEL);

/* Settings key roots */
#define KEY_COORD_ROOT      "ls/coord"
#define KEY_COORD_NEXT_ADDR "ls/coord/next_addr"
#define KEY_COORD_FCNT      "ls/coord/fcnt"
#define KEY_COORD_NODE_FMT  "ls/coord/node/%04x"   /* arg: short_addr */

#define KEY_NODE_ROOT       "ls/node"
#define KEY_NODE_ADDR       "ls/node/addr"
#define KEY_NODE_KEY        "ls/node/key"
#define KEY_NODE_FCNT       "ls/node/fcnt"
#define KEY_NODE_FCNT_LAST  "ls/node/fcnt_last"

/* --------------------------------------------------------------------------
 * Coordinator handler
 * -------------------------------------------------------------------------- */

static struct {
	uint16_t next_addr;
	uint32_t fcnt;
	bool     joined_found; /* at least one node record loaded */

	ls_storage_node_load_cb node_cb;
	void                   *node_cb_data;
} coord_ctx;

static int coord_h_set(const char *key, size_t len,
		       settings_read_cb read_cb, void *cb_arg)
{
	if (strcmp(key, "next_addr") == 0) {
		ssize_t n = read_cb(cb_arg, &coord_ctx.next_addr, sizeof(uint16_t));

		if (n != sizeof(uint16_t)) {
			LOG_ERR("short read for next_addr: %zd", n);
			return -EINVAL;
		}
	} else if (strcmp(key, "fcnt") == 0) {
		ssize_t n = read_cb(cb_arg, &coord_ctx.fcnt, sizeof(uint32_t));

		if (n != sizeof(uint32_t)) {
			LOG_ERR("short read for coord fcnt: %zd", n);
			return -EINVAL;
		}
	} else if (strncmp(key, "node/", 5) == 0) {
		uint16_t addr = (uint16_t)strtoul(key + 5, NULL, 16);
		struct ls_node_record rec;

		ssize_t n = read_cb(cb_arg, &rec, sizeof(rec));

		if (n == sizeof(rec) && coord_ctx.node_cb) {
			coord_ctx.node_cb(addr, &rec, coord_ctx.node_cb_data);
			coord_ctx.joined_found = true;
		}
	}

	return 0;
}

static struct settings_handler coord_handler = {
	.name  = KEY_COORD_ROOT,
	.h_set = coord_h_set,
};

/* --------------------------------------------------------------------------
 * Node handler
 * -------------------------------------------------------------------------- */

static struct {
	uint16_t *addr;
	uint8_t  *key;
	uint32_t *fcnt;
	uint32_t *fcnt_last;
	bool      addr_found;
} node_ctx;

static int node_h_set(const char *key, size_t len,
		      settings_read_cb read_cb, void *cb_arg)
{
	if (strcmp(key, "addr") == 0) {
		if (node_ctx.addr) {
			ssize_t n = read_cb(cb_arg, node_ctx.addr, sizeof(uint16_t));

			if (n != sizeof(uint16_t)) {
				LOG_ERR("short read for node addr: %zd", n);
				return -EINVAL;
			}
			node_ctx.addr_found = true;
		}
	} else if (strcmp(key, "key") == 0) {
		if (node_ctx.key) {
			ssize_t n = read_cb(cb_arg, node_ctx.key, LS_SESSION_KEY_SIZE);

			if (n != LS_SESSION_KEY_SIZE) {
				LOG_ERR("short read for session key: %zd", n);
				return -EINVAL;
			}
		}
	} else if (strcmp(key, "fcnt") == 0) {
		if (node_ctx.fcnt) {
			ssize_t n = read_cb(cb_arg, node_ctx.fcnt, sizeof(uint32_t));

			if (n != sizeof(uint32_t)) {
				LOG_ERR("short read for node fcnt: %zd", n);
				return -EINVAL;
			}
		}
	} else if (strcmp(key, "fcnt_last") == 0) {
		if (node_ctx.fcnt_last) {
			ssize_t n = read_cb(cb_arg, node_ctx.fcnt_last, sizeof(uint32_t));

			if (n != sizeof(uint32_t)) {
				LOG_ERR("short read for node fcnt_last: %zd", n);
				return -EINVAL;
			}
		}
	}

	return 0;
}

static struct settings_handler node_handler = {
	.name  = KEY_NODE_ROOT,
	.h_set = node_h_set,
};

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int ls_storage_init(void)
{
	int ret;

	ret = settings_subsys_init();
	if (ret < 0) {
		return ret;
	}

	ret = settings_register(&coord_handler);
	if (ret < 0) {
		return ret;
	}

	return settings_register(&node_handler);
}

/* --- coordinator --- */

int ls_storage_coord_load(uint16_t *next_addr, uint32_t *fcnt,
			  ls_storage_node_load_cb node_cb, void *user_data)
{
	coord_ctx.next_addr    = LS_ADDR_MIN;
	coord_ctx.fcnt         = 0;
	coord_ctx.joined_found = false;
	coord_ctx.node_cb      = node_cb;
	coord_ctx.node_cb_data = user_data;

	int ret = settings_load_subtree(KEY_COORD_ROOT);

	*next_addr = coord_ctx.next_addr;
	*fcnt      = coord_ctx.fcnt;

	coord_ctx.node_cb      = NULL;
	coord_ctx.node_cb_data = NULL;

	return ret;
}

int ls_storage_coord_save_next_addr(uint16_t next_addr)
{
	return settings_save_one(KEY_COORD_NEXT_ADDR, &next_addr, sizeof(next_addr));
}

int ls_storage_coord_save_fcnt(uint32_t fcnt)
{
	return settings_save_one(KEY_COORD_FCNT, &fcnt, sizeof(fcnt));
}

int ls_storage_coord_save_node(uint16_t short_addr, const struct ls_node_record *rec)
{
	char key[32];

	snprintf(key, sizeof(key), KEY_COORD_NODE_FMT, short_addr);
	return settings_save_one(key, rec, sizeof(*rec));
}


/* --- node --- */

int ls_storage_node_load(uint16_t *short_addr,
			 uint8_t session_key[LS_SESSION_KEY_SIZE],
			 uint32_t *own_fcnt, uint32_t *fcnt_last)
{
	*short_addr = 0;
	*own_fcnt   = 0;
	*fcnt_last  = 0;
	memset(session_key, 0, LS_SESSION_KEY_SIZE);

	node_ctx.addr       = short_addr;
	node_ctx.key        = session_key;
	node_ctx.fcnt       = own_fcnt;
	node_ctx.fcnt_last  = fcnt_last;
	node_ctx.addr_found = false;

	int ret = settings_load_subtree(KEY_NODE_ROOT);

	node_ctx.addr      = NULL;
	node_ctx.key       = NULL;
	node_ctx.fcnt      = NULL;
	node_ctx.fcnt_last = NULL;

	if (ret < 0) {
		return ret;
	}

	return node_ctx.addr_found ? 0 : -ENOENT;
}

int ls_storage_node_save(uint16_t short_addr,
			 const uint8_t session_key[LS_SESSION_KEY_SIZE],
			 uint32_t own_fcnt)
{
	int ret;

	ret = settings_save_one(KEY_NODE_ADDR, &short_addr, sizeof(short_addr));
	if (ret < 0) {
		return ret;
	}

	ret = settings_save_one(KEY_NODE_KEY, session_key, LS_SESSION_KEY_SIZE);
	if (ret < 0) {
		return ret;
	}

	return settings_save_one(KEY_NODE_FCNT, &own_fcnt, sizeof(own_fcnt));
}

int ls_storage_node_save_fcnt(uint32_t own_fcnt)
{
	return settings_save_one(KEY_NODE_FCNT, &own_fcnt, sizeof(own_fcnt));
}

int ls_storage_node_save_fcnt_last(uint32_t fcnt_last)
{
	return settings_save_one(KEY_NODE_FCNT_LAST, &fcnt_last, sizeof(fcnt_last));
}
