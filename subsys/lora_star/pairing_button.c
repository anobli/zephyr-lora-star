/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT zephyr_ls_pairing_button

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/logging/log.h>

#include <lora_star/lora_star.h>
#include <lora_star/pairing.h>
#include <lora_star/pairing_button.h>

LOG_MODULE_REGISTER(ls_pairing_button, CONFIG_LORA_STAR_LOG_LEVEL);

BUILD_ASSERT(DT_NUM_INST_STATUS_OKAY(DT_DRV_COMPAT) <= 1,
	    "Only one lora_star,pairing-button node is supported");



struct ls_pairing_button_config {
	const struct gpio_dt_spec btn;
};

struct ls_pairing_button_data {
	struct gpio_callback btn_cb;
	struct k_work pairing_work;
};

/* --------------------------------------------------------------------------
 * Coordinator path
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LORA_STAR_COORDINATOR

static struct ls_coord_pairing_ctx coord_pair_ctx;
static bool                        coord_pair_ready;
static ls_pairing_join_cb          coord_join_cb;
static void                       *coord_join_cb_ud;

void ls_pairing_button_set_join_cb(ls_pairing_join_cb cb, void *user_data)
{
	coord_join_cb    = cb;
	coord_join_cb_ud = user_data;
}

static void coord_pairing_trigger(struct ls_ctx *ctx)
{
	int ret;

	if (!coord_pair_ready) {
		ret = ls_pairing_coord_init(ctx, &coord_pair_ctx, coord_join_cb, coord_join_cb_ud);
		if (ret < 0) {
			LOG_ERR("ls_pairing_coord_init failed: %d", ret);
			return;
		}
		coord_pair_ready = true;
	}

	LOG_INF("Pairing button pressed — opening pairing window");
	ret = ls_pairing_coord_start(&coord_pair_ctx);
	if (ret < 0) {
		LOG_WRN("Failed to open pairing window: %d", ret);
	}
}

#endif /* CONFIG_LORA_STAR_COORDINATOR */

/* --------------------------------------------------------------------------
 * Node path
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LORA_STAR_NODE

static struct ls_node_pairing_ctx node_pair_ctx;
static ls_pairing_node_done_cb    node_done_cb;
static void                      *node_done_cb_ud;

void ls_pairing_button_set_done_cb(ls_pairing_node_done_cb cb, void *user_data)
{
	node_done_cb    = cb;
	node_done_cb_ud = user_data;
}

static void node_pairing_trigger(struct ls_ctx *ctx)
{
	int ret;

	hwinfo_get_device_id(node_pair_ctx.dev_eui, LS_DEV_EUI_SIZE);
	node_pair_ctx.done_cb        = node_done_cb;
	node_pair_ctx.done_user_data = node_done_cb_ud;

	LOG_INF("Pairing button pressed — starting pairing");
	ret = ls_pairing_node_start(ctx, &node_pair_ctx);
	if (ret < 0) {
		LOG_WRN("Failed to start pairing: %d", ret);
	}
}

#endif /* CONFIG_LORA_STAR_NODE */

/* --------------------------------------------------------------------------
 * Role dispatch
 * -------------------------------------------------------------------------- */

#if defined(CONFIG_LORA_STAR_COORDINATOR) && defined(CONFIG_LORA_STAR_NODE)

static bool dual_role_set;
static bool dual_role_is_coord;

void ls_pairing_button_set_role(bool is_coordinator)
{
	dual_role_set      = true;
	dual_role_is_coord = is_coordinator;
}

static void pairing_work_handler(struct k_work *work)
{
	struct ls_ctx *ctx = ls_get_ctx();

	ARG_UNUSED(work);

	if (!dual_role_set) {
		LOG_WRN("Role not set — call ls_pairing_button_set_role() first; "
			"defaulting to node");
	}

	if (dual_role_is_coord) {
		coord_pairing_trigger(ctx);
	} else {
		node_pairing_trigger(ctx);
	}
}

#elif defined(CONFIG_LORA_STAR_COORDINATOR)

static void pairing_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	coord_pairing_trigger(ls_get_ctx());
}

#elif defined(CONFIG_LORA_STAR_NODE)

static void pairing_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	node_pairing_trigger(ls_get_ctx());
}

#endif

/* --------------------------------------------------------------------------
 * GPIO wiring
 * -------------------------------------------------------------------------- */

static void btn_isr(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	struct ls_pairing_button_data *data;

	data = CONTAINER_OF(cb, struct ls_pairing_button_data, btn_cb);

	k_work_submit(&data->pairing_work);
}

static int ls_pairing_button_init(const struct device *dev)
{
	const struct ls_pairing_button_config *cfg = dev->config;
	struct ls_pairing_button_data *data = dev->data;
	int ret;

	if (!gpio_is_ready_dt(&cfg->btn)) {
		LOG_ERR("Pairing button GPIO not ready");
		return -ENODEV;
	}

	k_work_init(&data->pairing_work, pairing_work_handler);

	ret = gpio_pin_configure_dt(&cfg->btn, GPIO_INPUT);
	if (ret < 0) {
		LOG_ERR("Failed to configure pairing button: %d", ret);
		return ret;
	}

	ret = gpio_pin_interrupt_configure_dt(&cfg->btn, GPIO_INT_EDGE_TO_ACTIVE);
	if (ret < 0) {
		LOG_ERR("Failed to configure pairing button interrupt: %d", ret);
		return ret;
	}

	gpio_init_callback(&data->btn_cb, btn_isr, BIT(cfg->btn.pin));
	gpio_add_callback(cfg->btn.port, &data->btn_cb);

	LOG_INF("Pairing button ready");
	return 0;
}

#define LS_PAIRING_BUTTON_DEVICE_INIT(inst)                                             \
	static struct ls_pairing_button_data ls_pairing_button_data##inst;              \
	static const struct ls_pairing_button_config ls_pairing_button_config##inst = { \
		.btn = GPIO_DT_SPEC_INST_GET(inst, gpios),                              \
	};                                                                              \
	DEVICE_DT_INST_DEFINE(inst, ls_pairing_button_init, NULL,                       \
			      &ls_pairing_button_data##inst,                            \
			      &ls_pairing_button_config##inst,                          \
			      POST_KERNEL, CONFIG_LORA_INIT_PRIORITY,                   \
			      NULL);

DT_INST_FOREACH_STATUS_OKAY(LS_PAIRING_BUTTON_DEVICE_INIT)
