#include <stdio.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include <lora_star/lora_star.h>

LOG_MODULE_REGISTER(node_sample, LOG_LEVEL_INF);

static const struct gpio_dt_spec pairing_btn =
	GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);

static struct gpio_callback  btn_cb;
static struct k_work         btn_work;
static struct ls_node_ctx   *node;

/* --------------------------------------------------------------------------
 * Application callbacks
 * -------------------------------------------------------------------------- */

static void on_recv(struct ls_node_ctx *ctx, const uint8_t *data, uint8_t len)
{
	LOG_INF("Downlink (%u bytes): %.*s", len, len, data);
}

/* --------------------------------------------------------------------------
 * Periodic uplink thread
 * -------------------------------------------------------------------------- */

static void uplink_thread_fn(void *p1, void *p2, void *p3)
{
	uint32_t counter = 0;
	char     msg[32];

	while (1) {
		k_sleep(K_SECONDS(30));

		int n = snprintf(msg, sizeof(msg), "ping %u", counter++);
		int ret = ls_node_send(node, (const uint8_t *)msg, n);

		if (ret < 0) {
			LOG_WRN("Send failed: %d", ret);
		} else {
			LOG_INF("Sent: %s", msg);
		}
	}
}

K_THREAD_DEFINE(uplink_tid, 1024, uplink_thread_fn,
		NULL, NULL, NULL, 7, 0, 0);

/* --------------------------------------------------------------------------
 * Button handling
 * -------------------------------------------------------------------------- */

static void btn_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	LOG_INF("Pairing button pressed");
	ls_node_start_pairing(node);
}

static void btn_isr(const struct device *dev, struct gpio_callback *cb,
		    uint32_t pins)
{
	k_work_submit(&btn_work);
}

/* --------------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------------- */

int main(void)
{
	const struct device *lora_dev = DEVICE_DT_GET(DT_ALIAS(lora0));

	if (ls_init(lora_dev) < 0) {
		LOG_ERR("ls_init failed");
		return -EIO;
	}

	node = ls_init_node(lora_dev);
	if (!node) {
		LOG_ERR("ls_init_node failed");
		return -EIO;
	}

	ls_node_set_recv_cb(node, on_recv);

	k_work_init(&btn_work, btn_work_handler);

	if (device_is_ready(pairing_btn.port)) {
		gpio_pin_configure_dt(&pairing_btn, GPIO_INPUT);
		gpio_pin_interrupt_configure_dt(&pairing_btn,
						GPIO_INT_EDGE_TO_ACTIVE);
		gpio_init_callback(&btn_cb, btn_isr, BIT(pairing_btn.pin));
		gpio_add_callback(pairing_btn.port, &btn_cb);
	} else {
		LOG_WRN("Pairing button not available");
	}

	LOG_INF("Node ready");
	return 0;
}
