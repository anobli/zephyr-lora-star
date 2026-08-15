#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include <lora_star/lora_star.h>

LOG_MODULE_REGISTER(coord_sample, LOG_LEVEL_INF);

static const struct gpio_dt_spec pairing_btn =
	GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);

static struct gpio_callback      btn_cb;
static struct k_work             btn_work;
static struct ls_coord_ctx      *coord;

/* --------------------------------------------------------------------------
 * Application callbacks
 * -------------------------------------------------------------------------- */

static void on_join(struct ls_coord_ctx *ctx, uint16_t short_addr,
		    const uint8_t *dev_eui)
{
	LOG_INF("New node: addr=0x%04x EUI=%02x%02x%02x%02x%02x%02x%02x%02x",
		short_addr,
		dev_eui[0], dev_eui[1], dev_eui[2], dev_eui[3],
		dev_eui[4], dev_eui[5], dev_eui[6], dev_eui[7]);
}

static void on_recv(struct ls_coord_ctx *ctx, uint16_t short_addr,
		    const uint8_t *data, uint8_t len)
{
	LOG_INF("Uplink from 0x%04x (%u bytes): %.*s",
		short_addr, len, len, data);

	const char ack_msg[] = "ok";

	ls_coord_send(ctx, short_addr,
		      (const uint8_t *)ack_msg, sizeof(ack_msg) - 1);
}

/* --------------------------------------------------------------------------
 * Button handling
 * -------------------------------------------------------------------------- */

static void btn_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	LOG_INF("Pairing button pressed — opening pairing window");
	ls_coord_start_pairing(coord);
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

	coord = ls_init_coordinator(lora_dev);
	if (!coord) {
		LOG_ERR("ls_init_coordinator failed");
		return -EIO;
	}

	ls_coord_set_join_cb(coord, on_join);
	ls_coord_set_recv_cb(coord, on_recv);

	k_work_init(&btn_work, btn_work_handler);

	if (device_is_ready(pairing_btn.port)) {
		gpio_pin_configure_dt(&pairing_btn, GPIO_INPUT);
		gpio_pin_interrupt_configure_dt(&pairing_btn,
						GPIO_INT_EDGE_TO_ACTIVE);
		gpio_init_callback(&btn_cb, btn_isr,
				   BIT(pairing_btn.pin));
		gpio_add_callback(pairing_btn.port, &btn_cb);
	} else {
		LOG_WRN("Pairing button not available");
	}

	LOG_INF("Coordinator ready");
	return 0;
}
