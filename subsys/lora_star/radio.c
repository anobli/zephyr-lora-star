#include <errno.h>
#include <lora_star/radio.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ls_radio, CONFIG_LORA_STAR_LOG_LEVEL);

static struct lora_modem_config radio_rx_cfg = {
	.frequency    = CONFIG_LORA_STAR_FREQUENCY,
	.bandwidth    = BW_125_KHZ,
	.datarate     = SF_7,
	.coding_rate  = CR_4_5,
	.preamble_len = 8,
	.tx_power     = CONFIG_LORA_STAR_TX_POWER_DBM,
	.tx           = false,
};

static struct lora_modem_config radio_tx_cfg = {
	.frequency    = CONFIG_LORA_STAR_FREQUENCY,
	.bandwidth    = BW_125_KHZ,
	.datarate     = SF_7,
	.coding_rate  = CR_4_5,
	.preamble_len = 8,
	.tx_power     = CONFIG_LORA_STAR_TX_POWER_DBM,
	.tx           = true,
};

int ls_radio_init(const struct device *lora_dev)
{
	int ret;

	ret = lora_config(lora_dev, &radio_tx_cfg);
	if (ret) {
                LOG_ERR("Failed to config radio: %d", ret);
                return -EIO;
	}

	return 0;
}

int ls_radio_tx(const struct device *lora_dev, uint8_t *data, size_t len)
{
	int ret;

	ret = lora_config(lora_dev, &radio_tx_cfg);
	if (ret) {
                LOG_ERR("TX config failed: %d", ret);
                return -EIO;
	}

	ret = lora_send(lora_dev, data, len);
        if (ret != 0) {
                LOG_ERR("lora_send failed: %d", ret);
                return -EIO;
        }

	return 0;
}

int ls_radio_rx_start(const struct device *lora_dev, lora_recv_cb rx_cb, void *user_data)
{
	int ret;

	if (rx_cb == NULL) {
		return -EINVAL;
	}

	ret = lora_config(lora_dev, &radio_rx_cfg);
	if (ret) {
                LOG_ERR("RX config failed: %d", ret);
                return -EIO;
	}

	return lora_recv_async(lora_dev, rx_cb, user_data);
}

int ls_radio_rx_stop(const struct device *lora_dev)
{
	return lora_recv_async(lora_dev, NULL, NULL);
}

uint32_t ls_radio_airtime_ms(const struct device *lora_dev, size_t frame_len)
{
	return lora_airtime(lora_dev, (uint32_t)frame_len);
}
