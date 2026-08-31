/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/lora_fake.h>
#include <lora_star/radio.h>

static void radio_before(void *fixture)
{
	ARG_UNUSED(fixture);
	lora_fake_reset();
}

/* --------------------------------------------------------------------------
 * ls_radio_init
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_radio, test_ls_radio_init)
{
	const struct device *dev;
	int ret;

	dev = lora_fake_get_device();
	ret = ls_radio_init(dev);

	zassert_equal(ret, 0);
	zassert_equal(lora_fake_config_fake.call_count, 1);
	zassert_true(lora_fake_config_fake.arg1_val->tx);
}

ZTEST(lora_star_radio, test_ls_radio_init_propagates_error)
{
	const struct device *dev;
	int ret;

	dev = lora_fake_get_device();
	lora_fake_config_fake.return_val = -EIO;
	ret = ls_radio_init(dev);

	zassert_equal(ret, -EIO);
}

/* --------------------------------------------------------------------------
 * ls_radio_tx
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_radio, test_ls_radio_tx)
{
	const struct device *dev;
	uint8_t data[] = {0x33, 0x45, 0x56, 0x32};
	const uint8_t *sent_data;
	uint32_t sent_data_len;
	int ret;

	dev = lora_fake_get_device();
	ret = ls_radio_tx(dev, data, sizeof(data));
	sent_data = lora_fake_get_sent_data(&sent_data_len);

	zassert_equal(ret, 0);
	zassert_equal(sent_data_len, sizeof(data));
	zassert_mem_equal(sent_data, data, sizeof(data));
}

ZTEST(lora_star_radio, test_ls_radio_tx_configures_tx_mode)
{
	const struct device *dev;
	uint8_t data[] = {0x01};

	dev = lora_fake_get_device();
	ls_radio_tx(dev, data, sizeof(data));

	zassert_true(lora_fake_config_fake.arg1_val->tx);
}

ZTEST(lora_star_radio, test_ls_radio_tx_propagates_config_error)
{
	const struct device *dev;
	uint8_t data[] = {0x01};
	int ret;

	dev = lora_fake_get_device();
	lora_fake_config_fake.return_val = -EIO;
	ret = ls_radio_tx(dev, data, sizeof(data));

	zassert_equal(ret, -EIO);
}

ZTEST(lora_star_radio, test_ls_radio_tx_propagates_send_error)
{
	const struct device *dev;
	uint8_t data[] = {0x01};
	int ret;

	dev = lora_fake_get_device();
	lora_fake_send_fake.custom_fake = NULL;
	lora_fake_send_fake.return_val = -EIO;
	ret = ls_radio_tx(dev, data, sizeof(data));

	zassert_equal(ret, -EIO);
}

/* --------------------------------------------------------------------------
 * ls_radio_rx_start / ls_radio_rx_stop
 * -------------------------------------------------------------------------- */

static void rx_cb(const struct device *dev, uint8_t *data, uint16_t size,
		  int16_t rssi, int8_t snr, void *user_data)
{
	int *count = user_data;

	ARG_UNUSED(dev);
	ARG_UNUSED(data);
	ARG_UNUSED(size);
	ARG_UNUSED(rssi);
	ARG_UNUSED(snr);
	*count += 1;
}

ZTEST(lora_star_radio, test_ls_radio_rx_null_callback)
{
	const struct device *dev;
	int ret;

	dev = lora_fake_get_device();
	ret = ls_radio_rx_start(dev, NULL, NULL);

	zassert_equal(ret, -EINVAL);
}

ZTEST(lora_star_radio, test_ls_radio_rx_start)
{
	const struct device *dev;
	int count = 0;
	int ret;

	dev = lora_fake_get_device();
	ret = ls_radio_rx_start(dev, rx_cb, &count);

	zassert_equal(ret, 0);
	zassert_equal(lora_fake_recv_async_fake.call_count, 1);
	zassert_false(lora_fake_config_fake.arg1_val->tx);
}

ZTEST(lora_star_radio, test_ls_radio_rx_start_propagates_config_error)
{
	const struct device *dev;
	int count = 0;
	int ret;

	dev = lora_fake_get_device();
	lora_fake_config_fake.return_val = -EIO;
	ret = ls_radio_rx_start(dev, rx_cb, &count);

	zassert_equal(ret, -EIO);
}

ZTEST(lora_star_radio, test_ls_radio_rx_callback_invoked)
{
	const struct device *dev;
	uint8_t data[] = {0x33, 0x45, 0x56, 0x32};
	int count = 0;

	dev = lora_fake_get_device();
	ls_radio_rx_start(dev, rx_cb, &count);
	lora_fake_set_recv_data(data, sizeof(data), -70, 5);
	lora_fake_trigger_recv_async();

	zassert_equal(count, 1);
}

ZTEST(lora_star_radio, test_ls_radio_rx_stop)
{
	const struct device *dev;
	uint8_t data[] = {0x33, 0x45, 0x56, 0x32};
	int count = 0;

	dev = lora_fake_get_device();
	ls_radio_rx_start(dev, rx_cb, &count);
	ls_radio_rx_stop(dev);
	lora_fake_set_recv_data(data, sizeof(data), -70, 5);
	lora_fake_trigger_recv_async();

	zassert_equal(count, 0);
}

/* --------------------------------------------------------------------------
 * ls_radio_airtime_ms
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_radio, test_ls_radio_airtime_ms)
{
	const struct device *dev;
	uint32_t airtime;

	dev = lora_fake_get_device();
	lora_fake_airtime_fake.return_val = 42;
	airtime = ls_radio_airtime_ms(dev, 128);

	zassert_equal(airtime, 42);
	zassert_equal(lora_fake_airtime_fake.arg1_val, 128);
}

ZTEST_SUITE(lora_star_radio, NULL, NULL, radio_before, NULL, NULL);
