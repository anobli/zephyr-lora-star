#include <errno.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <lora_star/lora_star.h>
#include <lora_star/ls_frame.h>
#include <lora_star/ls_crypto.h>
#include "ls_internal.h"
#include "ls_storage.h"

LOG_MODULE_REGISTER(ls_star, CONFIG_LORA_STAR_LOG_LEVEL);

int ls_append_mic(uint8_t *buf, uint8_t hdr_payload_len, const uint8_t *key)
{
	uint8_t mic[LS_MIC_SIZE];
	int ret = ls_crypto_compute_mic(key,
					buf, LS_HEADER_SIZE,
					buf + LS_HEADER_SIZE,
					hdr_payload_len - LS_HEADER_SIZE,
					mic);
	if (ret < 0) {
		return ret;
	}
	memcpy(buf + hdr_payload_len, mic, LS_MIC_SIZE);
	return 0;
}

int ls_init(const struct device *lora_dev)
{
	if (!device_is_ready(lora_dev)) {
		return -ENODEV;
	}

	if (ls_storage_init() < 0) {
		return -EIO;
	}

	return 0;
}
