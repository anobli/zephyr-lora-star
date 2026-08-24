zephyr_library()

zephyr_library_sources(
	radio.c
	mac.c
	frame.c
	crypto.c
	lora_star.c
	storage.c
)

zephyr_library_sources_ifdef(CONFIG_LORA_STAR_PAIRING pairing.c)