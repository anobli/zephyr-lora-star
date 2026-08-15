zephyr_library()

zephyr_library_sources(
	ls_frame.c
	ls_crypto.c
	ls_storage.c
	ls_common.c
)

zephyr_library_sources_ifdef(CONFIG_LORA_STAR_COORDINATOR ls_coordinator.c)
zephyr_library_sources_ifdef(CONFIG_LORA_STAR_NODE       ls_node.c)
