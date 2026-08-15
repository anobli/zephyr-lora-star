#include <string.h>
#include <errno.h>
#include <zephyr/sys/byteorder.h>
#include <lora_star/ls_frame.h>

int ls_frame_encode(uint8_t *buf, size_t buf_size,
		    const struct ls_frame_hdr *hdr,
		    const uint8_t *payload, uint8_t payload_len)
{
	size_t total = LS_HEADER_SIZE + payload_len + LS_MIC_SIZE;

	if (buf_size < total) {
		return -ENOMEM;
	}

	buf[0] = hdr->type;
	sys_put_le16(hdr->src,  &buf[1]);
	sys_put_le16(hdr->dst,  &buf[3]);
	sys_put_le32(hdr->fcnt, &buf[5]);
	buf[9] = hdr->flags;

	if (payload_len > 0) {
		memcpy(&buf[LS_HEADER_SIZE], payload, payload_len);
	}

	/* Caller fills the 4-byte MIC slot at buf[LS_HEADER_SIZE + payload_len] */
	memset(&buf[LS_HEADER_SIZE + payload_len], 0, LS_MIC_SIZE);

	return (int)(LS_HEADER_SIZE + payload_len);
}

int ls_frame_decode(const uint8_t *buf, size_t buf_len,
		    struct ls_frame_hdr *hdr,
		    const uint8_t **payload, uint8_t *payload_len,
		    const uint8_t **mic)
{
	uint8_t plen;

	if (buf_len < LS_OVERHEAD_SIZE) {
		return -EINVAL;
	}

	hdr->type  = buf[0];
	hdr->src   = sys_get_le16(&buf[1]);
	hdr->dst   = sys_get_le16(&buf[3]);
	hdr->fcnt  = sys_get_le32(&buf[5]);
	hdr->flags = buf[9];

	plen = buf_len - LS_OVERHEAD_SIZE;

	*payload     = (plen > 0) ? &buf[LS_HEADER_SIZE] : NULL;
	*payload_len = plen;
	*mic         = &buf[LS_HEADER_SIZE + plen];

	return 0;
}
