#include "test_harness.h"

static void test_rtp_hdr_init() {
    uint8_t raw[64];
    memset(raw, 0, sizeof(raw));
    rtphdr_t *header = reinterpret_cast<rtphdr_t *>(raw);
    rtp_hdr_init(header);
    EXPECT(rtp_hdr_get_version(header) == RFC_1889_VERSION);
    EXPECT(rtp_hdr_get_padding(header) == 0);
    EXPECT(rtp_hdr_get_marker(header) == 0);
    EXPECT(rtp_hdr_get_extension(header) == 0);
    EXPECT(rtp_hdr_get_csrc_count(header) == 0);
}

static void test_rtp_hdr_fields() {
    uint8_t raw[64];
    memset(raw, 0, sizeof(raw));
    rtphdr_t *header = reinterpret_cast<rtphdr_t *>(raw);
    rtp_hdr_init(header);

    rtp_hdr_set_padding(header, 1);
    rtp_hdr_set_marker(header, 1);
    rtp_hdr_set_ptype(header, RTP_PT_PCMA);
    rtp_hdr_set_sequence(header, 0xffff);
    rtp_hdr_set_timestamp(header, 0x01020304);
    rtp_hdr_set_ssrc(header, 0x11223344);
    EXPECT(rtp_hdr_get_padding(header) == 1);
    EXPECT(rtp_hdr_get_marker(header) == 1);
    EXPECT(rtp_hdr_get_ptype(header) == RTP_PT_PCMA);
    EXPECT(rtp_hdr_get_sequence(header) == 0xffff);
    EXPECT(rtp_hdr_get_timestamp(header) == 0x01020304);
    EXPECT(rtp_hdr_get_ssrc(header) == 0x11223344);
}

static void test_rtp_hdr_is_ptype_rtcp() {
    uint8_t raw[64];
    memset(raw, 0, sizeof(raw));
    rtphdr_t *header = reinterpret_cast<rtphdr_t *>(raw);
    rtp_hdr_init(header);

    rtp_hdr_set_ptype(header, RTP_PT_PCMA);
    EXPECT(rtp_hdr_is_ptype_rtcp(header) == 0);
    rtp_hdr_set_ptype(header, RTP_PT_RTCP_START);
    EXPECT(rtp_hdr_is_ptype_rtcp(header) == 1);
    rtp_hdr_set_ptype(header, RTP_PT_RTCP_END);
    EXPECT(rtp_hdr_is_ptype_rtcp(header) == 1);
    rtp_hdr_set_ptype(header, RTP_PT_RTCP_START - 1);
    EXPECT(rtp_hdr_is_ptype_rtcp(header) == 0);
    rtp_hdr_set_ptype(header, RTP_PT_RTCP_END + 1);
    EXPECT(rtp_hdr_is_ptype_rtcp(header) == 0);
}

static void test_rtp_hdr_get_extension_length() {
    uint8_t raw[64];
    memset(raw, 0, sizeof(raw));
    rtphdr_t *header = reinterpret_cast<rtphdr_t *>(raw);
    rtp_hdr_init(header);
    EXPECT(rtp_hdr_get_extension_length(header) == 0);
    EXPECT(rtp_hdr_get_hdr_length(header) == static_cast<int>(sizeof(rtphdr_t)));

    rtp_hdr_set_extension(header, 1);
    rtp_hdr_set_csrc_count(header, 1);
    uint16_t *extension = reinterpret_cast<uint16_t *>(raw + sizeof(rtphdr_t) + 4);
    extension[0] = htons(0xbede);
    extension[1] = htons(1);
    EXPECT(rtp_hdr_get_csrc_length(header) == 4);
    EXPECT(rtp_hdr_get_extension_length(header) == 8);
    EXPECT(rtp_hdr_get_hdr_length(header) == static_cast<int>(sizeof(rtphdr_t)) + 12);
    EXPECT(static_cast<uint8_t *>(rtp_hdr_get_payload(header)) == raw + sizeof(rtphdr_t) + 12);
}

static void test_rtp_event() {
    rtp_event_t event;
    rtp_event_init(&event);
    rtp_event_set_event(&event, 7);
    rtp_event_set_end(&event, 1);
    rtp_event_set_volume(&event, 10);
    rtp_event_set_duration(&event, 960);
    EXPECT(rtp_event_get_event(&event) == 7);
    EXPECT(rtp_event_get_end(&event) == 1);
    EXPECT(rtp_event_get_volume(&event) == 10);
    EXPECT(rtp_event_get_duration(&event) == 960);
}

void test_rtp_utils() {
    test_rtp_hdr_init();
    test_rtp_hdr_fields();
    test_rtp_hdr_is_ptype_rtcp();
    test_rtp_hdr_get_extension_length();
    test_rtp_event();
}
