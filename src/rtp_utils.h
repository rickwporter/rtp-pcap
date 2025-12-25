/**
 * This file provides some utilities for dealing with RTP and RFC-2833 payloads.
 */
#pragma once

#include "rtp_types.h" // where rtphdr_t and rtp_event_t are defined
#include <arpa/inet.h> // for ntohl() and ntohs()
#include <stdint.h>

#define RFC_1889_VERSION 2

// Just a couple well-know payload types
#define RTP_PT_PCMU 0
#define RTP_PT_PCMA 8
#define RTP_PT_G729 18
#define RTP_PT_RTCP_START 72
#define RTP_PT_RTCP_END 76

static inline uint8_t rtp_hdr_get_version(rtphdr_t *hdr) { return hdr->b.v; }

static inline void rtp_hdr_set_version(rtphdr_t *hdr, uint8_t version) { hdr->b.v = version; }

static inline uint8_t rtp_hdr_get_padding(rtphdr_t *hdr) { return hdr->b.p; }

static inline void rtp_hdr_set_padding(rtphdr_t *hdr, uint8_t padding) { hdr->b.p = padding; }

static inline uint8_t rtp_hdr_get_extension(rtphdr_t *hdr) { return hdr->b.x; }

static inline void rtp_hdr_set_extension(rtphdr_t *hdr, uint8_t extension) { hdr->b.x = extension; }

static inline uint8_t rtp_hdr_get_csrc_count(rtphdr_t *hdr) { return hdr->b.cc; }

static inline void rtp_hdr_set_csrc_count(rtphdr_t *hdr, int count) { hdr->b.cc = count; }

static inline uint8_t rtp_hdr_get_marker(rtphdr_t *hdr) { return hdr->b.m; }

static inline void rtp_hdr_set_marker(rtphdr_t *hdr, uint8_t marker) { hdr->b.m = marker; }

static inline uint8_t rtp_hdr_get_ptype(rtphdr_t *hdr) { return hdr->b.pt; }

static inline void rtp_hdr_set_ptype(rtphdr_t *hdr, uint8_t payload_type) { hdr->b.pt = payload_type; }

static inline uint16_t rtp_hdr_get_sequence(rtphdr_t *hdr) { return ntohs(hdr->b.seqnum); }

static inline void rtp_hdr_set_sequence(rtphdr_t *hdr, uint16_t sequence) { hdr->b.seqnum = htons(sequence); }

static inline uint32_t rtp_hdr_get_timestamp(rtphdr_t *hdr) { return ntohl(hdr->timestamp); }

static inline void rtp_hdr_set_timestamp(rtphdr_t *hdr, uint32_t timestamp) { hdr->timestamp = htonl(timestamp); }

static inline uint32_t rtp_hdr_get_ssrc(rtphdr_t *hdr) { return ntohl(hdr->ssrc); }

static inline void rtp_hdr_set_ssrc(rtphdr_t *hdr, uint32_t ssrc) { hdr->ssrc = htonl(ssrc); }

static inline int rtp_hdr_get_csrc_length(rtphdr_t *hdr) { return sizeof(uint32_t) * rtp_hdr_get_csrc_count(hdr); }

// RTP header extensions come AFTER the Contributing SSRC list, but before
// the "real" RTP payload. The RTP extensions have the following form:
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      defined by profile       |           length              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        header extension                       |
// |                             ....                              |
static inline int rtp_hdr_get_extension_length(rtphdr_t *hdr) {
    if (hdr->b.x == 0) {
        return 0;
    }

    uint8_t *p = (uint8_t *)(hdr + 1);
    p += rtp_hdr_get_csrc_length(hdr);
    p += sizeof(uint16_t);

    // the length field is # of uint32's in the header extension, excluding the
    // 4 octets for the basic header definition
    return 4 * (htons(*(uint16_t *)p) + 1);
}

static inline int rtp_hdr_get_hdr_length(rtphdr_t *hdr) {
    return (sizeof(rtphdr_t) + rtp_hdr_get_csrc_length(hdr) + rtp_hdr_get_extension_length(hdr));
}

static inline void rtp_hdr_init(rtphdr_t *hdr) {
    // set everything to zero, except the version
    memset(hdr, 0, sizeof(*hdr));
    hdr->b.v = RFC_1889_VERSION;
}

static inline void *rtp_hdr_get_payload(rtphdr_t *hdr) {
    void *payload;

    payload = (uint8_t *)hdr + rtp_hdr_get_hdr_length(hdr);
    return payload;
}

static inline int rtp_hdr_is_ptype_rtcp(rtphdr_t *hdr) { return (hdr->b.pt >= RTP_PT_RTCP_START && hdr->b.pt <= RTP_PT_RTCP_END); }

static inline uint8_t rtp_event_get_event(rtp_event_t *event) { return event->event; }

static inline void rtp_event_set_event(rtp_event_t *event, uint8_t id) { event->event = id; }

static inline uint8_t rtp_event_get_end(rtp_event_t *event) { return event->e; }

static inline void rtp_event_set_end(rtp_event_t *event, uint8_t end) { event->e = end; }

static inline uint8_t rtp_event_get_volume(rtp_event_t *event) { return event->volume; }

static inline void rtp_event_set_volume(rtp_event_t *event, uint8_t volume) { event->volume = volume; }

static inline uint16_t rtp_event_get_duration(rtp_event_t *event) { return ntohs(event->duration); }

static inline void rtp_event_set_duration(rtp_event_t *event, uint16_t duration) { event->duration = ntohs(duration); }

static inline void rtp_event_init(rtp_event_t *event) { memset(event, 0, sizeof(*event)); }
