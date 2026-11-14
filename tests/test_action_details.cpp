#include "test_harness.h"

int rtp_pcap_packet_get_rtp_payload_length(rtp_pcap_pkt_t *pkt);
bool is_next_rtp_sequence(rtphdr_t *last, rtphdr_t *curr);
void rtp_pcap_details_time_display(
    time_display_t time_type, char *time_display, const size_t display_size, char *time_dspace, const size_t space_size,
    const struct timeval *pkttime, const struct timeval *lastpkt, const struct timeval *firstpkt
);
const char *rtp_pcap_details_analyze(
    char *output, size_t out_size, rtphdr_t *rtph, rtphdr_t *last_rtp, const RtpMap &rtpmap, uint32_t samples_per_packet, uint8_t dtmf_decode,
    uint8_t last_dtmf_event, uint32_t last_dtmf_time
);
const char *rtp_pcap_details_packet_display(
    char *output, size_t out_size, rtphdr_t *rtph, uint32_t index, const char *time_display, const RtpMap &rtpmap, uint8_t dtmf_decode,
    int payload_len
);
const char *rtp_pcap_details_packet_summary(
    char *output, size_t out_size, rtphdr_t *last_rtp, uint32_t n_suppressed, uint32_t index_start, uint32_t index_end, const char *time_display,
    const RtpMap &rtpmap, uint8_t dtmf_decode, uint8_t last_dtmf_event, uint32_t samples_per_packet
);

static std::string analyze_of(uint8_t *current, uint8_t *previous, uint32_t samples, uint8_t dtmf, uint8_t last_event, uint32_t last_time) {
    char output[512];
    RtpMap rtpmap;
    rtp_pcap_details_analyze(
        output,
        sizeof(output),
        reinterpret_cast<rtphdr_t *>(current),
        reinterpret_cast<rtphdr_t *>(previous),
        rtpmap,
        samples,
        dtmf,
        last_event,
        last_time
    );
    return output;
}

static void test_rtp_pcap_packet_get_rtp_payload_length() {
    uint8_t raw[64];
    memset(raw, 0, sizeof(raw));
    rtphdr_t *header = reinterpret_cast<rtphdr_t *>(raw);
    rtp_hdr_init(header);
    rtp_hdr_set_extension(header, 1);
    rtp_hdr_set_csrc_count(header, 1);
    uint16_t *extension = reinterpret_cast<uint16_t *>(raw + sizeof(rtphdr_t) + 4);
    extension[0] = htons(0xbede);
    extension[1] = htons(1);

    udphdr_t udp;
    memset(&udp, 0, sizeof(udp));
    udp.len = static_cast<uint16_t>(sizeof(udp) + rtp_hdr_get_hdr_length(header) + 10);
    rtp_pcap_pkt_t packet;
    memset(&packet, 0, sizeof(packet));
    packet.udph = &udp;
    packet.rtph = header;
    EXPECT(rtp_pcap_packet_get_rtp_payload_length(&packet) == 10);
}

static void test_is_next_rtp_sequence() {
    rtphdr_t previous_header;
    rtphdr_t current_header;
    rtp_hdr_init(&previous_header);
    rtp_hdr_init(&current_header);
    rtp_hdr_set_sequence(&previous_header, 5);
    rtp_hdr_set_sequence(&current_header, 6);
    EXPECT(is_next_rtp_sequence(&previous_header, &current_header));
    rtp_hdr_set_sequence(&current_header, 7);
    EXPECT(!is_next_rtp_sequence(&previous_header, &current_header));
    rtp_hdr_set_sequence(&previous_header, 65535);
    rtp_hdr_set_sequence(&current_header, 0);
    EXPECT(is_next_rtp_sequence(&previous_header, &current_header));
}

static void test_rtp_pcap_details_time_display() {
    char display[64];
    char spaces[64];
    struct timeval packet_time;
    struct timeval last_time;
    struct timeval first_time;
    memset(&packet_time, 0, sizeof(packet_time));
    memset(&last_time, 0, sizeof(last_time));
    memset(&first_time, 0, sizeof(first_time));
    packet_time.tv_sec = 2;
    packet_time.tv_usec = 500000;
    last_time.tv_sec = 1;

    rtp_pcap_details_time_display(tdisp_prevpacket, display, sizeof(display), spaces, sizeof(spaces), &packet_time, &last_time, &first_time);
    EXPECT_STREQ(display, "  1500");
    EXPECT_STREQ(spaces, "   ");

    rtp_pcap_details_time_display(tdisp_startcapture, display, sizeof(display), spaces, sizeof(spaces), &packet_time, &last_time, &first_time);
    EXPECT_STREQ(display, " 2.500");
    EXPECT_STREQ(spaces, "   ");

    packet_time.tv_sec = 0;
    packet_time.tv_usec = 0;
    rtp_pcap_details_time_display(tdisp_timeofday, display, sizeof(display), spaces, sizeof(spaces), &packet_time, &last_time, &first_time);
    EXPECT_STREQ(display, "00:00:00.000 GMT");
    EXPECT(strlen(spaces) == 13);
    rtp_pcap_details_time_display(tdisp_date, display, sizeof(display), spaces, sizeof(spaces), &packet_time, &last_time, &first_time);
    EXPECT_STREQ(display, "1970-01-01 00:00:00.000 GMT");
    EXPECT(strlen(spaces) == 24);
    rtp_pcap_details_time_display(tdisp_none, display, sizeof(display), spaces, sizeof(spaces), &packet_time, &last_time, &first_time);
    EXPECT_STREQ(display, "");
    EXPECT_STREQ(spaces, "");
}

static void test_rtp_pcap_details_analyze() {
    uint8_t current[64];
    uint8_t previous[64];
    fill_rtp(previous, sizeof(previous), 2, 1, 0, 1, 0, 0);
    fill_rtp(current, sizeof(current), 2, 2, 160, 1, 0, 0);
    EXPECT_STREQ(analyze_of(current, previous, 0, 101, 255, 0).c_str(), "");

    fill_rtp(current, sizeof(current), 1, 2, 160, 1, 0, 0);
    EXPECT_STREQ(analyze_of(current, previous, 0, 101, 255, 0).c_str(), "***** Invalid RTP version=1 ******\n");
    fill_rtp(previous, sizeof(previous), 1, 1, 0, 1, 0, 0);
    EXPECT_STREQ(analyze_of(current, previous, 0, 101, 255, 0).c_str(), "");

    fill_rtp(previous, sizeof(previous), 2, 1, 0, 1, 0, 0);
    fill_rtp(current, sizeof(current), 2, 2, 160, 2, 0, 0);
    EXPECT_STREQ(analyze_of(current, previous, 0, 101, 255, 0).c_str(), "***** SSRC changed from 1 to 2 ******\n");

    fill_rtp(current, sizeof(current), 2, 2, 160, 1, 8, 0);
    EXPECT_STREQ(analyze_of(current, previous, 0, 101, 255, 0).c_str(), "***** Codec type change from pcmu(0) to pcma(8) ******\n");
    fill_rtp(current, sizeof(current), 2, 8, 160, 1, 8, 0);
    EXPECT_STREQ(analyze_of(current, previous, 0, 101, 255, 0).c_str(), "***** Codec type change from pcmu(0), seq=1 to pcma(8), seq=8 ******\n");

    fill_rtp(current, sizeof(current), 2, 4, 160, 1, 0, 0);
    EXPECT_STREQ(analyze_of(current, previous, 0, 101, 255, 0).c_str(), "***** Missed 2 sequence numbers ******\n");
    fill_rtp(previous, sizeof(previous), 2, 10, 0, 1, 0, 0);
    fill_rtp(current, sizeof(current), 2, 8, 160, 1, 0, 0);
    EXPECT_STREQ(analyze_of(current, previous, 0, 101, 255, 0).c_str(), "***** Out of order RTP sequence number: back 2 ******\n");
    fill_rtp(previous, sizeof(previous), 2, 1, 0, 1, 0, 0);
    fill_rtp(current, sizeof(current), 2, 100, 160, 1, 0, 0);
    EXPECT_STREQ(analyze_of(current, previous, 0, 101, 255, 0).c_str(), "***** Sequence number jump: last=1, curr=100 ******\n");

    fill_rtp(previous, sizeof(previous), 2, 1, 1000, 1, 101, 0);
    fill_rtp(current, sizeof(current), 2, 2, 2000, 1, 101, 0);
    rtp_event_t *event = reinterpret_cast<rtp_event_t *>(current + sizeof(rtphdr_t));
    rtp_event_init(event);
    rtp_event_set_event(event, 7);
    EXPECT_STREQ(
        analyze_of(current, previous, 0, 101, 5, 1000).c_str(), "***** New DTMF event: old id=5, timestamp=1000; new id=2000, timestamp=7 ******\n"
    );

    fill_rtp(previous, sizeof(previous), 2, 1, 0, 1, 0, 0);
    fill_rtp(current, sizeof(current), 2, 2, 800, 1, 0, 1);
    EXPECT_STREQ(analyze_of(current, previous, 160, 101, 255, 0).c_str(), "***** Marked silence gap of 640 samples ******\n");
    fill_rtp(current, sizeof(current), 2, 2, 800, 1, 0, 0);
    EXPECT_STREQ(
        analyze_of(current, previous, 160, 101, 255, 0).c_str(),
        "***** Timestamp discontinuity (possible silence): old(0) + expected(160) != new(800) ******\n"
    );
}

static void test_rtp_pcap_details_packet_display() {
    uint8_t current[64];
    char output[512];
    RtpMap rtpmap;
    fill_rtp(current, sizeof(current), 1, 2, 160, 1, 0, 0);
    rtp_pcap_details_packet_display(output, sizeof(output), reinterpret_cast<rtphdr_t *>(current), 4, "T", rtpmap, 101, 20);
    EXPECT_STREQ(output, "     4 T RTP Invalid: version=1\n");

    fill_rtp(current, sizeof(current), 2, 5, 160, 0x10, 0, 1);
    rtp_pcap_details_packet_display(output, sizeof(output), reinterpret_cast<rtphdr_t *>(current), 7, "X", rtpmap, 101, 20);
    EXPECT_STREQ(output, "     7 X Payload type=pcmu(0), SSRC=0x00000010, Seq=5, Time=160, Mark, payload bytes=20\n");
    fill_rtp(current, sizeof(current), 2, 5, 160, 0x10, 0, 0);
    rtp_pcap_details_packet_display(output, sizeof(output), reinterpret_cast<rtphdr_t *>(current), 7, "X", rtpmap, 101, 20);
    EXPECT_STREQ(output, "     7 X Payload type=pcmu(0), SSRC=0x00000010, Seq=5, Time=160, payload bytes=20\n");

    fill_rtp(current, sizeof(current), 2, 9, 50, 0x10, 101, 0);
    rtp_event_t *event = reinterpret_cast<rtp_event_t *>(current + sizeof(rtphdr_t));
    rtp_event_init(event);
    rtp_event_set_event(event, 7);
    rtp_event_set_duration(event, 960);
    rtp_event_set_end(event, 1);
    rtp_pcap_details_packet_display(output, sizeof(output), reinterpret_cast<rtphdr_t *>(current), 3, "X", rtpmap, 101, 4);
    EXPECT_STREQ(output, "     3 X Payload type=telephone-events(101), SSRC=0x00000010, Seq=9, Time=50, DTMF id=7, duration=960 (end)\n");
    rtp_event_set_end(event, 0);
    rtp_pcap_details_packet_display(output, sizeof(output), reinterpret_cast<rtphdr_t *>(current), 3, "X", rtpmap, 101, 4);
    EXPECT_STREQ(output, "     3 X Payload type=telephone-events(101), SSRC=0x00000010, Seq=9, Time=50, DTMF id=7, duration=960\n");
}

static void test_rtp_pcap_details_packet_summary() {
    uint8_t previous[64];
    char output[512];
    RtpMap rtpmap;
    fill_rtp(previous, sizeof(previous), 2, 20, 0, 0x10, 0, 0);
    rtp_pcap_details_packet_summary(output, sizeof(output), reinterpret_cast<rtphdr_t *>(previous), 5, 10, 14, "", rtpmap, 101, 7, 160);
    EXPECT_STREQ(output, "    10-14  Payload type=pcmu(0), SSRC=0x00000010, Seq=16-19, Time=160 samples/pkt\n");
    fill_rtp(previous, sizeof(previous), 2, 20, 0, 0x10, 101, 0);
    rtp_pcap_details_packet_summary(output, sizeof(output), reinterpret_cast<rtphdr_t *>(previous), 5, 10, 14, "", rtpmap, 101, 7, 160);
    EXPECT_STREQ(output, "    10-14  Payload type=telephone-events(101), SSRC=0x00000010, Seq=16-19, DTMF id=7\n");
    fill_rtp(previous, sizeof(previous), 2, 1, 0, 0x10, 0, 0);
    rtp_pcap_details_packet_summary(output, sizeof(output), reinterpret_cast<rtphdr_t *>(previous), 3, 1, 3, "", rtpmap, 101, 0, 160);
    EXPECT_STREQ(output, "     1-3  Payload type=pcmu(0), SSRC=0x00000010, Seq=65535-0, Time=160 samples/pkt\n");
}

static void test_rtp_pcap_details() {
    std::vector<std::vector<uint8_t>> stream;
    stream.push_back(make_rtp(0, 1, 0, 0x99, 0, 0, std::vector<uint8_t>(4, 0)));
    stream.push_back(voice_packet(1, 0, 0, 1));
    stream.push_back(voice_packet(2, 160, 0, 0));
    stream.push_back(voice_packet(3, 320, 0, 0));
    stream.push_back(voice_packet(4, 480, 8, 0));

    rtp_event_t event;
    rtp_event_init(&event);
    rtp_event_set_event(&event, 5);
    rtp_event_set_duration(&event, 160);
    std::vector<uint8_t> tone(sizeof(event));
    memcpy(&(tone[0]), &event, sizeof(event));
    stream.push_back(make_rtp(RFC_1889_VERSION, 5, 800, 0x99, 101, 0, tone));

    CmdResult details = run_cli({"details", write_rtp_capture("details-analysis.pcap", stream, 4002, 4000)});
    EXPECT(details.code == 0);
    EXPECT_CONTAINS(details.output, "Codec type change from pcmu(0) to pcma(8)");
    EXPECT_CONTAINS(details.output, "samples/pkt");
    EXPECT_CONTAINS(details.output, "DTMF id=5");
}

static void test_add_details_command() {
    std::vector<std::vector<uint8_t>> stream;
    stream.push_back(voice_packet(1, 0, 0, 1));
    stream.push_back(voice_packet(2, 160, 0, 0));
    std::string stream_path = write_rtp_capture("details-stream.pcap", stream, 4002, 4000);
    CmdResult details = run_cli({"details", stream_path, "--filter", "src"});
    EXPECT(details.code == 0);
    EXPECT_CONTAINS(details.output, "Payload type=pcmu(0)");

    CmdResult missing = run_cli({"details", g_tmpdir + "/no-such-details.pcap"});
    EXPECT(missing.code == -2);
    EXPECT_CONTAINS(missing.output, "missing file=");

    std::string bad_path = g_tmpdir + "/bad-details.pcap";
    FILE *bad = fopen(bad_path.c_str(), "w");
    fputs("not pcap", bad);
    fclose(bad);
    CmdResult bad_details = run_cli({"details", bad_path});
    EXPECT(bad_details.code == -2);
    EXPECT_CONTAINS(bad_details.output, "failed to open PCAP=");
}

void test_action_details() {
    test_rtp_pcap_packet_get_rtp_payload_length();
    test_is_next_rtp_sequence();
    test_rtp_pcap_details_time_display();
    test_rtp_pcap_details_analyze();
    test_rtp_pcap_details_packet_display();
    test_rtp_pcap_details_packet_summary();
    test_rtp_pcap_details();
    test_add_details_command();
}
