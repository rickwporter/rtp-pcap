#include "test_harness.h"

static void test_RtpMap_get_string() {
    RtpMap rtpmap;
    EXPECT_STREQ(rtpmap.get_string(0), "pcmu");
    EXPECT_STREQ(rtpmap.get_string(99), "unknown");
}

static void test_RtpMap_parse() {
    RtpMap rtpmap;
    rtpmap.parse(NULL);
    EXPECT_STREQ(rtpmap.get_string(0), "pcmu");
    rtpmap.parse("no-equals");
    rtpmap.parse("99=opus:101=telephone-events");
    EXPECT_STREQ(rtpmap.get_string(99), "opus");
    EXPECT_STREQ(rtpmap.get_string(101), "telephone-events");
    rtpmap.parse("8=");
    EXPECT_STREQ(rtpmap.get_string(8), "");
    rtpmap.parse("not-a-number=renamed");
    EXPECT_STREQ(rtpmap.get_string(0), "renamed");
}

static void test_rtp_pcap_time_display_parse() {
    EXPECT(rtp_pcap_time_display_parse("previous") == tdisp_prevpacket);
    EXPECT(rtp_pcap_time_display_parse("capture") == tdisp_startcapture);
    EXPECT(rtp_pcap_time_display_parse("timeofday") == tdisp_timeofday);
    EXPECT(rtp_pcap_time_display_parse("date") == tdisp_date);
    EXPECT(rtp_pcap_time_display_parse("none") == tdisp_none);
    EXPECT(rtp_pcap_time_display_parse("other") == tdisp_none);
}

static void test_CommonArgs_init_filter() {
    CommonArgs args;
    args.filter = "src";
    args.addr = "10.1.2.3";
    args.port = "5004";
    rtp_pcap_filter_t filter;
    args.init_filter(filter);
    EXPECT(filter.flags & FILTER_FLAG_SRC_FILTER);
    EXPECT(filter.flags & FILTER_FLAG_SADDR_SET);
    EXPECT(filter.flags & FILTER_FLAG_SPORT_SET);
    EXPECT(filter.saddr == inet_network("10.1.2.3"));
    EXPECT(filter.sport == 5004);

    args.filter = "dst";
    args.addr = "10.9.8.7";
    args.port = "9";
    args.init_filter(filter);
    EXPECT(filter.flags & FILTER_FLAG_DST_FILTER);
    EXPECT(filter.flags & FILTER_FLAG_DADDR_SET);
    EXPECT(filter.flags & FILTER_FLAG_DPORT_SET);
    EXPECT(filter.daddr == inet_network("10.9.8.7"));
    EXPECT(filter.dport == 9);

    args.addr.clear();
    args.port.clear();
    args.init_filter(filter);
    EXPECT(filter.flags == FILTER_FLAG_DST_FILTER);
    EXPECT(filter.daddr == 0);
    EXPECT(filter.dport == 0);
}

static void test_CommonArgs_create_rtpmap() {
    CommonArgs args;
    args.rtpmap_values.push_back("99=l16");
    args.rtpmap_values.push_back("100=opus");
    RtpMap created = args.create_rtpmap();
    EXPECT_STREQ(created.get_string(99), "l16");
    EXPECT_STREQ(created.get_string(100), "opus");
    EXPECT_STREQ(created.get_string(0), "pcmu");
}

void test_arguments() {
    test_RtpMap_get_string();
    test_RtpMap_parse();
    test_rtp_pcap_time_display_parse();
    test_CommonArgs_init_filter();
    test_CommonArgs_create_rtpmap();
}
