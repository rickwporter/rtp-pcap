#include "packet_utilities.h"
#include "test_harness.h"

int rtp_pcap_packet_get_rtp_payload_length(rtp_pcap_pkt_t *pkt);

static void test_rtp_pcap_iph_byteswap() {
    iphdr_t ip;
    memset(&ip, 0, sizeof(ip));
    ip.tot_len = htons(100);
    ip.id = htons(7);
    ip.frag_off = htons(0x4000);
    ip.check = htons(0x1234);
    ip.saddr = htonl(ipv4(10, 0, 0, 1));
    ip.daddr = htonl(ipv4(10, 0, 0, 2));
    rtp_pcap_iph_byteswap(&ip);
    EXPECT(ip.tot_len == 100);
    EXPECT(ip.id == 7);
    EXPECT(ip.frag_off == 0x4000);
    EXPECT(ip.check == 0x1234);
    EXPECT(ip.saddr == ipv4(10, 0, 0, 1));
    EXPECT(ip.daddr == ipv4(10, 0, 0, 2));
}

static void test_rtp_pcap_udph_byteswap() {
    udphdr_t udp;
    udp.source = htons(4002);
    udp.dest = htons(4000);
    udp.len = htons(36);
    udp.check = htons(0xabcd);
    rtp_pcap_udph_byteswap(&udp);
    EXPECT(udp.source == 4002);
    EXPECT(udp.dest == 4000);
    EXPECT(udp.len == 36);
    EXPECT(udp.check == 0xabcd);
}

static void test_rtp_pcap_open_input() {
    std::string bad_path = g_tmpdir + "/not-a-pcap";
    FILE *bad = fopen(bad_path.c_str(), "w");
    fputs("this is not a pcap\n", bad);
    fclose(bad);
    std::string missing = capture([&]() { EXPECT(rtp_pcap_open_input("unit-test", (g_tmpdir + "/missing.pcap").c_str()) == NULL); });
    EXPECT_CONTAINS(missing, "missing file=");
    std::string failed = capture([&]() { EXPECT(rtp_pcap_open_input("unit-test", bad_path.c_str()) == NULL); });
    EXPECT_CONTAINS(failed, "failed to open PCAP=");
}

static void test_rtp_pcap_get_next_packet() {
    PcapFile empty;
    std::string empty_path = g_tmpdir + "/empty.pcap";
    empty.write(empty_path);
    pcap_t *pcap = open_pcap(empty_path);
    rtp_pcap_filter_t filter;
    memset(&filter, 0, sizeof(filter));
    filter.flags = FILTER_FLAG_DST_FILTER;
    rtp_pcap_pkt_t packet;
    uint32_t total = 0;
    EXPECT(rtp_pcap_get_next_packet(pcap, &total, &filter, &packet) == -1);
    EXPECT(total == 0);
    pcap_close(pcap);

    std::vector<uint8_t> payload(4, 0);
    payload[0] = 1;
    payload[1] = 2;
    payload[2] = 3;
    payload[3] = 4;
    std::vector<uint8_t> rtp = make_rtp(RFC_1889_VERSION, 42, 160, 7, 0, 0, payload);
    PcapFile mixed;
    mixed.add_ethernet(0x0806, std::vector<uint8_t>(28, 0), false, 0, 0);
    mixed.add_ipv4(IPPROTO_TCP, ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), std::vector<uint8_t>(20, 0), false, 0, 1);
    mixed.add_udp(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 4002, 4000, rtp, true, 1, 0);
    std::string mixed_path = g_tmpdir + "/mixed.pcap";
    mixed.write(mixed_path);

    pcap = open_pcap(mixed_path);
    total = 0;
    EXPECT(rtp_pcap_get_next_packet(pcap, &total, &filter, &packet) == 0);
    EXPECT(total == 3);
    EXPECT(packet.iph->saddr == ipv4(10, 0, 0, 1));
    EXPECT(packet.iph->daddr == ipv4(10, 0, 0, 2));
    EXPECT(packet.udph->source == 4002);
    EXPECT(packet.udph->dest == 4000);
    EXPECT(rtp_hdr_get_sequence(packet.rtph) == 42);
    EXPECT(rtp_pcap_packet_get_rtp_payload_length(&packet) == 4);
    EXPECT(rtp_pcap_get_next_packet(pcap, &total, &filter, &packet) == -1);
    pcap_close(pcap);

    pcap = open_pcap(mixed_path);
    memset(&filter, 0, sizeof(filter));
    filter.flags = FILTER_FLAG_DST_FILTER | FILTER_FLAG_DPORT_SET;
    filter.dport = 9;
    total = 0;
    EXPECT(rtp_pcap_get_next_packet(pcap, &total, &filter, &packet) == -1);
    EXPECT(total == 3);
    pcap_close(pcap);

    pcap = open_pcap(mixed_path);
    filter.dport = 4000;
    total = 0;
    EXPECT(rtp_pcap_get_next_packet(pcap, &total, &filter, &packet) == 0);
    EXPECT(rtp_hdr_get_sequence(packet.rtph) == 42);
    pcap_close(pcap);

    pcap = open_pcap(mixed_path);
    memset(&filter, 0, sizeof(filter));
    filter.flags = FILTER_FLAG_SRC_FILTER | FILTER_FLAG_SADDR_SET | FILTER_FLAG_SPORT_SET;
    filter.saddr = ipv4(10, 0, 0, 9);
    filter.sport = 4002;
    total = 0;
    EXPECT(rtp_pcap_get_next_packet(pcap, &total, &filter, &packet) == -1);
    pcap_close(pcap);

    pcap = open_pcap(mixed_path);
    filter.saddr = ipv4(10, 0, 0, 1);
    total = 0;
    EXPECT(rtp_pcap_get_next_packet(pcap, &total, &filter, &packet) == 0);
    EXPECT(packet.udph->source == 4002);
    pcap_close(pcap);

    pcap = open_pcap(mixed_path);
    memset(&filter, 0, sizeof(filter));
    filter.flags = FILTER_FLAG_DADDR_SET;
    filter.daddr = ipv4(10, 0, 0, 9);
    total = 0;
    EXPECT(rtp_pcap_get_next_packet(pcap, &total, &filter, &packet) == -1);
    pcap_close(pcap);

    pcap = open_pcap(mixed_path);
    memset(&filter, 0, sizeof(filter));
    filter.flags = FILTER_FLAG_SPORT_SET;
    filter.sport = 9;
    total = 0;
    EXPECT(rtp_pcap_get_next_packet(pcap, &total, &filter, &packet) == -1);
    pcap_close(pcap);
}

void test_packet_utilities() {
    test_rtp_pcap_iph_byteswap();
    test_rtp_pcap_udph_byteswap();
    test_rtp_pcap_open_input();
    test_rtp_pcap_get_next_packet();
}
