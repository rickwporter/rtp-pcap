#include "test_harness.h"

void test_action_list() {
    TestScope scope(__FILE__ ":test_action_list");
    CmdResult missing = run_cli({"list", g_tmpdir + "/no-such-list.pcap"});
    EXPECT(missing.code == -2);
    EXPECT_CONTAINS(missing.output, "missing file=");

    std::vector<std::vector<uint8_t>> odd_dest;
    odd_dest.push_back(voice_packet(1, 0, 0, 0));
    std::string odd_dest_path = write_rtp_capture("odd-dest.pcap", odd_dest, 6000, 6001);
    CmdResult even_only = run_cli({"list", odd_dest_path});
    EXPECT(even_only.code == 0);
    EXPECT(even_only.output.find("10.0.0.2") == std::string::npos);
    CmdResult with_odd = run_cli({"list", odd_dest_path, "--odd"});
    EXPECT(with_odd.code == 0);
    EXPECT_CONTAINS(with_odd.output, "IP destination: 10.0.0.2:6001");

    std::string odd_src_path = write_rtp_capture("odd-src.pcap", odd_dest, 6001, 6000);
    CmdResult skip_odd_src = run_cli({"list", odd_src_path, "--filter", "src"});
    EXPECT(skip_odd_src.code == 0);
    EXPECT(skip_odd_src.output.find("10.0.0.2") == std::string::npos);
    CmdResult keep_odd_src = run_cli({"list", odd_src_path, "--filter", "src", "--odd"});
    EXPECT(keep_odd_src.code == 0);
    EXPECT_CONTAINS(keep_odd_src.output, "IP destination: 10.0.0.2:6000");

    std::vector<std::vector<uint8_t>> even_dest;
    even_dest.push_back(voice_packet(1, 0, 0, 0));
    std::string even_path = write_rtp_capture("even-dest.pcap", even_dest, 4002, 4000);
    CmdResult listed = run_cli({"list", even_path});
    EXPECT(listed.code == 0);
    EXPECT_CONTAINS(listed.output, "IP destination: 10.0.0.2:4000");
    EXPECT_CONTAINS(listed.output, "Start index: 1\n    Start time: 0.000\n    Duration: 0.000 seconds\n");
    EXPECT_CONTAINS(listed.output, "pcmu (0) : 1");

    CmdResult timed = run_cli({"list", even_path, "--time", "capture"});
    EXPECT(timed.code == 0);
    EXPECT_CONTAINS(timed.output, "Start index: 1\n    Start time: 0.000\n    Duration: 0.000 seconds\n");
    CmdResult clock = run_cli({"list", even_path, "--time", "timeofday"});
    EXPECT(clock.code == 0);
    EXPECT_CONTAINS(clock.output, "Start time: 00:00:00.000 GMT");
    CmdResult dated = run_cli({"list", even_path, "--time", "date"});
    EXPECT(dated.code == 0);
    EXPECT_CONTAINS(dated.output, "Start time: 1970-01-01 00:00:00.000 GMT");
    CmdResult hidden = run_cli({"list", even_path, "--time", "none"});
    EXPECT(hidden.code == 0);
    EXPECT(hidden.output.find("Start time:") == std::string::npos);

    PcapFile streams;
    streams.add_udp(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 4002, 4004, voice_packet(1, 0, 0, 0), false, 10, 0);
    streams.add_udp(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 4002, 4000, voice_packet(1, 0, 0, 0), false, 11, 500000);
    streams.add_udp(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 4002, 4004, voice_packet(2, 160, 0, 0), false, 13, 0);
    streams.add_udp(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 4002, 4000, voice_packet(2, 160, 0, 0), false, 15, 0);
    std::string streams_path = g_tmpdir + "/list-streams.pcap";
    streams.write(streams_path);
    CmdResult spans = run_cli({"list", streams_path, "--time", "capture"});
    EXPECT(spans.code == 0);
    EXPECT_CONTAINS(spans.output, "IP destination: 10.0.0.2:4000 (2 packets)\n    Start index: 2\n    Start time: 1.500\n    Duration: 3.500 seconds\n");
    EXPECT_CONTAINS(spans.output, "IP destination: 10.0.0.2:4004 (2 packets)\n    Start index: 1\n    Start time: 0.000\n    Duration: 3.000 seconds\n");

    PcapFile shifted;
    shifted.add_ethernet(0x0806, std::vector<uint8_t>(8, 0), false, 5, 250000);
    shifted.add_udp(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 4002, 4000, voice_packet(1, 0, 0, 0), false, 8, 0);
    std::string shifted_path = g_tmpdir + "/list-shifted.pcap";
    shifted.write(shifted_path);
    CmdResult shifted_list = run_cli({"list", shifted_path, "--time", "capture"});
    EXPECT(shifted_list.code == 0);
    EXPECT_CONTAINS(shifted_list.output, "Start index: 2\n    Start time: 2.750\n    Duration: 0.000 seconds\n");

    std::vector<std::vector<uint8_t>> not_rtp;
    not_rtp.push_back(make_rtp(0, 1, 0, 0x99, 0, 0, std::vector<uint8_t>(4, 0)));
    CmdResult skipped = run_cli({"list", write_rtp_capture("not-rtp.pcap", not_rtp, 4002, 4000)});
    EXPECT(skipped.code == 0);
    EXPECT_CONTAINS(skipped.output, "found (1 total packet");
    EXPECT(skipped.output.find("10.0.0.2") == std::string::npos);
    EXPECT(skipped.output.find("Start index:") == std::string::npos);

    std::vector<std::vector<uint8_t>> leading;
    leading.push_back(make_rtp(0, 1, 0, 0x99, 0, 0, std::vector<uint8_t>(4, 0)));
    leading.push_back(voice_packet(1, 0, 0, 0));
    CmdResult later = run_cli({"list", write_rtp_capture("list-leading.pcap", leading, 4002, 4000), "--time", "capture"});
    EXPECT(later.code == 0);
    EXPECT_CONTAINS(later.output, "Start index: 2\n    Start time: 1.000\n    Duration: 0.000 seconds\n");
}
