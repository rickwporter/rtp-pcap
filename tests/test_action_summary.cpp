#include "test_harness.h"

void test_action_summary() {
    TestScope scope(__FILE__ ":test_action_summary");
    std::vector<std::vector<uint8_t>> stream;
    stream.push_back(voice_packet(1, 0, 0, 1));
    stream.push_back(voice_packet(2, 160, 0, 0));
    std::string stream_path = write_rtp_capture("summary-stream.pcap", stream, 4002, 4000);

    CmdResult summary = run_cli({"summary", stream_path, "--filter", "src"});
    EXPECT(summary.code == 0);
    EXPECT_CONTAINS(summary.output, "IP source: 10.0.0.1:4002");
    EXPECT_CONTAINS(summary.output, "RTP 2 packets");
    EXPECT_CONTAINS(summary.output, "Start index: 1\n  Start time: 0.000\n  Duration: 1.000 seconds\n");

    CmdResult timed = run_cli({"summary", stream_path, "--time", "capture"});
    EXPECT(timed.code == 0);
    EXPECT_CONTAINS(timed.output, "Start index: 1\n  Start time: 0.000\n  Duration: 1.000 seconds\n");
    CmdResult clock = run_cli({"summary", stream_path, "--time", "timeofday"});
    EXPECT(clock.code == 0);
    EXPECT_CONTAINS(clock.output, "Start time: 00:00:00.000 GMT");
    CmdResult dated = run_cli({"summary", stream_path, "--time", "datetime"});
    EXPECT(dated.code == 0);
    EXPECT_CONTAINS(dated.output, "Start time: 1970-01-01 00:00:00.000 GMT");

    CmdResult missing = run_cli({"summary", g_tmpdir + "/no-such-summary.pcap"});
    EXPECT(missing.code == -2);
    EXPECT_CONTAINS(missing.output, "missing file=");

    CmdResult destination = run_cli({"summary", stream_path});
    EXPECT(destination.code == 0);
    EXPECT_CONTAINS(destination.output, "IP destination: 10.0.0.2:4000");

    std::vector<std::vector<uint8_t>> leading;
    leading.push_back(make_rtp(0, 1, 0, 0x99, 0, 0, std::vector<uint8_t>(4, 0)));
    leading.push_back(voice_packet(1, 0, 0, 0));
    CmdResult skipped = run_cli({"summary", write_rtp_capture("summary-leading.pcap", leading, 4002, 4000)});
    EXPECT(skipped.code == 0);
    EXPECT_CONTAINS(skipped.output, "RTP 1 packets (2 in capture)");
    EXPECT_CONTAINS(skipped.output, "Start index: 2\n  Start time: 1.000\n  Duration: 0.000 seconds\n");

    CmdResult later = run_cli({"summary", write_rtp_capture("summary-leading-time.pcap", leading, 4002, 4000), "--time", "capture"});
    EXPECT(later.code == 0);
    EXPECT_CONTAINS(later.output, "Start index: 2\n  Start time: 1.000\n  Duration: 0.000 seconds\n");

    PcapFile shifted;
    shifted.add_ethernet(0x0806, std::vector<uint8_t>(8, 0), false, 5, 250000);
    shifted.add_udp(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 4002, 4000, voice_packet(1, 0, 0, 0), false, 8, 0);
    std::string shifted_path = g_tmpdir + "/summary-shifted.pcap";
    shifted.write(shifted_path);
    CmdResult shifted_summary = run_cli({"summary", shifted_path, "--time", "capture"});
    EXPECT(shifted_summary.code == 0);
    EXPECT_CONTAINS(shifted_summary.output, "Start index: 2\n  Start time: 2.750\n  Duration: 0.000 seconds\n");
}
