#include "test_harness.h"

void test_action_stats() {
    std::vector<std::vector<uint8_t>> jumped;
    jumped.push_back(voice_packet(1, 0, 0, 0));
    jumped.push_back(voice_packet(200, 160, 0, 0));
    CmdResult jump = run_cli({"stats", write_rtp_capture("jump.pcap", jumped, 4002, 4000)});
    EXPECT(jump.code == 0);
    EXPECT_CONTAINS(jump.output, "last=1, curr=200, delta=198");
    EXPECT_CONTAINS(jump.output, "jumps: 1");

    std::vector<std::vector<uint8_t>> backwards;
    backwards.push_back(voice_packet(5, 0, 0, 0));
    backwards.push_back(voice_packet(4, 160, 0, 0));
    CmdResult misordered = run_cli({"stats", write_rtp_capture("misordered.pcap", backwards, 4002, 4000)});
    EXPECT(misordered.code == 0);
    EXPECT_CONTAINS(misordered.output, "misordered: 1");

    std::vector<std::vector<uint8_t>> single;
    single.push_back(voice_packet(1, 0, 0, 0));
    CmdResult one = run_cli({"stats", write_rtp_capture("single.pcap", single, 4002, 4000)});
    EXPECT(one.code == 0);
    EXPECT_CONTAINS(one.output, "mean: 0.000 msecs");

    std::vector<std::vector<uint8_t>> broken;
    broken.push_back(voice_packet(1, 0, 0, 0));
    broken.push_back(make_rtp(0, 2, 160, 0x99, 0, 0, std::vector<uint8_t>(160, 0)));
    CmdResult invalid = run_cli({"stats", write_rtp_capture("invalid.pcap", broken, 4002, 4000)});
    EXPECT(invalid.code == 0);
    EXPECT_CONTAINS(invalid.output, "packets: 1");

    std::vector<std::vector<uint8_t>> timed;
    timed.push_back(voice_packet(1, 0, 0, 0));
    timed.push_back(voice_packet(2, 160, 0, 0));
    timed.push_back(voice_packet(4, 320, 8, 0));
    std::string timed_path = write_rtp_capture("timed.pcap", timed, 4002, 4000);
    CmdResult deltas = run_cli({"stats", timed_path});
    EXPECT(deltas.code == 0);
    EXPECT_CONTAINS(deltas.output, "lost: 1");
    EXPECT_CONTAINS(deltas.output, "pt changes: 1");
    EXPECT_CONTAINS(deltas.output, "mean: 1000.000 msecs");

    CmdResult by_date = run_cli({"stats", timed_path, "--time", "date"});
    EXPECT(by_date.code == 0);
    EXPECT_CONTAINS(by_date.output, "1970-01-01");

    CmdResult by_clock = run_cli({"stats", timed_path, "--time", "timeofday"});
    EXPECT(by_clock.code == 0);
    EXPECT_CONTAINS(by_clock.output, "00:00:00.000 GMT");

    CmdResult source = run_cli({"stats", timed_path, "--filter", "src"});
    EXPECT(source.code == 0);
    EXPECT_CONTAINS(source.output, "IP source: 10.0.0.1:4002");

    CmdResult unmatched = run_cli({"stats", timed_path, "--ip", "10.9.9.9"});
    EXPECT(unmatched.code == 0);
    EXPECT_CONTAINS(unmatched.output, "No matching RTP packets found.");

    std::vector<std::vector<uint8_t>> leading;
    leading.push_back(make_rtp(0, 1, 0, 0x99, 0, 0, std::vector<uint8_t>(4, 0)));
    leading.push_back(voice_packet(1, 0, 0, 0));
    CmdResult skipped = run_cli({"stats", write_rtp_capture("stats-leading.pcap", leading, 4002, 4000)});
    EXPECT(skipped.code == 0);
    EXPECT_CONTAINS(skipped.output, "packets: 1");

    CmdResult missing = run_cli({"stats", g_tmpdir + "/no-such-stats.pcap"});
    EXPECT(missing.code == -2);
    EXPECT_CONTAINS(missing.output, "missing file=");
}
