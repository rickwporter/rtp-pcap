#include "test_harness.h"

void test_action_summary() {
    std::vector<std::vector<uint8_t>> stream;
    stream.push_back(voice_packet(1, 0, 0, 1));
    stream.push_back(voice_packet(2, 160, 0, 0));
    std::string stream_path = write_rtp_capture("summary-stream.pcap", stream, 4002, 4000);

    CmdResult summary = run_cli({"summary", stream_path, "--filter", "src"});
    EXPECT(summary.code == 0);
    EXPECT_CONTAINS(summary.output, "IP source: 10.0.0.1:4002");
    EXPECT_CONTAINS(summary.output, "RTP 2 packets");

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
}
