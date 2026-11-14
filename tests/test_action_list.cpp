#include "test_harness.h"

void test_action_list() {
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
    CmdResult listed = run_cli({"list", write_rtp_capture("even-dest.pcap", even_dest, 4002, 4000)});
    EXPECT(listed.code == 0);
    EXPECT_CONTAINS(listed.output, "IP destination: 10.0.0.2:4000");
    EXPECT_CONTAINS(listed.output, "pcmu (0) : 1");

    std::vector<std::vector<uint8_t>> not_rtp;
    not_rtp.push_back(make_rtp(0, 1, 0, 0x99, 0, 0, std::vector<uint8_t>(4, 0)));
    CmdResult skipped = run_cli({"list", write_rtp_capture("not-rtp.pcap", not_rtp, 4002, 4000)});
    EXPECT(skipped.code == 0);
    EXPECT_CONTAINS(skipped.output, "found (1 total packet");
    EXPECT(skipped.output.find("10.0.0.2") == std::string::npos);
}
