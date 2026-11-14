#include "test_harness.h"

int rtp_pcap_run(int argc, char **argv);

static CmdResult run_program(const std::vector<std::string> &args) {
    std::vector<std::vector<char>> storage;
    std::vector<char *> argv;
    for (size_t i = 0; i < args.size(); i++) {
        storage.push_back(std::vector<char>(args[i].begin(), args[i].end()));
        storage.back().push_back('\0');
        argv.push_back(&(storage.back()[0]));
    }

    int code = 0;
    std::string output = capture([&]() { code = rtp_pcap_run(static_cast<int>(argv.size()), argv.data()); });
    CmdResult result;
    result.code = code;
    result.output = output;
    return result;
}

void test_rtp_pcap() {
    CmdResult help = run_program({"rtp-pcap"});
    EXPECT(help.code == 0);
    EXPECT_CONTAINS(help.output, "Look at RTP in a PCAP file");
    EXPECT_CONTAINS(help.output, "rtp-pcap <action> --help");

    CmdResult bare = run_program({"./rtp-pcap", "details"});
    EXPECT(bare.code == 0);
    EXPECT_CONTAINS(bare.output, "Provide RTP packet details");

    CmdResult unknown = run_program({"rtp-pcap", "nope"});
    EXPECT(unknown.code != 0);

    CmdResult bad_flag = run_program({"rtp-pcap", "details", "--not-an-arg"});
    EXPECT(bad_flag.code != 0);

    std::vector<std::vector<uint8_t>> stream;
    stream.push_back(voice_packet(1, 0, 0, 0));
    std::string path = write_rtp_capture("main-list.pcap", stream, 4002, 4000);
    CmdResult listed = run_program({"rtp-pcap", "list", path});
    EXPECT(listed.code == 0);
    EXPECT_CONTAINS(listed.output, "IP destination: 10.0.0.2:4000");
}
