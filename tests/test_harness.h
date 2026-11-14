#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <unistd.h>

#include <CLI/CLI.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "action_details.h"
#include "action_list.h"
#include "action_stats.h"
#include "action_summary.h"
#include "packet_utilities.h"
#include "rtp_utils.h"

#if INCLUDE_SRTP
#include "action_srtp.h"
#endif

extern int g_failed;
extern std::string g_tmpdir;

inline void expect(bool condition, const char *expression, const char *file, int line) {
    if (!condition) {
        fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expression);
        g_failed++;
    }
}

inline void expect_streq(const char *actual, const char *expected, const char *file, int line) {
    if (actual == NULL || expected == NULL || strcmp(actual, expected) != 0) {
        fprintf(stderr, "FAIL %s:%d:\n  actual:   [%s]\n  expected: [%s]\n", file, line, actual ? actual : "(null)", expected ? expected : "(null)");
        g_failed++;
    }
}

inline void expect_contains(const std::string &haystack, const char *needle, const char *file, int line) {
    if (haystack.find(needle) == std::string::npos) {
        fprintf(stderr, "FAIL %s:%d: missing \"%s\" in:\n%s\n", file, line, needle, haystack.c_str());
        g_failed++;
    }
}

#define EXPECT(condition) expect(static_cast<bool>(condition), #condition, __FILE__, __LINE__)
#define EXPECT_STREQ(actual, expected) expect_streq((actual), (expected), __FILE__, __LINE__)
#define EXPECT_CONTAINS(haystack, needle) expect_contains((haystack), (needle), __FILE__, __LINE__)

class TempDir {
  public:
    TempDir() {
        char tmpl[] = "./.unit-test-XXXXXX";
        if (mkdtemp(tmpl) == NULL) {
            perror("mkdtemp");
            exit(1);
        }
        path = tmpl;
        g_tmpdir = path;
    }

    ~TempDir() {
        std::string command = "rm -rf " + path;
        int rc = system(command.c_str());
        if (rc != 0) {
            fprintf(stderr, "failed to remove %s\n", path.c_str());
        }
    }

    std::string file(const std::string &name) const { return path + "/" + name; }

    std::string path;
};

class Capture {
  public:
    Capture() : saved_out(-1), saved_err(-1), file(NULL) {
        fflush(stdout);
        fflush(stderr);
        saved_out = dup(STDOUT_FILENO);
        saved_err = dup(STDERR_FILENO);
        path = g_tmpdir + "/capture";
        file = fopen(path.c_str(), "w+");
        if (saved_out < 0 || saved_err < 0 || file == NULL) {
            perror("capture");
            exit(1);
        }
        dup2(fileno(file), STDOUT_FILENO);
        dup2(fileno(file), STDERR_FILENO);
    }

    ~Capture() { restore(); }

    std::string stop() {
        fflush(stdout);
        fflush(stderr);
        restore();
        std::string output;
        rewind(file);
        char buffer[4096];
        size_t count;
        while ((count = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            output.append(buffer, count);
        }
        fclose(file);
        file = NULL;
        return output;
    }

  private:
    void restore() {
        if (saved_out >= 0) {
            fflush(stdout);
            fflush(stderr);
            dup2(saved_out, STDOUT_FILENO);
            dup2(saved_err, STDERR_FILENO);
            close(saved_out);
            close(saved_err);
            saved_out = -1;
            saved_err = -1;
        }
    }

    int saved_out;
    int saved_err;
    FILE *file;
    std::string path;
};

template <typename Function> inline std::string capture(Function function) {
    Capture redirect;
    function();
    return redirect.stop();
}

struct CmdResult {
    int code;
    std::string output;
};

inline CmdResult run_cli(const std::vector<std::string> &args) {
    std::vector<std::string> words;
    words.push_back("rtp-pcap");
    words.insert(words.end(), args.begin(), args.end());

    std::vector<std::vector<char>> storage;
    std::vector<char *> argv;
    for (size_t i = 0; i < words.size(); i++) {
        storage.push_back(std::vector<char>(words[i].begin(), words[i].end()));
        storage.back().push_back('\0');
        argv.push_back(&(storage.back()[0]));
    }

    int exit_code = 0;
    CLI::App app{"Look at RTP in a PCAP file"};
    app.name("rtp-pcap");
    add_list_command(app, exit_code, "rtp-pcap");
    add_summary_command(app, exit_code, "rtp-pcap");
    add_details_command(app, exit_code, "rtp-pcap");
    add_stats_command(app, exit_code, "rtp-pcap");
#if INCLUDE_SRTP
    add_encrypt_command(app, exit_code, "rtp-pcap");
    add_decrypt_command(app, exit_code, "rtp-pcap");
#endif

    std::string output = capture([&]() {
        try {
            app.parse(static_cast<int>(argv.size()), argv.data());
        } catch (const CLI::ParseError &error) {
            exit_code = app.exit(error);
        }
    });

    CmdResult result;
    result.code = exit_code;
    result.output = output;
    return result;
}

inline void append_u16le(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
}

inline void append_u32le(std::vector<uint8_t> &out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
}

inline void append_u16be(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

inline void append_addr(std::vector<uint8_t> &out, uint32_t host_order) {
    out.push_back(static_cast<uint8_t>((host_order >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((host_order >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((host_order >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(host_order & 0xff));
}

inline uint32_t ipv4(unsigned a, unsigned b, unsigned c, unsigned d) { return (a << 24) | (b << 16) | (c << 8) | d; }

class PcapFile {
  public:
    PcapFile() {
        append_u32le(bytes, 0xa1b2c3d4);
        append_u16le(bytes, 2);
        append_u16le(bytes, 4);
        append_u32le(bytes, 0);
        append_u32le(bytes, 0);
        append_u32le(bytes, 65535);
        append_u32le(bytes, 1);
    }

    void add_ethernet(uint16_t ethertype, const std::vector<uint8_t> &payload, bool vlan, uint32_t ts_sec, uint32_t ts_usec) {
        std::vector<uint8_t> frame(12, 0);
        if (vlan) {
            append_u16be(frame, 0x8100);
            append_u16be(frame, 0);
            append_u16be(frame, ethertype);
        } else {
            append_u16be(frame, ethertype);
        }
        frame.insert(frame.end(), payload.begin(), payload.end());
        append_u32le(bytes, ts_sec);
        append_u32le(bytes, ts_usec);
        append_u32le(bytes, static_cast<uint32_t>(frame.size()));
        append_u32le(bytes, static_cast<uint32_t>(frame.size()));
        bytes.insert(bytes.end(), frame.begin(), frame.end());
    }

    void add_ipv4(uint8_t protocol, uint32_t src, uint32_t dst, const std::vector<uint8_t> &l4, bool vlan, uint32_t ts_sec, uint32_t ts_usec) {
        std::vector<uint8_t> ip;
        ip.push_back(0x45);
        ip.push_back(0);
        append_u16be(ip, static_cast<uint16_t>(20 + l4.size()));
        append_u16be(ip, 1);
        append_u16be(ip, 0);
        ip.push_back(64);
        ip.push_back(protocol);
        append_u16be(ip, 0);
        append_addr(ip, src);
        append_addr(ip, dst);
        ip.insert(ip.end(), l4.begin(), l4.end());
        add_ethernet(0x0800, ip, vlan, ts_sec, ts_usec);
    }

    void add_udp(
        uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport, const std::vector<uint8_t> &payload, bool vlan, uint32_t ts_sec, uint32_t ts_usec
    ) {
        std::vector<uint8_t> udp;
        append_u16be(udp, sport);
        append_u16be(udp, dport);
        append_u16be(udp, static_cast<uint16_t>(8 + payload.size()));
        append_u16be(udp, 0);
        udp.insert(udp.end(), payload.begin(), payload.end());
        add_ipv4(IPPROTO_UDP, src, dst, udp, vlan, ts_sec, ts_usec);
    }

    void write(const std::string &path) const {
        FILE *file = fopen(path.c_str(), "wb");
        EXPECT(file != NULL);
        if (file == NULL) {
            return;
        }
        size_t written = fwrite(&(bytes[0]), 1, bytes.size(), file);
        EXPECT(written == bytes.size());
        fclose(file);
    }

  private:
    std::vector<uint8_t> bytes;
};

inline std::vector<uint8_t> make_rtp(
    uint8_t version, uint16_t sequence, uint32_t timestamp, uint32_t ssrc, uint8_t payload_type, uint8_t marker, const std::vector<uint8_t> &payload
) {
    rtphdr_t header;
    rtp_hdr_init(&header);
    rtp_hdr_set_version(&header, version);
    rtp_hdr_set_sequence(&header, sequence);
    rtp_hdr_set_timestamp(&header, timestamp);
    rtp_hdr_set_ssrc(&header, ssrc);
    rtp_hdr_set_ptype(&header, payload_type);
    rtp_hdr_set_marker(&header, marker);

    std::vector<uint8_t> bytes(sizeof(header) + payload.size(), 0);
    memcpy(&(bytes[0]), &header, sizeof(header));
    if (!payload.empty()) {
        memcpy(&(bytes[sizeof(header)]), &(payload[0]), payload.size());
    }
    return bytes;
}

inline void
fill_rtp(uint8_t *raw, size_t raw_size, uint8_t version, uint16_t sequence, uint32_t timestamp, uint32_t ssrc, uint8_t payload_type, uint8_t marker) {
    memset(raw, 0, raw_size);
    rtphdr_t *header = reinterpret_cast<rtphdr_t *>(raw);
    rtp_hdr_init(header);
    rtp_hdr_set_version(header, version);
    rtp_hdr_set_sequence(header, sequence);
    rtp_hdr_set_timestamp(header, timestamp);
    rtp_hdr_set_ssrc(header, ssrc);
    rtp_hdr_set_ptype(header, payload_type);
    rtp_hdr_set_marker(header, marker);
}

inline pcap_t *open_pcap(const std::string &path) {
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(path.c_str(), error);
    EXPECT(pcap != NULL);
    return pcap;
}

inline std::string write_rtp_capture(const std::string &name, const std::vector<std::vector<uint8_t>> &packets, uint16_t sport, uint16_t dport) {
    PcapFile file;
    for (size_t i = 0; i < packets.size(); i++) {
        file.add_udp(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), sport, dport, packets[i], false, static_cast<uint32_t>(i), 0);
    }
    std::string path = g_tmpdir + "/" + name;
    file.write(path);
    return path;
}

inline std::vector<uint8_t> voice_packet(uint16_t sequence, uint32_t timestamp, uint8_t payload_type, uint8_t marker) {
    return make_rtp(RFC_1889_VERSION, sequence, timestamp, 0x99, payload_type, marker, std::vector<uint8_t>(160, 0));
}

void test_action_details();
void test_action_list();
void test_action_stats();
void test_action_summary();
void test_arguments();
void test_base64();
void test_hexutils();
void test_packet_utilities();
void test_rtp_pcap();
void test_rtp_utils();
void test_time_utilities();
#if INCLUDE_SRTP
void test_action_srtp();
#endif
