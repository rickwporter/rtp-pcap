#include "test_harness.h"

#include <srtp2/srtp.h>

#include <map>

typedef enum {
    srtp_alg_none,
    srtp_alg_aes128_sha1_32bit,
    srtp_alg_aes128_sha1_80bit,
} srtp_algorithm_t;

typedef enum {
    cryptop_none,
    cryptop_encrypt,
    cryptop_decrypt,
} cryptop_t;

const char *rtp_pcap_algorithm_string(srtp_algorithm_t alg);
const char *rtp_pcap_cryptop_string(cryptop_t op);
const char *rtp_pcap_get_srtp_error_string(srtp_err_status_t status);
bool isxstring(const char *input);
int parse_srtp_key(unsigned char *output, const char *input);
void srtp_log_print(srtp_log_level_t level, const char *msg, void *data);
void error_inc(std::map<srtp_err_status_t, int> &errors, srtp_err_status_t error, int inc_value);

static const char *HEX_KEY = "69206b6e6f7720616c6c20796f7572206c6974746c652073656372657473";
static const char *B64_KEY = "aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz";

static void shutdown_after_crypto(const CmdResult &result) {
    if (result.output.find("results") != std::string::npos) {
        EXPECT(srtp_shutdown() == srtp_err_status_ok);
    }
}

static void test_rtp_pcap_algorithm_string() {
    EXPECT_STREQ(rtp_pcap_algorithm_string(srtp_alg_none), "none");
    EXPECT_STREQ(rtp_pcap_algorithm_string(srtp_alg_aes128_sha1_32bit), "AES-CM-128-SHA1-32bit");
    EXPECT_STREQ(rtp_pcap_algorithm_string(srtp_alg_aes128_sha1_80bit), "AES-CM-128-SHA1-80bit");
    EXPECT_STREQ(rtp_pcap_algorithm_string(static_cast<srtp_algorithm_t>(99)), "unknown");
}

static void test_rtp_pcap_cryptop_string() {
    EXPECT_STREQ(rtp_pcap_cryptop_string(cryptop_encrypt), "encrypt");
    EXPECT_STREQ(rtp_pcap_cryptop_string(cryptop_decrypt), "decrypt");
    EXPECT_STREQ(rtp_pcap_cryptop_string(cryptop_none), "unknown");
    EXPECT_STREQ(rtp_pcap_cryptop_string(static_cast<cryptop_t>(99)), "unknown");
}

static void test_rtp_pcap_get_srtp_error_string() {
    struct ErrorName {
        srtp_err_status_t status;
        const char *name;
    };
    const ErrorName names[] = {
        {srtp_err_status_ok, "none"},
        {srtp_err_status_fail, "unspecified"},
        {srtp_err_status_bad_param, "bad parameter"},
        {srtp_err_status_alloc_fail, "allocation failure"},
        {srtp_err_status_dealloc_fail, "deallocation failure"},
        {srtp_err_status_init_fail, "init failure"},
        {srtp_err_status_terminus, "counter expired"},
        {srtp_err_status_auth_fail, "authentication failure"},
        {srtp_err_status_cipher_fail, "cipher failure"},
        {srtp_err_status_replay_fail, "replay bad index"},
        {srtp_err_status_replay_old, "replay old index"},
        {srtp_err_status_algo_fail, "algorithm failure"},
        {srtp_err_status_no_such_op, "unsupported op"},
        {srtp_err_status_no_ctx, "no context"},
        {srtp_err_status_cant_check, "invalid op"},
        {srtp_err_status_key_expired, "key expired"},
        {srtp_err_status_socket_err, "socket failure"},
        {srtp_err_status_signal_err, "signal failure"},
        {srtp_err_status_nonce_bad, "bad nonce"},
        {srtp_err_status_read_fail, "read failure"},
        {srtp_err_status_write_fail, "write failure"},
        {srtp_err_status_parse_err, "parse failure"},
        {srtp_err_status_encode_err, "encoding failure"},
        {srtp_err_status_semaphore_err, "semaphore failure"},
        {srtp_err_status_pfkey_err, "key derivation failure"},
        {srtp_err_status_bad_mki, "bad MKI"},
        {srtp_err_status_pkt_idx_old, "old packet index"},
        {srtp_err_status_pkt_idx_adv, "future packet index"},
        {srtp_err_status_cryptex_err, "unkwown"},
        {static_cast<srtp_err_status_t>(1000), "unkwown"},
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        EXPECT_STREQ(rtp_pcap_get_srtp_error_string(names[i].status), names[i].name);
    }
}

static void test_isxstring() {
    EXPECT(isxstring(HEX_KEY));
    EXPECT(isxstring(""));
    EXPECT(isxstring("0123456789abcdefABCDEF"));
    EXPECT(!isxstring(B64_KEY));
    EXPECT(!isxstring("zz"));
}

static void test_parse_srtp_key() {
    unsigned char decoded_hex[64];
    unsigned char decoded_b64[64];
    int hex_length = parse_srtp_key(decoded_hex, HEX_KEY);
    int b64_length = parse_srtp_key(decoded_b64, B64_KEY);
    EXPECT(hex_length == 30);
    EXPECT(b64_length == 30);
    EXPECT(memcmp(decoded_hex, decoded_b64, 30) == 0);
}

static void test_error_inc() {
    std::map<srtp_err_status_t, int> errors;
    error_inc(errors, srtp_err_status_auth_fail, 1);
    error_inc(errors, srtp_err_status_auth_fail, 3);
    error_inc(errors, srtp_err_status_fail, 2);
    EXPECT(errors[srtp_err_status_auth_fail] == 4);
    EXPECT(errors[srtp_err_status_fail] == 2);
}

static void test_srtp_log_print() {
    std::string logged = capture([&]() { srtp_log_print(static_cast<srtp_log_level_t>(3), "hello", NULL); });
    EXPECT_CONTAINS(logged, "SRTP-LOG [3]: hello");
}

static void test_add_encrypt_command() {
    std::vector<std::vector<uint8_t>> stream;
    stream.push_back(voice_packet(1, 0, 8, 1));
    stream.push_back(voice_packet(2, 160, 8, 0));
    std::string input = write_rtp_capture("srtp-in.pcap", stream, 4002, 4000);
    std::string encrypted = g_tmpdir + "/encrypted.pcap";

    CmdResult too_long = run_cli({"encrypt", input, "--key", std::string(129, 'a')});
    EXPECT(too_long.code == 0);
    EXPECT_CONTAINS(too_long.output, "key length is too long");

    CmdResult bad_length = run_cli({"encrypt", input, "--key", std::string(66, 'a')});
    EXPECT(bad_length.code == 0);
    EXPECT_CONTAINS(bad_length.output, "invalid key length");

    CmdResult no_key = run_cli({"encrypt", input, "--key", ""});
    EXPECT_CONTAINS(no_key.output, "no key specified");

    CmdResult no_output = run_cli({"encrypt", input, "--key", HEX_KEY, "--output", ""});
    EXPECT_CONTAINS(no_output.output, "no output file specified");

    std::string existing = g_tmpdir + "/existing.pcap";
    FILE *existing_file = fopen(existing.c_str(), "w");
    fputs("keep", existing_file);
    fclose(existing_file);
    CmdResult exists = run_cli({"encrypt", input, "--key", HEX_KEY, "--output", existing});
    EXPECT_CONTAINS(exists.output, "already exists");

    CmdResult encrypt = run_cli({"encrypt", input, "--filter", "src", "--key", B64_KEY, "--alg", "aes128-sha1-80", "--debug", "--output", encrypted});
    EXPECT(encrypt.code == 0);
    EXPECT_CONTAINS(encrypt.output, "SRTP-LOG");
    EXPECT_CONTAINS(encrypt.output, "encrypt results");
    EXPECT_CONTAINS(encrypt.output, "No srtp failures");
    EXPECT_CONTAINS(encrypt.output, "wrote 2 packets");
    shutdown_after_crypto(encrypt);
}

static void test_add_decrypt_command() {
    std::string encrypted = g_tmpdir + "/encrypted.pcap";
    std::string decrypted = g_tmpdir + "/decrypted.pcap";

    CmdResult missing = run_cli({"decrypt", g_tmpdir + "/missing-srtp.pcap", "--key", HEX_KEY});
    EXPECT(missing.code == -2);
    EXPECT_CONTAINS(missing.output, "missing file=");

    CmdResult decrypt = run_cli({"decrypt", encrypted, "--key", HEX_KEY, "--alg", "aes128-sha1-80", "--output", decrypted});
    EXPECT(decrypt.code == 0);
    EXPECT_CONTAINS(decrypt.output, "decrypt results");
    EXPECT_CONTAINS(decrypt.output, "No srtp failures");
    EXPECT_CONTAINS(decrypt.output, "wrote 2 packets");
    shutdown_after_crypto(decrypt);

    CmdResult bad_alg = run_cli({"decrypt", encrypted, "--key", HEX_KEY, "--output", g_tmpdir + "/bad-alg.pcap"});
    EXPECT(bad_alg.code == 0);
    EXPECT_CONTAINS(bad_alg.output, "srtp failures");
    EXPECT_CONTAINS(bad_alg.output, "authentication failure");
    EXPECT_CONTAINS(bad_alg.output, "wrote 0 packets");
    shutdown_after_crypto(bad_alg);
}

static void test_rtp_pcap_srtp_bad_output() {
    std::vector<std::vector<uint8_t>> stream;
    stream.push_back(voice_packet(1, 0, 8, 1));
    stream.push_back(voice_packet(2, 160, 8, 0));
    std::string input = write_rtp_capture("srtp-in.pcap", stream, 4002, 4000);

    CmdResult bad_output = run_cli({"encrypt", input, "--key", HEX_KEY, "--output", g_tmpdir + "/no-such-dir/out.pcap"});
    EXPECT_CONTAINS(bad_output.output, "unable to open output file");
}

void test_action_srtp() {
    test_rtp_pcap_algorithm_string();
    test_rtp_pcap_cryptop_string();
    test_rtp_pcap_get_srtp_error_string();
    test_isxstring();
    test_parse_srtp_key();
    test_error_inc();
    test_srtp_log_print();
    test_add_encrypt_command();
    test_add_decrypt_command();
    test_rtp_pcap_srtp_bad_output();
}
