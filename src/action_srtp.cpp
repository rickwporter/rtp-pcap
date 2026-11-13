#include <cstdio>
#include <cstring>  // for memset()
#include <ctype.h>  // for isxdigit()
#include <string.h> // for memcpy(), strlen()
#include <sys/stat.h>

#include <CLI/CLI.hpp>
#include <memory>
#include <pcap/pcap.h>
#include <srtp2/srtp.h>

#include "action_srtp.h"
#include "arguments.h"
#include "base64.h"
#include "hexutils.h"
#include "packet_utilities.h"
#include "rtp_utils.h"

using namespace std;

typedef enum {
    cryptop_none,
    cryptop_encrypt,
    cryptop_decrypt,
} cryptop_t;

typedef enum {
    srtp_alg_none,
    srtp_alg_aes128_sha1_32bit,
    srtp_alg_aes128_sha1_80bit,
} srtp_algorithm_t;

typedef map<srtp_err_status_t, int> SrtpErrorMap;

const char *rtp_pcap_algorithm_string(srtp_algorithm_t alg) {
    if (srtp_alg_none == alg) {
        return "none";
    }
    if (srtp_alg_aes128_sha1_32bit == alg) {
        return "AES-CM-128-SHA1-32bit";
    }
    if (srtp_alg_aes128_sha1_80bit == alg) {
        return "AES-CM-128-SHA1-80bit";
    }

    return "unknown";
}

const char *rtp_pcap_cryptop_string(cryptop_t op) {
    if (cryptop_encrypt == op) {
        return "encrypt";
    }
    if (cryptop_decrypt == op) {
        return "decrypt";
    }
    return "unknown";
}

static inline const char *rtp_pcap_get_srtp_error_string(srtp_err_status_t status) {
    switch (status) {
    case srtp_err_status_ok:
        return "none";
    case srtp_err_status_fail:
        return "unspecified";
    case srtp_err_status_bad_param:
        return "bad parameter";
    case srtp_err_status_alloc_fail:
        return "allocation failure";
    case srtp_err_status_dealloc_fail:
        return "deallocation failure";
    case srtp_err_status_init_fail:
        return "init failure";
    case srtp_err_status_terminus:
        return "counter expired";
    case srtp_err_status_auth_fail:
        return "authentication failure";
    case srtp_err_status_cipher_fail:
        return "cipher failure";
    case srtp_err_status_replay_fail:
        return "replay bad index";
    case srtp_err_status_replay_old:
        return "replay old index";
    case srtp_err_status_algo_fail:
        return "algorithm failure";
    case srtp_err_status_no_such_op:
        return "unsupported op";
    case srtp_err_status_no_ctx:
        return "no context";
    case srtp_err_status_cant_check:
        return "invalid op";
    case srtp_err_status_key_expired:
        return "key expired";
    case srtp_err_status_socket_err:
        return "socket failure";
    case srtp_err_status_signal_err:
        return "signal failure";
    case srtp_err_status_nonce_bad:
        return "bad nonce";
    case srtp_err_status_read_fail:
        return "read failure";
    case srtp_err_status_write_fail:
        return "write failure";
    case srtp_err_status_parse_err:
        return "parse failure";
    case srtp_err_status_encode_err:
        return "encoding failure";
    case srtp_err_status_semaphore_err:
        return "semaphore failure";
    case srtp_err_status_pfkey_err:
        return "key derivation failure";
    case srtp_err_status_bad_mki:
        return "bad MKI";
    case srtp_err_status_pkt_idx_old:
        return "old packet index";
    case srtp_err_status_pkt_idx_adv:
        return "future packet index";
    default:
        return "unkwown";
    }
}

bool isxstring(const char *input) {
    for (const char *i = input; *i != 0; i++) {
        if (!isxdigit(*i)) {
            return false;
        }
    }

    return true;
}

int parse_srtp_key(unsigned char *output, const char *input) {
    if (isxstring(input)) {
        return hexString2Binary(output, input);
    }

    size_t out_len = 0;
    unsigned char *decoded = base64_decode((const unsigned char *)input, strlen(input), &out_len);
    memcpy(output, decoded, out_len);
    return out_len;
}

void srtp_log_print(srtp_log_level_t level, const char *msg, void *data) {
    // Simple handler to print logs to console
    printf("SRTP-LOG [%d]: %s\n", level, msg);
}

void error_inc(SrtpErrorMap &map, srtp_err_status_t error, int inc_value = 1) {
    SrtpErrorMap::const_iterator it = map.find(error);
    int count = (it == map.end() ? 0 : it->second);
    map[error] = count + inc_value;
}

static void rtp_pcap_srtp(
    const char *progname, pcap_t *input, rtp_pcap_filter_t *filter, cryptop_t op, srtp_algorithm_t alg, bool force, bool debug,
    const std::string &key, const std::string &outfile
) {
    struct stat mystat;
    pcap_t *output;
    pcap_dumper_t *dumper;
    rtp_pcap_pkt_t packet;
    uint32_t total_pkt_count = 0;
    uint32_t stream_pkt_count = 0;
    uint32_t write_pkt_count = 0;
    uint32_t srtp_fail_count = 0;
    uint8_t master_key[128];
    srtp_err_status_t srtp_status;
    srtp_policy_t srtp_policy;
    srtp_t srtp_sess;
    SrtpErrorMap errors;
    int orig_length;
    int rtp_length;
    int delta_length;
    int key_length;

    memset(&srtp_sess, 0, sizeof(srtp_sess));
    memset(&srtp_policy, 0, sizeof(srtp_policy));

    if (alg == srtp_alg_none) {
        fprintf(stdout, "\n%s: invalid algorithm specified!\n", progname);
        return;
    }

    if (key.length() == 0) {
        fprintf(stdout, "\n%s: no key specified!\n", progname);
        return;
    }

    if (key.length() > 128) {
        fprintf(stdout, "\n%s: key length is too long (%zu)!\n", progname, key.length());
        return;
    }

    // initialize the master key from the hex string
    memset(master_key, 0, sizeof(master_key));
    key_length = parse_srtp_key(master_key, key.c_str());
    if (key_length <= 0 || key_length > 32) {
        fprintf(stdout, "\n%s: invalid key length (%u) for '%s'!\n", progname, key_length, key.c_str());
        return;
    }

    if (outfile.length() == 0) {
        fprintf(stdout, "\n%s: no output file specified!\n", progname);
        return;
    }

    // make sure output file does not exist -- don't want to worry about overwriting
    if (!force && 0 == stat(outfile.c_str(), &mystat)) {
        fprintf(stdout, "\n%s: output file (%s) already exists!\n", progname, outfile.c_str());
        return;
    }

    srtp_status = srtp_init();
    if (srtp_err_status_ok != srtp_status) {
        fprintf(stdout, "\n%s: failed to initialize srtp: %d!\n", progname, srtp_status);
        return;
    }

    srtp_install_log_handler(srtp_log_print, NULL);

    // turn on debug before creating/initializing the contexts, so those operations are visible
    if (debug) {
        srtp_set_debug_module("srtp", 1);
        srtp_set_debug_module("cipher", 1);
        srtp_set_debug_module("aes icm", 1);
        srtp_set_debug_module("auth func", 1);
        srtp_set_debug_module("hmac sha1", 1);
    }

    // initialize the policy that is used to create the context
    srtp_policy.next = NULL;
    srtp_policy.ssrc.type = (op == cryptop_encrypt ? ssrc_any_outbound : ssrc_any_inbound);
    srtp_policy.ssrc.value = 0;
    srtp_policy.key = master_key;
    srtp_crypto_policy_set_rtcp_default(&srtp_policy.rtcp);
    if (alg == srtp_alg_aes128_sha1_32bit) {
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&srtp_policy.rtp);
    } else {
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&srtp_policy.rtp);
    }

    // create the SRTP context
    srtp_status = srtp_create(&srtp_sess, &srtp_policy);
    if (srtp_err_status_ok != srtp_status) {
        fprintf(stdout, "\n%s: failed to create srtp context: %d!\n", progname, srtp_status);
        return;
    }

    output = pcap_open_dead_with_tstamp_precision(pcap_datalink(input), pcap_snapshot(input), pcap_get_tstamp_precision(input));
    if (NULL == output) {
        fprintf(stdout, "\n%s: unable to create output pcap!\n", progname);
        return;
    }

    dumper = pcap_dump_open(output, outfile.c_str());
    if (NULL == dumper) {
        fprintf(stdout, "\n%s: unable to open output file (%s)!\n", progname, outfile.c_str());
        return;
    }

    do {
        int result = rtp_pcap_get_next_packet(input, &total_pkt_count, filter, &packet);
        if (0 != result) {
            break;
        }

        if (stream_pkt_count == 0) {
            if (filter->flags & FILTER_FLAG_DST_FILTER) {
                filter->flags |= FILTER_FLAG_DADDR_SET | FILTER_FLAG_DPORT_SET;
                filter->daddr = packet.iph->daddr;
                filter->dport = packet.udph->dest;
            } else if (filter->flags & FILTER_FLAG_SRC_FILTER) {
                filter->flags |= FILTER_FLAG_SADDR_SET | FILTER_FLAG_SPORT_SET;
                filter->saddr = packet.iph->saddr;
                filter->sport = packet.udph->source;
            }
        }

        stream_pkt_count++;
        rtp_length = orig_length = packet.udph->len - sizeof(udphdr_t);

        if (op == cryptop_encrypt) {
            // TODO: distinguish RTP/RTCP
            srtp_status = srtp_protect(srtp_sess, packet.rtph, &rtp_length);
        } else {
            // TODO: distinguish SRTP/SRTCP
            srtp_status = srtp_unprotect(srtp_sess, packet.rtph, &rtp_length);
        }

        if (srtp_status != srtp_err_status_ok) {
            error_inc(errors, srtp_status);
            DEBUG_PRINT(
                "\n%s of packet[%d] failed: %s (%d)",
                rtp_pcap_cryptop_string(op),
                stream_pkt_count - 1,
                rtp_pcap_get_srtp_error_string(srtp_status),
                srtp_status
            );
            srtp_fail_count++;
            continue;
        }

        // adjust the packet
        delta_length = rtp_length - orig_length;
        packet.pcap_hdr.len += delta_length;
        packet.pcap_hdr.caplen += delta_length;
        packet.iph->tot_len += delta_length;
        packet.udph->len += delta_length;
        // TODO: recalculate checksums (instead of zero'ing out below)?
        packet.iph->check = 0;
        packet.udph->check = 0;

        // put things back into network byte order before writing to file
        rtp_pcap_iph_byteswap(packet.iph);
        rtp_pcap_udph_byteswap(packet.udph);

        // write the packet to the output
        pcap_dump((u_char *)dumper, &packet.pcap_hdr, packet.buffer);
        write_pkt_count++;
    } while (1);

    fprintf(stdout, "\n");
    fprintf(stdout, "\n%s: %s results", progname, rtp_pcap_cryptop_string(op));
    fprintf(stdout, "\n    %s key[%d]=%s", rtp_pcap_algorithm_string(alg), key_length, bin2hexString(master_key, key_length));
    if (errors.size()) {
        fprintf(stdout, "\n    %u srtp failures:", srtp_fail_count);
        for (SrtpErrorMap::const_iterator it = errors.begin(); it != errors.end(); it++) {
            fprintf(stdout, "\n        %-20s: %-8d", rtp_pcap_get_srtp_error_string(it->first), it->second);
        }
    } else {
        fprintf(stdout, "\n    No srtp failures");
    }
    fprintf(stdout, "\n    wrote %u packets to %s", write_pkt_count, outfile.c_str());
    fprintf(stdout, "\n");

    srtp_dealloc(srtp_sess);
    pcap_dump_close(dumper);
    pcap_close(output);
}

struct SrtpCommand {
    CommonArgs common;
    std::string alg;
    std::string key;
    std::string outfile;
    bool force;
    bool debug;

    SrtpCommand() : alg("aes128-sha1-32"), outfile("output.pcap"), force(false), debug(false) {}
};

static int run_srtp_action(const char *progname, SrtpCommand &command, cryptop_t op) {
    srtp_algorithm_t alg = srtp_alg_aes128_sha1_32bit;
    if (command.alg == "aes128-sha1-80") {
        alg = srtp_alg_aes128_sha1_80bit;
    }

    pcap_t *pcap_file = rtp_pcap_open_input(progname, command.common.filename.c_str());
    if (NULL == pcap_file) {
        return -2;
    }

    rtp_pcap_filter_t filter;
    command.common.init_filter(filter);
    rtp_pcap_srtp(progname, pcap_file, &filter, op, alg, command.force, command.debug, command.key, command.outfile);
    pcap_close(pcap_file);
    return 0;
}

static void add_srtp_command(CLI::App &app, int &exit_code, const char *progname, const char *name, const char *description, cryptop_t op) {
    shared_ptr<SrtpCommand> command = make_shared<SrtpCommand>();
    CLI::App *cmd = rtp_pcap_add_command(app, name, description);
    rtp_pcap_add_common_options(cmd, command->common);
    cmd->add_option("--alg", command->alg, "Cryptographic algorithm suite (default aes128-sha1-32)")
        ->default_val("aes128-sha1-32")
        ->transform(CLI::IsMember({"aes128-sha1-32", "aes128-sha1-80"}, CLI::ignore_case));
    cmd->add_option("--key", command->key, "Master key in hexadecimal or base64 format")->required()->type_name("hex|base64");
    cmd->add_option("--output", command->outfile, "Output filename (default output.pcap)")->default_val("output.pcap")->type_name("filename");
    cmd->add_flag("--force", command->force, "Overwrite existing output file");
    cmd->add_flag("--debug", command->debug, "Turn on libSRTP debug");

    string program(progname);
    cmd->callback([&exit_code, program, command, op]() { exit_code = run_srtp_action(program.c_str(), *command, op); });
}

void add_encrypt_command(CLI::App &app, int &exit_code, const char *progname) {
    add_srtp_command(app, exit_code, progname, ARG_ACT_ENCRYPT, "Encrypt single RTP stream to another PCAP", cryptop_encrypt);
}

void add_decrypt_command(CLI::App &app, int &exit_code, const char *progname) {
    add_srtp_command(app, exit_code, progname, ARG_ACT_DECRYPT, "Decrypt single RTP stream to another PCAP", cryptop_decrypt);
}
