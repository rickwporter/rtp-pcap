#include <algorithm>
#include <arpa/inet.h> // for inet_ntoa()
#include <cstdio>
#include <cstdlib>
#include <cstring> // for memset()
#include <netinet/in.h>

#include <CLI/CLI.hpp>
#include <memory>
#include <pcap/pcap.h>

#include "action_stats.h"
#include "arguments.h"
#include "packet_utilities.h"
#include "rtp_utils.h"
#include "time_utilities.h"

using namespace std;

class StreamStats {
  private:
    // hide the default constructor -- need to provide start/end times
    StreamStats() {}

  public:
    double start_time;
    double end_time;
    uint32_t packets;
    uint16_t last_seq;
    uint32_t count_delta;
    double min_delta;
    double max_delta;
    double sum_delta;
    uint8_t last_pt;
    int pt_changes;
    int lost;
    int misordered;
    int seq_jumps;

    StreamStats(double time)
        : start_time(time), end_time(time), packets(0), last_seq(0), count_delta(0), min_delta(1000.0), max_delta(0.0), sum_delta(0.0), last_pt(0),
          pt_changes(0), lost(0), misordered(0), seq_jumps(0) {}

    void add_delta(double delta) {
        this->max_delta = max(this->max_delta, delta);
        this->min_delta = min(this->min_delta, delta);
        this->sum_delta += delta;
        this->count_delta += 1;
    }

    void set_seq(uint16_t seq) {
        // Set the last sequence number and other related items.
        if (this->packets) {
            int delta = (seq - this->last_seq - 1);
            if ((uint16_t)delta == 0) {
            } else if (abs(delta) > RTP_STATS_WINDOW_PACKETS) {
                printf("last=%d, curr=%d, delta=%d\n", this->last_seq, seq, delta);
                this->seq_jumps += 1;
            } else if (delta > 0) {
                this->lost += delta;
            } else if (delta < 0) {
                this->misordered += 1;
            }
        }
        this->last_seq = seq;
    }

    void set_pt(uint8_t pt) {
        // Set last payload type
        if (this->packets && this->last_pt != pt) {
            this->pt_changes += 1;
        }
        this->last_pt = pt;
    }

    double mean_delta() const {
        if (this->count_delta == 0) {
            return 0.0;
        }
        return this->sum_delta / this->count_delta;
    }

    double duration() const { return this->end_time - this->start_time; }
};

typedef map<uint32_t, StreamStats *> StreamStatMap;

static void rtp_pcap_stats(pcap_t *pcap_file, rtp_pcap_filter_t *filter, time_display_t time_type) {
    uint32_t stream_pkt_count = 0;
    uint32_t total_pkt_count = 0;
    struct timeval last_clock;
    struct timeval first_clock;
    bool first_packet = true;
    rtp_pcap_pkt_t packet; // on stack place to hold data
    rtphdr_t *rtph = NULL; // pointer within current packet
    StreamStatMap stats = StreamStatMap();

    memset(&last_clock, 0, sizeof(last_clock));
    memset(&first_clock, 0, sizeof(first_clock));

    do {
        int result = rtp_pcap_get_next_packet(pcap_file, &total_pkt_count, filter, &packet);
        if (0 != result) {
            break;
        }

        if (first_packet) {
            first_clock = packet.pcap_hdr.ts;
            first_packet = false;
        }

        rtph = packet.rtph;
        if (stream_pkt_count == 0 && rtp_hdr_get_version(rtph) != RFC_1889_VERSION) {
            // ignore non-rtp streams
            continue;
        }

        stream_pkt_count++;

        // lock down the filter on the address/port, and initialize the clock
        if (stream_pkt_count == 1) {
            if (filter->flags & FILTER_FLAG_DST_FILTER) {
                filter->flags |= FILTER_FLAG_DADDR_SET | FILTER_FLAG_DPORT_SET;
                filter->daddr = packet.iph->daddr;
                filter->dport = packet.udph->dest;
            } else if (filter->flags & FILTER_FLAG_SRC_FILTER) {
                filter->flags |= FILTER_FLAG_SADDR_SET | FILTER_FLAG_SPORT_SET;
                filter->saddr = packet.iph->saddr;
                filter->sport = packet.udph->source;
            }
            last_clock = packet.pcap_hdr.ts;
        }

        rtph = packet.rtph;
        if (RFC_1889_VERSION != rtp_hdr_get_version(rtph)) {
            continue;
        }

        double current = tv2seconds(&packet.pcap_hdr.ts);
        uint32_t ssrc = rtp_hdr_get_ssrc(rtph);
        StreamStats *info = NULL;
        StreamStatMap::const_iterator it = stats.find(ssrc);
        if (it != stats.end()) {
            info = it->second;
        } else {
            info = new StreamStats(current);
            stats[ssrc] = info;
        }

        if (!rtp_hdr_get_marker(rtph) && ((info->last_seq + 1) & 0xffff) == rtp_hdr_get_sequence(rtph) && info->packets > 0) {
            info->add_delta(current - info->end_time);
        }
        info->set_pt(rtp_hdr_get_ptype(rtph));
        info->set_seq(rtp_hdr_get_sequence(rtph));
        info->packets += 1;
        info->end_time = current;
    } while (1);

    if (stats.size() == 0) {
        fprintf(stdout, "No matching RTP packets found.");
        return;
    }

    struct in_addr addr;
    addr.s_addr = htonl((filter->flags & FILTER_FLAG_DST_FILTER ? filter->daddr : filter->saddr));
    fprintf(
        stdout,
        "IP %s: %s:%d, %u packets (%u in capture)\n",
        filter->flags & FILTER_FLAG_DST_FILTER ? "destination" : "source",
        inet_ntoa(addr),
        filter->flags & FILTER_FLAG_DST_FILTER ? filter->dport : filter->sport,
        stream_pkt_count,
        total_pkt_count
    );
    for (StreamStatMap::const_iterator it = stats.begin(); it != stats.end(); it++) {
        uint32_t ssrc = it->first;
        StreamStats *info = it->second;
        struct timeval start_tv = seconds2tv(info->start_time);
        struct timeval end_tv = seconds2tv(info->end_time);
        char start_buffer[64];
        char end_buffer[64];
        char *start_time = NULL;
        char *end_time = NULL;

        if (time_type == time_display_t::tdisp_date) {
            start_time = datetime(start_buffer, sizeof(start_buffer), &start_tv);
            end_time = datetime(end_buffer, sizeof(end_buffer), &end_tv);
        } else if (time_type == time_display_t::tdisp_timeofday) {
            start_time = timeofday(start_buffer, sizeof(start_buffer), &start_tv);
            end_time = timeofday(end_buffer, sizeof(end_buffer), &end_tv);
        } else if (time_type == time_display_t::tdisp_startcapture) {
            double cap_start = tv2seconds(&first_clock);
            snprintf(start_buffer, sizeof(start_buffer), "%0.3f", info->start_time - cap_start);
            snprintf(end_buffer, sizeof(end_buffer), "%0.3f", info->end_time - cap_start);
            start_time = start_buffer;
            end_time = end_buffer;
        }
        fprintf(stdout, "  0x%08X:\n", ssrc);
        if (start_time) {
            fprintf(stdout, "      start-time: %s\n", start_time);
        }
        if (end_time) {
            fprintf(stdout, "        end-time: %s\n", end_time);
        }
        fprintf(stdout, "        duration: %0.3f seconds\n", info->duration());
        fprintf(stdout, "         packets: %d\n", info->packets);
        fprintf(stdout, "            lost: %d\n", info->lost);
        fprintf(stdout, "      misordered: %d\n", info->misordered);
        fprintf(stdout, "           jumps: %d\n", info->seq_jumps);
        fprintf(stdout, "      pt changes: %d\n", info->pt_changes);
        fprintf(stdout, "           delta:\n");
        fprintf(stdout, "                min: %0.3f msecs\n", info->min_delta * 1000);
        fprintf(stdout, "               mean: %0.3f msecs\n", info->mean_delta() * 1000);
        fprintf(stdout, "                max: %0.3f msecs\n", info->max_delta * 1000);
    }

    return;
}

struct StatsCommand {
    CommonArgs common;
    std::string time;

    StatsCommand() : time("capture") {}
};

static int run_stats(const char *progname, StatsCommand &command) {
    pcap_t *pcap_file = rtp_pcap_open_input(progname, command.common.filename.c_str());
    if (NULL == pcap_file) {
        return -2;
    }

    rtp_pcap_filter_t filter;
    command.common.init_filter(filter);
    rtp_pcap_stats(pcap_file, &filter, rtp_pcap_time_display_parse(command.time));
    pcap_close(pcap_file);
    return 0;
}

void add_stats_command(CLI::App &app, int &exit_code, const char *progname) {
    shared_ptr<StatsCommand> command = make_shared<StatsCommand>();
    CLI::App *cmd = rtp_pcap_add_command(app, ARG_ACT_STATS, "Provide RTP packet statistics for a stream");
    rtp_pcap_add_common_options(cmd, command->common);
    rtp_pcap_add_time_option(cmd, command->time, "capture", "Time display format (default capture)");

    string program(progname);
    cmd->callback([&exit_code, program, command]() { exit_code = run_stats(program.c_str(), *command); });
}
