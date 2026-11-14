#include "test_harness.h"

int g_failed = 0;
std::string g_tmpdir;

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    TempDir temp;
    test_time_utilities();
    test_hexutils();
    test_base64();
    test_arguments();
    test_rtp_utils();
    test_packet_utilities();
    test_action_details();
    test_action_list();
    test_action_summary();
    test_action_stats();
#if INCLUDE_SRTP
    test_action_srtp();
#endif
    test_rtp_pcap();

    if (g_failed != 0) {
        fprintf(stderr, "%d unit test assertion(s) failed\n", g_failed);
        return 1;
    }
    printf("unit tests passed\n");
    return 0;
}
