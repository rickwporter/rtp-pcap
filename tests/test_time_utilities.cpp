#include "test_harness.h"
#include "time_utilities.h"

static void test_milliseconds() {
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 1500;
    EXPECT(milliseconds(&tv) == 1);
    tv.tv_usec = 999;
    EXPECT(milliseconds(&tv) == 0);
}

static void test_tv2seconds() {
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 500000;
    EXPECT(tv2seconds(&tv) == 2.5);
}

static void test_seconds2tv() {
    struct timeval back = seconds2tv(2.5);
    EXPECT(back.tv_sec == 2);
    EXPECT(back.tv_usec == 500000);
}

static void test_timeofday() {
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    char buffer[64];
    EXPECT_STREQ(timeofday(buffer, sizeof(buffer), &tv), "00:00:00.000 GMT");
}

static void test_rtp_pcap_format_start_time() {
    struct timeval capture_start;
    capture_start.tv_sec = 1;
    capture_start.tv_usec = 250000;
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 500000;
    char buffer[64];
    EXPECT(!rtp_pcap_format_start_time(tdisp_none, buffer, sizeof(buffer), &tv, &capture_start));
    EXPECT(!rtp_pcap_format_start_time(tdisp_prevpacket, buffer, sizeof(buffer), &tv, &capture_start));
    EXPECT(rtp_pcap_format_start_time(tdisp_startcapture, buffer, sizeof(buffer), &tv, &capture_start));
    EXPECT_STREQ(buffer, "2.250");
    EXPECT(rtp_pcap_format_start_time(tdisp_timeofday, buffer, sizeof(buffer), &tv, &capture_start));
    EXPECT_STREQ(buffer, "00:00:03.500 GMT");
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    EXPECT(rtp_pcap_format_start_time(tdisp_date, buffer, sizeof(buffer), &tv, &capture_start));
    EXPECT_STREQ(buffer, "1970-01-01 00:00:00.000 GMT");
}

static void test_datetime() {
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    char buffer[64];
    EXPECT_STREQ(datetime(buffer, sizeof(buffer), &tv), "1970-01-01 00:00:00.000 GMT");
}

void test_time_utilities() {
    RUN_TEST(test_milliseconds);
    RUN_TEST(test_tv2seconds);
    RUN_TEST(test_seconds2tv);
    RUN_TEST(test_timeofday);
    RUN_TEST(test_datetime);
    RUN_TEST(test_rtp_pcap_format_start_time);
}
