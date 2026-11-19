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

static void test_tv_to_seconds() {
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 500000;
    EXPECT(tv_to_seconds(&tv) == 2.5);
}

static void test_seconds_to_tv() {
    struct timeval back = seconds_to_tv(2.5);
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
    EXPECT(rtp_pcap_format_start_time(tdisp_none, &tv, &capture_start) == NULL);
    EXPECT(rtp_pcap_format_start_time_r(tdisp_none, buffer, sizeof(buffer), &tv, &capture_start) == NULL);
    EXPECT(rtp_pcap_format_start_time(tdisp_previous, &tv, &capture_start) == NULL);
    EXPECT(rtp_pcap_format_start_time_r(tdisp_previous, buffer, sizeof(buffer), &tv, &capture_start) == NULL);
    EXPECT(rtp_pcap_format_start_time_r(tdisp_capture, buffer, sizeof(buffer), &tv, &capture_start) == buffer);
    EXPECT_STREQ(buffer, "2.250");
    EXPECT_STREQ(rtp_pcap_format_start_time(tdisp_capture, &tv, &capture_start), "2.250");
    EXPECT(rtp_pcap_format_start_time_r(tdisp_timeofday, buffer, sizeof(buffer), &tv, &capture_start) == buffer);
    EXPECT_STREQ(buffer, "00:00:03.500 GMT");
    EXPECT_STREQ(rtp_pcap_format_start_time(tdisp_timeofday, &tv, &capture_start), "00:00:03.500 GMT");
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    EXPECT(rtp_pcap_format_start_time_r(tdisp_datetime, buffer, sizeof(buffer), &tv, &capture_start) == buffer);
    EXPECT_STREQ(buffer, "1970-01-01 00:00:00.000 GMT");
    EXPECT_STREQ(rtp_pcap_format_start_time(tdisp_datetime, &tv, &capture_start), "1970-01-01 00:00:00.000 GMT");
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
    RUN_TEST(test_tv_to_seconds);
    RUN_TEST(test_seconds_to_tv);
    RUN_TEST(test_timeofday);
    RUN_TEST(test_datetime);
    RUN_TEST(test_rtp_pcap_format_start_time);
}
