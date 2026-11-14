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

static void test_datetime() {
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    char buffer[64];
    EXPECT_STREQ(datetime(buffer, sizeof(buffer), &tv), "1970-01-01 00:00:00.000 GMT");
}

void test_time_utilities() {
    test_milliseconds();
    test_tv2seconds();
    test_seconds2tv();
    test_timeofday();
    test_datetime();
}
