#include <cstdio>
#include <ctime>

#include "time_utilities.h"

#define MSEC_PER_SEC 1000
#define USEC_PER_SEC 1000000

long milliseconds(const struct timeval *tv) { return long(tv->tv_usec / MSEC_PER_SEC); }

double tv_to_seconds(const struct timeval *tv) { return (double)(tv->tv_sec) + (double)(tv->tv_usec) / USEC_PER_SEC; }

struct timeval seconds_to_tv(double timestamp) {
    struct timeval tv;
    tv.tv_sec = (time_t)timestamp;
    tv.tv_usec = (suseconds_t)((timestamp - tv.tv_sec) * USEC_PER_SEC);
    return tv;
}

char *timeofday(char *buffer, const size_t buflen, const struct timeval *tv) {
    time_t nowtime = tv->tv_sec;
    struct tm *nowtm;
    char tmbuf[64];

    nowtm = gmtime(&nowtime);
    strftime(tmbuf, sizeof(tmbuf), "%H:%M:%S", nowtm);
    snprintf(buffer, buflen, "%s.%03ld GMT", tmbuf, milliseconds(tv));
    return buffer;
}

char *datetime(char *buffer, const size_t buflen, const struct timeval *tv) {
    time_t nowtime = tv->tv_sec;
    struct tm *nowtm;
    char tmbuf[64];

    nowtm = gmtime(&nowtime);
    strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(buffer, buflen, "%s.%03ld GMT", tmbuf, milliseconds(tv));
    return buffer;
}

char g_time_buffer[128];

char *
rtp_pcap_format_start_time_r(time_display_t time_type, char *buffer, size_t buflen, const struct timeval *tv, const struct timeval *capture_start) {
    if (time_type == tdisp_capture) {
        snprintf(buffer, buflen, "%0.3f", tv_to_seconds(tv) - tv_to_seconds(capture_start));
        return buffer;
    }
    if (time_type == tdisp_timeofday) {
        timeofday(buffer, buflen, tv);
        return buffer;
    }
    if (time_type == tdisp_datetime) {
        datetime(buffer, buflen, tv);
        return buffer;
    }

    return NULL;
}

char *rtp_pcap_format_start_time(time_display_t time_type, const struct timeval *tv, const struct timeval *capture_start) {
    return rtp_pcap_format_start_time_r(time_type, g_time_buffer, sizeof(g_time_buffer), tv, capture_start);
}
