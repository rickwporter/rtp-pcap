#include <cstdio>
#include <ctime>

#include "time_utilities.h"

#define MSEC_PER_SEC 1000
#define USEC_PER_SEC 1000000

long milliseconds(const struct timeval *tv) { return long(tv->tv_usec / MSEC_PER_SEC); }

double tv2seconds(const struct timeval *tv) { return (double)(tv->tv_sec) + (double)(tv->tv_usec) / USEC_PER_SEC; }

struct timeval seconds2tv(double timestamp) {
    struct timeval tv;
    tv.tv_sec = (time_t)timestamp;
    tv.tv_usec = (suseconds_t)((timestamp - tv.tv_sec) * USEC_PER_SEC);
    return tv;
}

char *timeofday(char *buffer, const size_t buflen, const struct timeval *tv) {
    time_t nowtime = tv->tv_sec;
    struct tm *nowtm;
    char tmbuf[64];

    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof(tmbuf), "%H:%M:%S", nowtm);
    snprintf(buffer, buflen, "%s.%03ld", tmbuf, milliseconds(tv));
    return buffer;
}

char *datetime(char *buffer, const size_t buflen, const struct timeval *tv) {
    time_t nowtime = tv->tv_sec;
    struct tm *nowtm;
    char tmbuf[64];

    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(buffer, buflen, "%s.%03ld", tmbuf, milliseconds(tv));
    return buffer;
}
