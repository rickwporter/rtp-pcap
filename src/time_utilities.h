#pragma once

#include <stddef.h>
#include <sys/time.h>

long milliseconds(const struct timeval *tv);
double tv2seconds(const struct timeval *tv);
struct timeval seconds2tv(double timestamp);
char *timeofday(char *buffer, const size_t buflen, const struct timeval *tv);
char *datetime(char *buffer, const size_t buflen, const struct timeval *tv);
