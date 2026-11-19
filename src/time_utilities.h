#pragma once

#include <stddef.h>
#include <sys/time.h>

#include "arguments.h"

long milliseconds(const struct timeval *tv);
double tv_to_seconds(const struct timeval *tv);
struct timeval seconds_to_tv(double timestamp);
char *timeofday(char *buffer, const size_t buflen, const struct timeval *tv);
char *datetime(char *buffer, const size_t buflen, const struct timeval *tv);

// Writes a list/summary start time into buffer and returns buffer.
// capture is seconds since capture_start, the first packet in the file.
// timeofday and datetime are clock forms of the packet timestamp.
// Returns NULL for tdisp_none and for modes those actions do not offer.
char *
rtp_pcap_format_start_time_r(time_display_t time_type, char *buffer, size_t buflen, const struct timeval *tv, const struct timeval *capture_start);

// Returns the formatted start time, or NULL when the reentrant version returns NULL.
// The pointer is only valid until the next call.
char *rtp_pcap_format_start_time(time_display_t time_type, const struct timeval *tv, const struct timeval *capture_start);
