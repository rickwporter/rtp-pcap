#pragma once

#if INCLUDE_SRTP
int run_encrypt(const char *progname, int argc, char *argv[]);
int run_decrypt(const char *progname, int argc, char *argv[]);
#endif // INCLUDE_SRTP
