#pragma once

#if INCLUDE_SRTP
namespace CLI {
class App;
}

void add_encrypt_command(CLI::App &app, int &exit_code, const char *progname);
void add_decrypt_command(CLI::App &app, int &exit_code, const char *progname);
#endif // INCLUDE_SRTP
