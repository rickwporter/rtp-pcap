#pragma once

namespace CLI {
class App;
}

void add_list_command(CLI::App &app, int &exit_code, const char *progname);
