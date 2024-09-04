#ifndef PARSING_H
#define PARSING_H

#include <string>
#include <cstring>
#include <cstdlib>
#include "../common.h"

long long int extract_ts(const char *buffer);
uint64_t extract_server_time(const char *buffer);


#endif // PARSING_H