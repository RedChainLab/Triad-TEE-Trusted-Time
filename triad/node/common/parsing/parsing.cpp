#include "parsing.h"

/*
uint64_t extract_ts(const char *buffer) {
    const char *start_tag = "<p>";
    const char *end_tag = "</p>";
    uint64_t number;
    char *start = strstr(buffer, start_tag);
    if (!start) {
        return -1; 
    }
    start += strlen(start_tag);
    char *end = strstr(start, end_tag);
    if (!end) {
        return -1; 
    }
    char number_str[20];
    strncpy(number_str, start, end - start);
    number_str[end - start] = '\0';

    t_print("ts : %s\n", number_str);
    number = strtoll(number_str, NULL, 10);
    t_print("ts : %ld\n", number);
    return number;
}
*/
long long int extract_ts(const char *buffer) {
    const char *start_tag = "<p>";
    const char *end_tag = "</p>";
    uint64_t number;
    char *start = strstr(buffer, start_tag);
    if (!start) {
        return -1; 
    }
    start += strlen(start_tag);
    char *end = strstr(start, end_tag);
    if (!end) {
        return -1; 
    }
    char number_str[20];
    strncpy(number_str, start, end - start);
    number_str[end - start] = '\0';
    number = strtoll(number_str, NULL, 10);
    return number;
}

uint64_t extract_server_time(const char *buffer) {
    const char *start_tag = "<p>";
    const char *end_tag = "</p>";
    uint64_t number;
    char *start = strstr(buffer, start_tag);
    if (!start) {
        return -1; 
    }
    start += strlen(start_tag);
    char *end = strstr(start, end_tag);
    if (!end) {
        return -1; 
    }
    char number_str[20];
    strncpy(number_str, start, end - start);
    number_str[end - start] = '\0';

    t_print("ts : %s\n", number_str);
    number = strtoll(number_str, NULL, 10);
    t_print("ts : %ld\n", number);
    return number;
}