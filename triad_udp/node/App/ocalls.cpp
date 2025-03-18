#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

void ocall_print_string(const char *str)
{
    printf("%s", str);
}


void ocall_readTSC(long long* ts) {
    /*
    Read the TSC register
    */
    #if defined(_MSC_VER) // MSVC specific
        *ts = __rdtsc();
    #elif defined(__GNUC__) || defined(__clang__) // GCC or Clang specific
        unsigned int lo, hi;
        __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
        *ts = ((uint64_t)hi << 32) | lo;
    #else
    #error "Compiler not supported"
    #endif
}

void ocall_sleep(int sec) {
    /*
    Sleep for sec seconds outside the enclave
    */
    sleep(sec);
}

void ocall_usleep(int usec) {
    /*
    Sleep for usec microseconds outside the enclave
    */
    usleep(usec);
}

void ocall_timespec_get(struct timespec* ts) {
    /*
    Get the current time
    */
    timespec_get(ts, TIME_UTC);
    // char buff[100];
    // strftime(buff, sizeof buff, "%D %T", gmtime(&(ts->tv_sec)));
    // printf("[utrst]> Current time: %s.%09ld UTC\n", buff, ts->tv_nsec);
}

void ocall_timespec_print(struct timespec* ts, int id, int caller) {
    /*
    Print the time
    */
    char buff[100];
    strftime(buff, sizeof buff, "%D %T", gmtime(&(ts->tv_sec)));
    switch(caller)
    {
        case 0:
            printf("[utrst-%s %d]> TS Time: %s.%09ld UTC\n", "Handler", id, buff, ts->tv_nsec);
            break;
        case 1:
            printf("[utrst-%s %d]> TS Time: %s.%09ld UTC\n", "ENode", id, buff, ts->tv_nsec);
            break;
        case 2: 
            printf("[utrst-%s %d]> TS Time: %s.%09ld UTC\n", "TA", id, buff, ts->tv_nsec);
            break;  
        case 3: 
            printf("[utrst-StateSwitch %d]> %s Time: %s.%09ld UTC\n", id, "OK", buff, ts->tv_nsec);
            break;
        case 4: 
            printf("[utrst-StateSwitch %d]> %s Time: %s.%09ld UTC\n", id, "Tainted", buff, ts->tv_nsec);
            break;
        case 5:
            printf("[utrst-StateSwitch %d]> %s Time: %s.%09ld UTC\n", id, "RefCalib", buff, ts->tv_nsec);
            break;
        case 6:
            printf("[utrst-StateSwitch %d]> %s Time: %s.%09ld UTC\n", id, "FullCalib", buff, ts->tv_nsec);
            break;
        default:
            printf("[utrst-%s %d]> TS Time: %s.%09ld UTC\n", "Unknown", id, buff, ts->tv_nsec);
            break;
    }
}

#ifdef __cplusplus
}
#endif