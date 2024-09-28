#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

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

void ocall_sleep(int* sec) {
    /*
    Sleep for sec seconds outside the enclave
    */
    //printf("Sleeping for %d seconds outside the enclave...\r\n", *sec);
    sleep(*sec);
    //printf("Done sleeping outside the enclave\r\n");
}

#ifdef __cplusplus
}
#endif