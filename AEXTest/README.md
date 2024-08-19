# AEX Test

This project measures the number of [AEX-Notify](https://www.intel.com/content/www/us/en/content-details/736463/white-paper-asynchronous-enclave-exit-notify-and-the-edeccssa-user-leaf-function.html) events that occur during a given amount of time.

## Functionalities

The project makes one thread increment a counter and monitors the number of AEX Notify events that occur during this counting. Another thread handles the delay measurement, either by sleeping outside of the enclave (i.e., using a standard `sleep`), or by running code for a while.

## Dependencies

- SGX-enabled hardware (AEX Notify handlers only work in hardware mode, not in simulation)
- AEX Notify availability in kernel: Linux kernel >=6.2
- [Intel SGX-SDK](https://github.com/intel/linux-sgx/tree/sgx_2.24) (tested with version 2.24.100.3)
- `make` apt package

## Building AEX Test

To compile the `app` executable:
``` sh
make
```

## Running AEX Test

A makefile recipe `make run` is available with example parameters.

The command line template is the following:
``` sh
./app <sleep_time> <sleep_inside_enclave> [<core_main> <core_add>]
```
with `<sleep_time>` the number of seconds to run the test; `<sleep_inside_enclave>` whether to measure elapsed time outside the enclave (with value `0`) or inside (with value `0`); `<core_main>` the core mask where the main process and thread will be pinned (e.g., for core 2: value `4`, i.e., `0b0010`); `<core_add>` the core mask where the main process and thread will be pinned (e.g., for core 3: value `4`, i.e., `0b0100`).