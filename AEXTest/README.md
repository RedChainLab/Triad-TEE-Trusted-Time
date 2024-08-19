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
of using the makefile:
``` sh
make run [CORE_MAIN=2] [CORE_ADD=4] [SLEEP_IN_ENCLAVE=0] [SLEEP_TIME=10]
```
with `<sleep_time>` the number of seconds to run the test; `<sleep_inside_enclave>` whether to measure elapsed time outside the enclave (with value `0`) or inside (with value `0`); `<core_main>` the core id where the main process and thread will be pinned (e.g., for core 2: value `2`); `<core_add>` the core id where the main process and thread will be pinned (e.g., for core 3: value `4`).

### Running for experiments

A makefile recipe `make exp` is available that automatically outputs results in a timestamped file `aex-<sleep_time_s>-<timestamp>.csv` (e.g., `aex-30-2024-08-19-10-10-05.csv`):
``` sh
make exp [CORE_MAIN=2] [CORE_ADD=4] [SLEEP_IN_ENCLAVE=0] [SLEEP_TIME=10]
```

### Plotting results

Python scripts are available in the `analysis` folder.
All follow the same interface `python <script_name> <results_file_name>.csv [0|1]`, with `results_file_name` the name of a file obtained during an experiment run (e.g., with `make exp` in the previous section), and a parameter 0 or 1 if few or many AEX occured in that experiment (in order to adapt the axis ticks).
The script `gen_plots.sh` in this same `analysis` folder enables to run all 3 scripts on all `.csv` files in the `out` folder, with the same parameter 0 or 1 as the Python scripts, i.e., by running:
``` sh
sh gen_plots.sh [0|1]
```
Available Python scripts do the following:
- `aex_timeline.py` plots the number of AEX events over the experiment timeframe;
- `aex_difference.py` plots the cumulative number of AEX events which occured *x* (milli)seconds after the previous one;
- `aex_ttpAEX.py` plots for each numbered AEX event the time since the previous AEX event.
