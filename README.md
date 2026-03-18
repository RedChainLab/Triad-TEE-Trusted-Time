# An Open-source Implementation and Security Analysis of Triad's TEE Trusted Time Protocol (DSN-S'25)

This repository contains the source code for the open implementation of the Triad TEE Trusted Time protocol [[Fernandez et al., 2023](https://doi.org/10.1109/CloudCom59040.2023.00037)], as well as scripts to run experiments and attacks on Triad, as well as generate figures presented in the paper "An Open-source Implementation and Security Analysis of Triad's TEE Trusted Time Protocol" published at the DSN'25 conference ([doi:10.1109/DSN-S65789.2025.00053](http://dx.doi.org/10.1109/DSN-S65789.2025.00053)).

## How to cite
```
M. Bettinger, S. Ben Mokhtar and A. Simonet-Boulogne, "An Open-source Implementation and Security Analysis of Triad’s TEE Trusted Time Protocol," 2025 55th Annual IEEE/IFIP International Conference on Dependable Systems and Networks - Supplemental Volume (DSN-S), Naples, Italy, 2025, pp. 133-139, doi: 10.1109/DSN-S65789.2025.00053.
```
```bib
@INPROCEEDINGS{11068371,
  author={Bettinger, Matthieu and Ben Mokhtar, Sonia and Simonet-Boulogne, Anthony},
  booktitle={2025 55th Annual IEEE/IFIP International Conference on Dependable Systems and Networks - Supplemental Volume (DSN-S)}, 
  title={An Open-source Implementation and Security Analysis of Triad’s TEE Trusted Time Protocol}, 
  year={2025},
  volume={},
  number={},
  pages={133-139},
  keywords={Trusted computing;Protocols;Scheduling algorithms;Operating systems;Control systems;Delays;Security;Logic;Resilience;Clocks;resilience;delay attack;trusted execution environment (TEE);trusted time},
  doi={10.1109/DSN-S65789.2025.00053}
}
```
## Dependencies

- SGX-enabled hardware (AEX Notify handlers only work in hardware mode, not in simulation)
- AEX Notify availability in kernel: Linux kernel >=6.2
- [Intel SGX-SDK](https://github.com/intel/linux-sgx/tree/sgx_2.24) (tested with version 2.24.100.3)
- `make` apt package
- For figure generation (you can use `make deps`): 
    - Python3, numpy, pandas, and matplotlib packages
    - Latex packages (e.g., for Ubuntu: `sudo apt-get install dvipng texlive-latex-extra texlive-fonts-recommended cm-super`)
- The `msr` kernel module is necessary for some monitoring/attacks: use `sudo apt-get install msr-tools`

## Compiling and running Triad

```sh
make
time_authority/server &
make exp
<enter_any_text>
```
creates a logfile `triad-<datetime>.log` in `out/log`

To generate figures:
```sh
analysis/grep_ts.sh <logfile-basename>
python analysis/plot_ts_drift.py <logfile-basename>
```
e.g.:
```sh
analysis/grep_ts.sh triad-2025-03-24-19-33-44
python analysis/plot_ts_drift.py triad-2025-03-24-19-33-44
```

For automated monitoring purposes:
```sh
export LOGFILE="triad-2025-03-24-19-33-44"; watch -n 60 "analysis/grep_ts.sh $LOGFILE; python analysis/plot_ts_drift.py $LOGFILE"
```

## Low-interruption environment example

In `/etc/default/grub`:
```sh
GRUB_CMDLINE_LINUX_DEFAULT="console=tty0 console=ttyS0,115200n8 console=ttyS1,115200n8 mitigations=off nmi_watchdog=0 nosoftlockup nohz=on nohz_full=2-4,18-20 kthread_cpus=0,16 irqaffinity=0,16 isolcpus=nohz,managed_irq,domain,2-4,18-20 tsc=nowatchdog nowatchdog rcu_nocbs=2-4,18-20 rcu_nocb_poll skew_tick=1 intel_pstate=disable intel_idle.max_cstate=0 processor.max_cstate=0"
```

## Simulating interruptions:
```sh
triad_udp/analysis/sim_interrupts.sh <core> [<proba_in_%oo>-<sleep_time_in_sec>]...
```
e.g., to reproduce interruptions from the Triad paper and log per-core interruption-simulation's start/stop in `out/interrupts.log`:
```sh
export CORE=3; echo "$CORE;`date +%Y-%m-%d-%H-%M-%S`" >> out/interrupts.log; analysis/sim_interrupts.sh $CORE 3400-0.01 3300-0.532 3300-1.5895; echo "$CORE;`date +%Y-%m-%d-%H-%M-%S`">> out/interrupts.log
```
