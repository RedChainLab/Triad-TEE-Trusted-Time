#!/bin/bash

# Stop irqbalance if running
sudo systemctl stop irqbalance
sudo systemctl disable irqbalance
sudo systemctl mask irqbalance

# Function to set affinity to CPU 0 for an IRQ
set_affinity_to_cpu0() {
    irq_identifier=$1
    echo "Setting affinity for IRQ $irq_identifier to CPU 0"
    echo 1 > /proc/irq/$irq_identifier/smp_affinity
}

# List of named IRQs
named_irqs=("NMI" "LOC" "SPU" "PMI" "IWI" "RTR" "RES" "CAL" "TLB" "TRM" "THR" "DFR" "MCE" "MCP" "ERR" "MIS" "PIN" "NPI" "PIW")

echo "Enumerating IRQs from /proc/interrupts..."
cat /proc/interrupts | grep -oP '\d+:.*' | while read -r line; do
    echo $line
    irq_number=$(echo $line | awk '{print $1}' | sed 's/://')
    set_affinity_to_cpu0 $irq_number
done

# Set affinity for named IRQs
#for irq in "${named_irqs[@]}"; do
#    set_affinity_to_cpu0 $irq
#done

echo "IRQ affinity set successfully."   