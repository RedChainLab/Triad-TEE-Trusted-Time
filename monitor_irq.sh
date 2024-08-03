#!/bin/bash

# Initialize variables
prev_irq_count=$(cat /proc/interrupts | grep -c -P '\d+:')  # Initial IRQ count

# Function to get current IRQ count
get_irq_count() {
    cat /proc/interrupts | grep -c -P '\d+:'
}

# Main loop to monitor IRQ count changes
while true; do
    current_irq_count=$(get_irq_count)
    new_irq_count=$((current_irq_count - prev_irq_count))
    
    echo "New IRQ occurrences in the last second: $new_irq_count"
    
    prev_irq_count=$current_irq_count
    
    sleep 1  # Wait for 1 second
done