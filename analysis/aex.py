import matplotlib.pyplot as plt
import math
RATIO=15665267190 / 20E3

# Read the timestamps from the file
timestamps = []
with open('aex.log', 'r') as file:
    for line in file:
        timestamps.append(line.strip())

#print(timestamps)
# Calculate the differences between successive timestamps
differences = []
for i in range(1, len(timestamps)):
    #print(i, timestamps[i], timestamps[i-1])
    diff = (int(timestamps[i]) - int(timestamps[i-1])) / RATIO
    differences.append(diff)
print(RATIO)
x_range_major=[x/10 for x in range(0,math.ceil(10*max(differences)+1),5)]
x_range_minor=[x/10 for x in range(0,math.ceil(10*max(differences)+1),1)]
# Create a histogram of the differences
plt.figure()
plt.hist(differences, bins=x_range_minor, alpha=0.5, color='green', cumulative=True, histtype='step', linewidth=2)
# Set minor and major grid
plt.grid(axis="x",which='both', linestyle='--', linewidth=0.5, alpha=0.3)
plt.grid(axis="x",which='major', color='black', linestyle='-', linewidth=1, alpha=0.5)

# Set minor and major ticks
plt.xticks(x_range_major)
plt.xticks(x_range_minor, minor=True)
plt.xlabel('Delay (ms)')
plt.ylabel('AEX count')
plt.title('Histogram of Differences')
plt.grid(True)

# Create a cumulative plot
plt.figure()
plt.plot(sorted(timestamps), range(1, len(timestamps) + 1), color='red')
plt.xlabel('Timestamp')
plt.ylabel('Cumulative Count')
plt.title('Cumulative Plot of Timestamps')
plt.grid(True)

# Show the plots
plt.show()