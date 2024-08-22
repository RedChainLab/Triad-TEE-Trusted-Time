import matplotlib.pyplot as plt
import math
import sys
import pandas as pd
import numpy as np

params = {'text.usetex' : True,
          'font.size' : 10,
            'font.family' : 'serif',
            'font.serif' : 'Computer Modern Roman',
          }
plt.rcParams.update(params) 

# Files in out/count directory are in the naming format count-<timestamp>-<in_enclave>-<sleep_time_secs>-<repeat_id>.csv
# Get <in_enclave> <sleep_time_secs> from command line arguments
in_enclave = sys.argv[1]
sleep_time_secs = sys.argv[2]

# Get all files in out/count directory that match in_enclave and sleep_time_secs
import os
import re
import progressbar
files = os.listdir('out/count')
files = [f for f in files if re.match(f'count-.*-{in_enclave}-{sleep_time_secs}-.*', f)]
#print(files)

# Group files by timestamp
timestamps = set(["-".join(f.split('-')[1:7]) for f in files])
#print(timestamps)

# For each timestamp, plot the count distribution
for timestamp in timestamps:
    files_timestamp = [f for f in files if timestamp=="-".join(f.split('-')[1:7])]
    #print(files_timestamp)
    agg_df = pd.DataFrame()
    for f in progressbar.progressbar(files_timestamp):
      try:
        with open(f'out/count/{f}', 'r') as file:
            df = pd.read_csv(file, sep=';', header=0, index_col=0)
            #print(df)
            agg_df = pd.concat([agg_df, df.tail(1)])
      except Exception as e:
        print(f'Error reading {f}: {e}\n')
    #print(agg_df)
    fig, ax = plt.subplots()
    ax.hist(agg_df['count'], bins=50, label='AEX', histtype='step', linewidth=1)
    ax.hist(agg_df['count'], bins=50, label='AEX', histtype='step', linewidth=1, cumulative=True)
    ax.set_xlabel('Number of increments')
    ax.set_ylabel('Number of runs')

    y_closest_power_of_10 = 10 ** (math.floor(math.log10(agg_df['count'].count()))-1)
    ax.set_yticks(np.arange(0, agg_df['count'].count()+y_closest_power_of_10/2, y_closest_power_of_10))

    x_closest_power_of_10 = 10 ** math.floor(math.log10(agg_df['count'].max()))
    ax.set_xticks(np.arange(0, agg_df['count'].max()+x_closest_power_of_10/2, x_closest_power_of_10/2))
    ax.set_xticks(np.arange(0, agg_df['count'].max()+x_closest_power_of_10/2, x_closest_power_of_10/10), minor=True)

    ax.grid(True, which='major', linestyle='-')
    ax.grid(True, which='minor', linestyle=':', alpha=0.8)

    fig.savefig(f'fig/count-{timestamp}-{in_enclave}-{sleep_time_secs}.png', bbox_inches='tight')

