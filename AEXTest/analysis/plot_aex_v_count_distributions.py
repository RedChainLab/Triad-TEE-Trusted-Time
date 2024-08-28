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

FILE_DIR='out/aex/'

files = os.listdir(FILE_DIR)
files = [f for f in files if re.match(f'aex-.*-{in_enclave}-{sleep_time_secs}.csv', f)]
print(files)

# Group files by timestamp
timestamps = set(["-".join(f.split('-')[1:7]) for f in files])
#print(timestamps)

# For each timestamp, plot the count distribution
for timestamp in timestamps:
    [file_timestamp] = [f for f in files if timestamp=="-".join(f.split('-')[1:7])]
    agg_df = pd.DataFrame()
    print(f'Processing {timestamp}...')
    with open(f'{FILE_DIR}{file_timestamp}', 'r') as file:
        try:
            agg_df = pd.read_csv(file, sep=';')
        except Exception as e:
            print(f'Error reading {f}: {e}\n')
    agg_df.columns = ["counter_aex", "monitor_aex", "count"]
    agg_df["sum_aex"]=agg_df["counter_aex"]+agg_df["monitor_aex"]
    agg_df.sort_values(by=["sum_aex","counter_aex"], inplace=True)
    max_sum_aex=agg_df["sum_aex"].max()
    agg_df.drop(columns=["sum_aex"], inplace=True)
    print(agg_df, max_sum_aex)
    agg_df["color"]=agg_df.apply(lambda row: (row["counter_aex"]/max_sum_aex,(max_sum_aex-row["counter_aex"]-row["monitor_aex"])/max_sum_aex,row["monitor_aex"]/max_sum_aex) if max_sum_aex>0 else (0,0,0), axis=1)
    print(agg_df)
    
    fig, ax = plt.subplots()
    #group by ["counter_aex", "monitor_aex"], then for each group plot the count distribution, using the color from the group, and stack each group distribution on top of the previous one
    print([list(g["color"].unique())[0] for _,g in agg_df.groupby(["counter_aex", "monitor_aex"])])
    ax.hist([g['count'] for _, g in agg_df.groupby(["counter_aex", "monitor_aex"])], bins=50, label='AEX', histtype='barstacked', linewidth=1, color=[list(g["color"].unique())[0] for _,g in agg_df.groupby(["counter_aex", "monitor_aex"])])

    ax.set_xlabel('Number of increments')
    ax.set_ylabel('Number of runs')

    ax.legend(handles=[plt.Rectangle((0,0),1,1,fc=(1,0,0), edgecolor='none', linewidth=0),plt.Rectangle((0,0),1,1,fc=(0,1,0), edgecolor='none', linewidth=0),plt.Rectangle((0,0),1,1,fc=(0,0,1), edgecolor='none', linewidth=0)], labels=["counter-aex-heavy", "no-aex", "monitor-aex-heavy"], loc='upper right')

    ax.grid(True, which='major', linestyle='-')
    ax.grid(True, which='minor', linestyle=':', alpha=0.8)
    fig.savefig(f'fig/aex-v-count-{timestamp}-{in_enclave}-{sleep_time_secs}.png')
