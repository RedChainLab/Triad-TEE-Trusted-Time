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

log=False

# Files in out/count directory are in the naming format count-<timestamp>-<sgx_type>-<sleep_type>-<sleep_time_secs>-<repeat_id>.csv
# Get <sleep_type> <sleep_time_secs> from command line arguments

if len(sys.argv) > 1:
  log = (sys.argv[1] == "1")

# Get all files in out/count directory that match sleep_type and sleep_time_secs
import os
import re
import progressbar
files = os.listdir('out/ts')
files = [f for f in files if re.match(f'triad*', f)]

for file in files:
    #print(files_timestamp)
    try:
      with open(f'out/ts/{file}', 'r') as f:
        df = pd.read_csv(f, header=None, sep=' ')
    except Exception as e:
      print(f'Error reading {file}: {e}\n')
    print(df)
    df.drop(columns=[0,3], inplace=True)
    df.columns = ['ID','type', 'date', "time","TZ"]
    node_ts = df[df['type'] == 'Node'].reset_index(drop=True)
    ref_ts = df[df['type'] == 'Ref.'].reset_index(drop=True)
    merged=node_ts.join(ref_ts, lsuffix='_node', rsuffix='_ref')
    merged.drop(columns=['type_node', 'type_ref', 'TZ_node', 'TZ_ref'], inplace=True)
    merged=merged[~merged["time_node"].str.contains("-")].dropna()
    merged["datetime_node"]=pd.to_datetime(merged["date_node"]+" "+merged["time_node"])
    merged["datetime_ref"]=pd.to_datetime(merged["date_ref"]+" "+merged["time_ref"])
    merged.drop(columns=["date_node", "time_node", "date_ref", "time_ref"], inplace=True)
    merged["drift"]=(merged["datetime_node"]-merged["datetime_ref"])/pd.Timedelta('1ms')
    merged["datetime_ref"]=(merged["datetime_ref"]-merged["datetime_ref"].min())/pd.Timedelta('1s')
    print(node_ts, ref_ts, merged)
    fig, ax = plt.subplots()
    for group in merged.groupby("ID_node"):
      ax.plot(group[1]["datetime_ref"], group[1]["drift"], marker='+', markersize=3, linestyle="-", linewidth=0.5, label=f"Node {group[0][:-2]}")
    ax.set_xlabel('reference time (s)')
    ax.set_ylabel('drift (ms)')
    ax.grid(True)
    ax.legend()
    if log:
      ax.set_yscale('log')
    fig.savefig(f'fig/{file}{"-log" if log else ""}.png', bbox_inches='tight', dpi=1200)