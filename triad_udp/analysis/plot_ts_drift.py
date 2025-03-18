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
  file = sys.argv[1]
elif len(sys.argv) > 2:
  log = (sys.argv[2] == "1")

#print(files_timestamp)
try:
  with open(f'out/ts/{file}-ts-node.log', 'r') as f:
    df = pd.read_csv(f, header=None, sep=' ')
except Exception as e:
  print(f'Error reading {file}-ts-node.log: {e}\n')
try:
  with open(f'out/ts/{file}-aex.log', 'r') as f:
    aex_df = pd.read_csv(f, header=None, sep=' ')
except Exception as e:
  print(f'Error reading {file}-aex: {e}\n')
try:
  with open(f'out/ts/{file}-ut-node.log', 'r') as f:
    ut_node_df = pd.read_csv(f, header=None, sep=' ')
except Exception as e:
  print(f'Error reading {file}-ut-node.log: {e}\n')
try:
  with open(f'out/ts/{file}-ut-ta.log', 'r') as f:
    ut_ta_df = pd.read_csv(f, header=None, sep=' ')
except Exception as e:
  print(f'Error reading {file}-ut-ta.log: {e}\n')
print(df)
print(aex_df)
print(ut_node_df)
print(ut_ta_df)

aex_df.drop(columns=[0,3], inplace=True)
aex_df.columns = ['ID','type', 'date', "time","TZ"]
aex_df["datetime"]=pd.to_datetime(aex_df["date"]+" "+aex_df["time"])
print(aex_df)

ut_ta_df.drop(columns=[0,3], inplace=True)
ut_ta_df.columns = ['ID','type', 'date', "time","TZ"]
ut_ta_df["datetime"]=pd.to_datetime(ut_ta_df["date"]+" "+ut_ta_df["time"])
print(ut_ta_df)

ut_node_df.drop(columns=[0,3], inplace=True)
ut_node_df.columns = ['ID','type', 'date', "time","TZ"]
ut_node_df["datetime"]=pd.to_datetime(ut_node_df["date"]+" "+ut_node_df["time"])
print(ut_node_df)

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

ref_datetime=min(merged["datetime_ref"].min(),aex_df["datetime"].min(),ut_ta_df["datetime"].min(),ut_node_df["datetime"].min())

merged["datetime_ref"]=(merged["datetime_ref"]-ref_datetime)/pd.Timedelta('1s')
aex_df["datetime"]=(aex_df["datetime"]-ref_datetime)/pd.Timedelta('1s')
ut_ta_df["datetime"]=(ut_ta_df["datetime"]-ref_datetime)/pd.Timedelta('1s')
ut_node_df["datetime"]=(ut_node_df["datetime"]-ref_datetime)/pd.Timedelta('1s')

print(node_ts, ref_ts, merged)
fig, ax = plt.subplots(nrows=4, sharex=True)
colors=["tab:blue","tab:orange","tab:green"]
for group, color in zip(merged.groupby("ID_node"), colors):
  ax[0].plot(group[1]["datetime_ref"], group[1]["drift"], marker='+', markersize=3, linestyle="-", linewidth=0.5, label=f"Node {group[0][:-2]}", color=color)

for (idx, group), color in zip(enumerate(aex_df.groupby("ID")),colors):
  ax[1].step(group[1]["datetime"], np.cumsum(np.ones(len(group[1]["datetime"]))), linestyle="-", linewidth=0.5, label=f"Node {group[0][:-2]}", color=color)

for (idx, group), color in zip(enumerate(ut_ta_df.groupby("ID")),colors):
  ax[2].step(group[1]["datetime"], np.cumsum(np.ones(len(group[1]["datetime"]))), linestyle="-", linewidth=0.5, label=f"Node {group[0][:-2]}", color=color, where='post')

for (idx, group), color in zip(enumerate(ut_node_df.groupby("ID")),colors):
  ax[3].step(group[1]["datetime"], np.cumsum(np.ones(len(group[1]["datetime"]))), linestyle="-", linewidth=0.5, label=f"Node {group[0][:-2]}", color=color, where='post')

ax[1].grid(True)
ax[1].grid(which='minor', linestyle=':', linewidth='0.5')
ax[1].grid(which='major', linestyle='-', linewidth='0.5')
ax[1].minorticks_on()

ax[2].grid(True)
ax[2].grid(which='minor', linestyle=':', linewidth='0.5')
ax[2].grid(which='major', linestyle='-', linewidth='0.5')
ax[2].minorticks_on()
ax[2].set_ylim(0)

ax[3].grid(True)
ax[3].grid(which='minor', linestyle=':', linewidth='0.5')
ax[3].grid(which='major', linestyle='-', linewidth='0.5')
ax[3].minorticks_on()
ax[3].set_ylim(0)

ax[3].set_xlabel('reference time (s)')
ax[0].set_ylabel('drift (ms)')
ax[1].set_ylabel('\#AEX')
ax[2].set_ylabel('\#TA untainting')
ax[3].set_ylabel('\#Peer untainting')
ax[0].set_xlim(0)
ax[0].grid(True)
ax[0].grid(which='minor', linestyle=':', linewidth='0.5')
ax[0].grid(which='major', linestyle='-', linewidth='0.5')
ax[0].minorticks_on()
ax[0].legend()
if log:
  ax[0].set_yscale('log')
fig.savefig(f'fig/{file}{"-log" if log else ""}.png', bbox_inches='tight', dpi=1200)