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

# Files in out/count directory are in the naming format count-<timestamp>-<sgx_type>-<sleep_type>-<sleep_time_secs>-<repeat_id>.csv
# Get <sleep_type> <sleep_time_secs> from command line arguments
vlines=[]
if len(sys.argv) > 1:
  file = sys.argv[1]
if len(sys.argv) > 2:
  vlines=[int(x) for x in sys.argv[2].split(",")]

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
try:
  with open(f'out/ts/{file}-states.log', 'r') as f:
    states_df = pd.read_csv(f, header=None, sep=' ')
except Exception as e:
  print(f'Error reading {file}-states.log: {e}\n')
# print(df)
# print(aex_df)
# print(ut_node_df)
# print(ut_ta_df)
# print(states_df)

aex_df.drop(columns=[0,3], inplace=True)
aex_df.columns = ['ID','type', 'date', "time","TZ"]
aex_df["datetime"]=pd.to_datetime(aex_df["date"]+" "+aex_df["time"])
# print(aex_df)

ut_ta_df.drop(columns=[0,3], inplace=True)
ut_ta_df.columns = ['ID','type', 'date', "time","TZ"]
ut_ta_df["datetime"]=pd.to_datetime(ut_ta_df["date"]+" "+ut_ta_df["time"])
# print(ut_ta_df)

ut_node_df.drop(columns=[0,3], inplace=True)
ut_node_df.columns = ['ID','type', 'date', "time","TZ"]
ut_node_df["datetime"]=pd.to_datetime(ut_node_df["date"]+" "+ut_node_df["time"])
# print(ut_node_df)

states_df.drop(columns=[0,3], inplace=True)
states_df.columns = ['ID','type', 'date', "time","TZ"]
states_df["datetime"]=pd.to_datetime(states_df["date"]+" "+states_df["time"])
states_df["type"].replace({"OK": 0, "Tainted": 1, "RefCalib":2, "FullCalib":3}, inplace=True)
print(states_df)

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
states_df["datetime"]=(states_df["datetime"]-ref_datetime)/pd.Timedelta('1s')

mem_aex_df=aex_df.copy()

df_list=[aex_df, ut_ta_df, ut_node_df]
for idx, a_df in enumerate(df_list):
# Add a row per node in aex_df with the datetime as merged["datetime_ref"].max() + 1 second
  unique_ids = a_df['ID'].unique()
  new_rows = pd.DataFrame({
    'ID': unique_ids,
    'datetime': [merged["datetime_ref"].max() + 1] * len(unique_ids)
  })
  a_df = pd.concat([a_df, new_rows], ignore_index=True)
  df_list[idx] = a_df
aex_df, ut_ta_df, ut_node_df = df_list

# Duplicate the last record for each node in states_df with a new row at datetime of merged["datetime_ref"].max + 1
unique_ids = states_df['ID'].unique()
new_rows = states_df.groupby('ID').tail(1).copy()
new_rows['datetime'] = merged["datetime_ref"].max() + 1
states_df = pd.concat([states_df, new_rows], ignore_index=True)

# print(node_ts, ref_ts, merged)
NB_FIGS=5
fig_ax = [plt.subplots(figsize=(4.5,1.5)) for _ in range(NB_FIGS)]

fig, ax = zip(*fig_ax)

colors=["tab:blue","tab:orange","tab:green"]
linestyles=["-","--",":"]
for (idx, group), color in zip(enumerate(merged.groupby("ID_node")), colors):
  ax[0].plot(group[1]["datetime_ref"], group[1]["drift"], marker='+', markersize=3, linestyle="-", linewidth=0.5, label=f"Node {1+int(group[0][:-2])%12345}", color=color,
              zorder=4-idx
             )

for (idx, group), color, linestyle in zip(enumerate(aex_df.groupby("ID")), colors, linestyles):
  ax[1].step(group[1]["datetime"], np.cumsum(np.ones(len(group[1]["datetime"]))), linestyle=linestyle, label=f"Node {1+int(group[0][:-2])%12345}", color=color)

for (idx, group), color, linestyle in zip(enumerate(ut_ta_df.groupby("ID")), colors, linestyles):
  ax[2].step(group[1]["datetime"], np.cumsum(np.ones(len(group[1]["datetime"]))), linestyle=linestyle, label=f"Node {1+int(group[0][:-2])%12345}", color=color, where='post')

for (idx, group), color, linestyle in zip(enumerate(ut_node_df.groupby("ID")), colors, linestyles):
  ax[3].step(group[1]["datetime"], np.cumsum(np.ones(len(group[1]["datetime"]))), linestyle=linestyle, label=f"Node {1+int(group[0][:-2])%12345}", color=color, where='post')

for (idx, group), color, linestyle in zip(enumerate(states_df.groupby("ID")), colors, linestyles):
  ax[4].step(group[1]["datetime"], group[1]["type"], linestyle=linestyle, label=f"Node {1+int(group[0][:-2])%12345}", color=color, where='post', 
            #  zorder=4-idx
            )

for a in ax:
  a.grid(True)
  a.grid(which='minor', linestyle=':', linewidth='0.5')
  a.grid(which='major', linestyle='-', linewidth='0.5')
  a.minorticks_on()

ax[3].set_ylim(-100)

ax[4].grid(axis="x", which='minor', linestyle=':', linewidth='0.5')
ax[4].set_yticks([0,1,2,3])
ax[4].set_yticklabels(["OK","Tainted","RefCalib","FullCalib"])
ax[4].minorticks_on()

MAJOR_TICKS=60 #240 #600 #60
MINOR_TICKS=10 #60 #60 #10
for axis in ax:
  axis.set_xlabel('Reference time (s)')
  axis.set_xticks(np.arange(0, min(3601,math.ceil(merged["datetime_ref"].max()+1)), MAJOR_TICKS))
  axis.set_xlim(0, min(3601,math.ceil(merged["datetime_ref"].max())))
  axis.set_xticks(np.arange(0, min(3601,math.ceil(merged["datetime_ref"].max()+1)), MINOR_TICKS), minor=True)

ax[0].set_ylabel('Drift (ms)')
ax[1].set_ylabel('AEX count')
ax[2].set_ylabel('Message count to TA')
ax[3].set_ylabel('Peer response count')
ax[4].set_ylabel('Node state')
# ax[0].set_xlim(0)
ax[2].legend(loc='lower right', fontsize='small')

for vline in vlines:
  for a in ax:
    a.axvline(x=vline, color='r', linestyle='--', zorder=100)

suffixes=["drift","aex","ut-ta","ut-node","states"]
for f,suffix in zip(fig,suffixes):
  f.savefig(f'fig/{file}-{suffix}.pdf', bbox_inches='tight', dpi=1200)

def compute_state_durations(states_df, state_value):
  state_df = states_df.copy()
  state_df["type"] = states_df["type"].replace({0: 0, 1: 0, 2: 0, 3: 0, state_value: 1})
  state_df["duration"] = state_df.groupby("ID")["datetime"].diff().fillna(0)
  state_df["duration"] = state_df.groupby("ID")["duration"].shift(-1).fillna(0)
  state_df = state_df[state_df["type"] == 1]
  state_durations = state_df.groupby("ID")["duration"].sum()
  return state_durations

ok_durations = compute_state_durations(states_df, 0)
tainted_durations = compute_state_durations(states_df, 1)
refcalib_durations = compute_state_durations(states_df, 2)
fullcalib_durations = compute_state_durations(states_df, 3)

# Merge the three state durations into a single DataFrame
state_durations_df = pd.DataFrame({
  'OK': ok_durations,
  'Tainted': tainted_durations,
  'RefCalib': refcalib_durations,
  'FullCalib': fullcalib_durations
}).fillna(0)
state_durations_df["ID"]=state_durations_df.index.str[:-2]
state_durations_df["ID"]=(state_durations_df["ID"].astype(int)+1)%12345
state_durations_df["ID"]=state_durations_df["ID"].astype(str)
state_durations_df.set_index("ID", inplace=True)

# Plot the state durations
fig2, ax2 = plt.subplots(figsize=(4.5, 2.5))
state_durations_df_normalized = state_durations_df.div(state_durations_df.sum(axis=1), axis=0) * 100

bar_width = 0.2
index = np.arange(len(state_durations_df_normalized))

hatching = ['/', 'xx', '\\', 'o']

ax2.bar(index, state_durations_df_normalized['OK'], bar_width, color='tab:blue', label='OK', edgecolor='black', hatch=hatching[0])
ax2.bar(index + bar_width, state_durations_df_normalized['Tainted'], bar_width, color='tab:orange', label='Tainted TS', edgecolor='black', hatch=hatching[1])
ax2.bar(index + 2 * bar_width, state_durations_df_normalized['RefCalib'], bar_width, color='tab:green', label='Time ref. calib.', edgecolor='black', hatch=hatching[2])
ax2.bar(index + 3 * bar_width, state_durations_df_normalized['FullCalib'], bar_width, color='tab:red', label='Full calib.', edgecolor='black', hatch=hatching[3])

ax2.set_xlabel('Node ID')
ax2.set_xticks(index + 1.5 * bar_width)
ax2.set_xticklabels(state_durations_df_normalized.index)
ax2.set_ylabel('Duration (\\%)')
ax2.set_ylim(0.01, 100)
ax2.set_yscale('log')
ax2.grid(axis='y', linestyle='-', linewidth='0.5')
ax2.grid(axis='y', which='minor', linestyle=':', linewidth='0.5')
ax2.minorticks_on()
handles, labels = ax2.get_legend_handles_labels()
ax2.legend(handles, labels, title='State', loc='upper center', fontsize='small', ncol=4, handleheight=1.5, bbox_to_anchor=(0.425, 1.3),handletextpad=0.5)
fig2.savefig(f'fig/{file}-state-durations.pdf', bbox_inches='tight', dpi=1200)

# Calculate delays between successive rows in aex_df
mem_aex_df["delay"] = mem_aex_df["datetime"].groupby(aex_df["ID"]).diff().fillna(0)

# Plot histogram of delays
fig3, ax3 = plt.subplots(figsize=(4.5, 1.5))
for group, color, linestyle in zip(mem_aex_df.groupby("ID"),colors, linestyles):
  ax3.hist(group[1]["delay"], bins=100, color=color, linestyle=linestyle, cumulative=True, histtype='step', density=True, label=f"Node {1+int(group[0][:-2])%12345}")
ax3.set_xlabel('Delay between successive AEXs (s)')
ax3.set_ylabel('Cumulative frequency')
ax3.grid(True)
ax3.grid(which='minor', linestyle=':', linewidth='0.5')
ax3.grid(which='major', linestyle='-', linewidth='0.5')
ax3.minorticks_on()
ax3.set_xlim(0)
ax3.set_ylim(0, 1)
ax3.set_yticks(np.arange(0, 1.01, 0.25))
ax3.set_yticks(np.arange(0, 1.01, 0.05), minor=True)
ax3.set_yticklabels(['{:.0f}\\%'.format(x * 100) for x in ax3.get_yticks()])

LOW_INTERRUPTS = False
if LOW_INTERRUPTS:
  max_x_value = math.ceil(mem_aex_df["delay"].max())
  closest_multiple_of_60 = (max_x_value // 60 + 1) * 60

  ax3.set_xticks(np.arange(0, closest_multiple_of_60 + 1, 60))
  ax3.set_xlim(0, closest_multiple_of_60)
  ax3.set_xticks(np.arange(0, closest_multiple_of_60 + 1, 10), minor=True)
else:
  ax3.set_xticks(np.arange(0, 2.01, 0.2))
  ax3.set_xlim(0, 2)
  ax3.set_xticks(np.arange(0, 2.01, 0.05), minor=True)
  # ax3.set_xlim(0.01, 10)
  # ax3.set_xscale('log')

handles, labels = ax3.get_legend_handles_labels()
ax3.legend(handles, labels, loc='upper left', fontsize='small')
fig3.savefig(f'fig/{file}-aex-delays-histogram.pdf', bbox_inches='tight', dpi=1200)