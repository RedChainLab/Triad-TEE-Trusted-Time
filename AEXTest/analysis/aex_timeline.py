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

# Get the filename from command line arguments
filename = sys.argv[1]
delay = int(filename.split('-')[1])

MANY_AEX = True
if len(sys.argv) > 2:
    MANY_AEX = True if int(sys.argv[2])==1 else False

with open(filename, 'r') as file:
    df = pd.read_csv(file, sep=';', header=0, index_col=0)
    print(df)

ratio=df['count'].max()/(delay*1000 if MANY_AEX else delay)

df['count'] = df['count'].apply(lambda x: x / ratio)
df.index+=1
df = df.head(-1)
print(df)

fig, ax = plt.subplots()
ax.step(df['count'], df.index, label='AEX', marker=None if MANY_AEX else "x", markersize=5, linewidth=1, where='post')
ax.set_xlabel(f'Elapsed time ({"ms" if MANY_AEX else "s"})')
ax.set_ylabel('Number of AEX')

y_closest_power_of_10 = 10 ** (math.floor(math.log10(df.index.max()))-(0 if MANY_AEX else 1))
ax.set_yticks(np.arange(0, df.index.max()+y_closest_power_of_10/2, y_closest_power_of_10/(2 if MANY_AEX else 1)))
if MANY_AEX:
  ax.set_yticks(np.arange(0, df.index.max()+y_closest_power_of_10/2, y_closest_power_of_10/10), minor=True)
x_closest_power_of_10 = 10 ** math.floor(math.log10(df['count'].max()))
ax.set_xticks(np.arange(0, df['count'].max()+x_closest_power_of_10/2, x_closest_power_of_10/2))
ax.set_xticks(np.arange(0, df['count'].max()+x_closest_power_of_10/2, x_closest_power_of_10/10), minor=True)

ax.grid(True, which='major', linestyle='-')
ax.grid(True, which='minor', linestyle=':', alpha=0.8)

fig.savefig(f'fig/timelineAEX-{"-".join(filename.split(".")[0].split("-")[1:])}{"-MANY_AEX" if MANY_AEX else ""}.png', bbox_inches='tight')
