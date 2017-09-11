import numpy as np
import matplotlib.pyplot as plt
from scapy.all import *

pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel\\Test1\\Aria\\Setup-A-2-STA.pcap"

dataset_X = pickle.load(open("behav_features.pickle", "rb"))
dataset_y = pickle.load(open("behav_Devices.pickle", "rb"))
print("Pickling successful behavioral features ......")

dataset_X = np.array(dataset_X)
dataset_y = np.array(dataset_y)

# scatterplot code
d_set = ["D-LinkSensor", "D-LinkSiren", "D-LinkWaterSensor", "EdimaxPlug1101W", "EdimaxPlug2101W", "SmarterCoffee", "iKettle2", "TP-LinkPlugHS100", "HueBridge"]

arr_ethlen_max = [[]]
arr_iplen_max = [[]]

for i in range(len(d_set)-1):
    arr_ethlen_max.append([])
    arr_iplen_max.append([])

for j, (d) in enumerate(d_set):
    var_X = dataset_X[dataset_y == d]
    print(d)
    for i in range(len(var_X)):
        print(var_X[i][74], var_X[i][79])
        arr_ethlen_max[j].append(var_X[i][74])
        arr_iplen_max[j].append(var_X[i][79])
    print("------------------------------------")

print(arr_ethlen_max)
print(arr_iplen_max)


N = len(arr_ethlen_max[0])
area = np.pi * (15 * np.random.rand(N))**2  # 0 to 15 point radii

for i in range(len(arr_ethlen_max)):
    plt.scatter(arr_ethlen_max[i], arr_iplen_max[i], s=area, label=d_set[i], alpha=0.5)

plt.legend()
plt.show()