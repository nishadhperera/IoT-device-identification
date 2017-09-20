import numpy as np
import matplotlib.pyplot as plt
from scapy.all import *

dataset_X = pickle.load(open("Ven_behav_features.pickle", "rb"))
dataset_v = pickle.load(open("Ven_behav_vendors.pickle", "rb"))
dataset_y = pickle.load(open("Ven_behav_Devices.pickle", "rb"))
print("Pickling successful behavioral features ......")

dataset_X = np.array(dataset_X)
dataset_v = np.array(dataset_v)
dataset_y = np.array(dataset_y)

# scatterplot code
# d_set = ["D-LinkSensor", "D-LinkSiren", "D-LinkWaterSensor", "EdimaxPlug1101W", "EdimaxPlug2101W", "SmarterCoffee", "iKettle2", "TP-LinkPlugHS100", "HueBridge"]
# d_set = ["Aria", "HueBridge", "Lightify", "MAXGateway"]
# d_set = ["Aria_V", "D-Link_V", "Edimax_V", "Ednet_V", "HomeMaticPlug_V", "Hue_V", "Lightify_V", "MAXGateway_V",
#          "SmarterCoffee_V", "TP-Link_V", "WeMo_V", "Withings_V", "iKettle2_V"]
d_set = ["SmarterCoffee_V", "iKettle2_V", "D-Link_V", "WeMo_V"]

arr_ethlen_max = [[]]
arr_iplen_max = [[]]

for i in range(len(d_set)-1):
    arr_ethlen_max.append([])
    arr_iplen_max.append([])

for j, (d) in enumerate(d_set):
    var_X = dataset_X[dataset_v == d]
    print(d)
    for i in range(len(var_X)):
        arr_ethlen_max[j].append(var_X[i][87])
        arr_iplen_max[j].append(var_X[i][74])
    print("------------------------------------")

print(arr_ethlen_max)
print(arr_iplen_max)


N = len(arr_ethlen_max[0])
area = np.pi * (15 * np.random.rand(N))**2  # 0 to 15 point radii

for i in range(len(arr_ethlen_max)):
    plt.scatter(arr_ethlen_max[i], arr_iplen_max[i], label=d_set[i], alpha=0.5)
    plt.xlabel("IP packet size variance")
    plt.ylabel("Maximum Ethernet packet size")

plt.legend()
plt.show()