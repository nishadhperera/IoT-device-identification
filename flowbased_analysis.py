from scapy.all import *
import fnmatch
import matplotlib.pyplot as plt
import numpy as np
from scipy.fftpack import fft
import bottleneck
from random import sample
import operator
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

prev_packet = ""
IA_times = []
IA_times_list = []
ether_len = []
ether_len_list = []
IP_len = []
IP_len_list = []
IP_header_len = []
IP_header_len_list = []
pkt_counter = 0
pkt_count_list = []
pkt_direction = []
pkt_direction_list = []
source_mac_add = ""
new_device = False

feature_list = []       # stores the features
device_list = []        # stores the device names


def pcap_class_generator(pcap_folder):
    global IA_times
    global IA_times_list
    global ether_len
    global ether_len_list
    global IP_len
    global IP_len_list
    global IP_header_len
    global IP_header_len_list
    global prev_packet
    global new_device
    global pkt_counter
    global pkt_count_list
    global pkt_direction
    global pkt_direction_list

    for path, dir_list, file_list in os.walk(pcap_folder):

        for name in fnmatch.filter(file_list, "*.pcap"):
            print(os.path.join(path, name), os.path.basename(os.path.normpath(path)))
            new_device = True
            if IA_times:
                IA_times_list.append(IA_times)
                IA_times = []
                prev_packet = ""
            if ether_len:
                ether_len_list.append(ether_len)
                ether_len = []
            if IP_len:
                IP_len_list.append(IP_len)
                IP_len = []
            if IP_header_len:
                IP_header_len_list.append(IP_header_len)
                IP_header_len = []
            if pkt_counter > 0:
                pkt_count_list.append(pkt_counter)
                pkt_counter = 0
            if pkt_direction:
                pkt_direction_list.append(pkt_direction)
                pkt_direction = []

            yield os.path.join(path, name), os.path.basename(os.path.normpath(path))


def packet_filter_generator(pcap_class_gen, filter_con):
    global source_mac_add

    for pcapfile, device_name in pcap_class_gen:
        capture = rdpcap(pcapfile)
        mac_address_list = {}
        src_mac_address_list = {}

        for i, (packet) in enumerate(capture):
            if packet[0].src not in mac_address_list:  # Counting the source MAC counter value
                mac_address_list[packet[0].src] = 1
            else:
                mac_address_list[packet[0].src] += 1

            if packet[0].dst not in mac_address_list:  # Counting the Destination MAC counter value
                mac_address_list[packet[0].dst] = 1
            else:
                mac_address_list[packet[0].dst] += 1

            if packet[0].src not in src_mac_address_list:  # keeping the source MAC address counter for capture length
                src_mac_address_list[packet[0].src] = 1
            else:
                src_mac_address_list[packet[0].src] += 1

        highest = max(mac_address_list.values())
        for k, v in mac_address_list.items():
            if v == highest:
                if k in src_mac_address_list:
                    source_mac_add = k
        print("Source MAC ", source_mac_add)

        for i, (packet) in enumerate(capture):
            if filter_con == "bidirectional":           # filter bidirectional traffic on source
                if packet[0].src == source_mac_add or packet[0].dst == source_mac_add:
                    yield packet, device_name
            elif filter_con == "Src_to_Other":          # filter traffic originated from source
                if packet[0].src == source_mac_add:
                    yield packet, device_name
            elif filter_con == "Other_to_Src":          # filter traffic destined to source
                if packet[0].dst == source_mac_add:
                    yield packet, device_name


def load_data(folder, filter_con):
    file_list = pcap_class_generator(folder)
    packet_list = packet_filter_generator(file_list, filter_con)
    return packet_list


def plot_list(list, title, x_label, y_label):
    fig, axarr = plt.subplots(len(list), sharex=True, sharey=True)
    for i, (data) in enumerate(list):
        axarr[i].plot(data)

    axarr[0].set_title(title)
    fig.text(0.5, 0.04, x_label, ha='center')
    fig.text(0.04, 0.5, y_label, va='center', rotation='vertical')
    fig.subplots_adjust(hspace=0)
    plt.setp([a.get_xticklabels() for a in fig.axes[:-1]], visible=False)
    plt.grid(linestyle='dotted')
    plt.show()


def plot_results(pred_accuracy, title, item_index, reverse, y_lable):
    dataset = sorted(pred_accuracy.items(), key=operator.itemgetter(item_index),
                     reverse=reverse)  # sort the dictionary with values

    # plot the results (device type vs accuracy of prediction)
    device = list(zip(*dataset))[0]
    accuracy = list(zip(*dataset))[1]

    x_pos = np.arange(len(device))

    plt.bar(x_pos, accuracy, align='edge', color='g')
    plt.xticks(x_pos, device, rotation=315, ha='left')
    plt.ylabel(y_lable)
    plt.title(title)
    plt.grid(linestyle='dotted')
    plt.show()


def initiate_feature_list(packet_list):
    global feature_list
    global device_list
    global new_device

    for i, (packet, dev_name) in enumerate(packet_list):
        if new_device:
            device_list.append(dev_name)
            feature_list.append([])
            new_device = False
        yield packet, dev_name


def calc_IA_features(packet_list, filter_con):
    global prev_packet
    global IA_times
    global IA_times_list
    global device_list
    IA_times_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        if prev_packet == "":
            pass
        else:
            IA_times.append(packet.time - prev_packet.time)
        prev_packet = packet
        yield packet, dev_name

    IA_times_list.append(IA_times)
    IA_times = []
    prev_packet = ""
    print("len(IA_times_list)", len(IA_times_list))

    for i, (data) in enumerate(IA_times_list):

        min_IAT = min(data)  # minimum packet inter-arrival time
        max_IAT = max(data)  # maximum packet inter-arrival time
        q1_IAT = np.percentile(data, 25)    # first quartile of inter-arrival time
        median_IAT = np.percentile(data, 50)    # median of inter-arrival time
        mean_IAT = np.mean(data)                # mean of inter-arrival time
        q3_IAT = np.percentile(data, 75)    # third quartile of inter-arrival time
        var_IAT = np.var(data)              # variance of inter-arrival time

        print(i, "IA features: ", filter_con, min_IAT, max_IAT, q1_IAT, median_IAT, mean_IAT, q3_IAT, var_IAT)

        feature_list[i].append(round(min_IAT, 2))
        feature_list[i].append(round(max_IAT, 2))
        feature_list[i].append(round(q1_IAT, 2))
        feature_list[i].append(round(median_IAT, 2))
        feature_list[i].append(round(mean_IAT, 2))
        feature_list[i].append(round(q3_IAT, 2))
        feature_list[i].append(round(var_IAT, 2))

        # FFT calculation for inter-arrival times
        data = np.array(data)
        min_len = min(len(data), 10)        # get 10 fft components or the minimum length of input data to fft
        fft_data = fft(data)                # calculate fft with scipy
        fft_data = np.abs(fft_data)         # get the magnitudes of fft components
        z = -bottleneck.partition(-fft_data, min_len - 1)[:min_len]     # get the max components
        sorted_fft = np.sort(z)
        sorted_fft[:] = sorted_fft[::-1]    # sort the fft components from largest to smallest

        if len(sorted_fft) < 10:            # pad the array with zeros if at least 10 fft components are not there
            sorted_fft = np.append(sorted_fft, np.zeros(10 - len(sorted_fft)))

        print(i, "FFT features: ", filter_con, sorted_fft)
        for fft_val in sorted_fft:          # append fft values to feature list
            feature_list[i].append(fft_val)


    # plot_list(IA_times_list, "Inter arrival time variation with the packet count (%s)" % filter_con, "Packet count",
    #           "Inter arrival time (s)")


def calc_ethsize_features(packet_list, filter_con):
    global ether_len
    global ether_len_list
    ether_len_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        ether_len.append(len(packet))
        yield packet, dev_name

    ether_len_list.append(ether_len)
    ether_len = []

    print("len(ether_len_list): ", len(ether_len_list))

    for i, (data) in enumerate(ether_len_list):
        min_ethlen = min(data)  # minimum ethernet packet size
        max_ethlen = max(data)  # maximum ethernet packet size
        q1_ethlen = np.percentile(data, 25)  # first quartile of ethernet packet size
        median_ethlen = np.percentile(data, 50)  # median of ethernet packet size
        mean_ethlen = np.mean(data)  # mean of ethernet packet size
        q3_ethlen = np.percentile(data, 75)  # third quartile of ethernet packet size
        var_ethlen = np.var(data)  # variance of ethernet packet size

        print(i, "Ethernet packet size features: ", min_ethlen, max_ethlen, q1_ethlen, median_ethlen, mean_ethlen,
              q3_ethlen, var_ethlen)

        feature_list[i].append(min_ethlen)
        feature_list[i].append(max_ethlen)
        feature_list[i].append(q1_ethlen)
        feature_list[i].append(median_ethlen)
        feature_list[i].append(mean_ethlen)
        feature_list[i].append(q3_ethlen)
        feature_list[i].append(var_ethlen)

    # plot_list(ether_len_list, "Ethernet packet size variation pattern with number of packets (%s)" % filter_con, "Packet count",
    #           "Ethernet packet size")


def calc_IP_size_features(packet_list, filter_con):
    global IP_len
    global IP_len_list
    IP_len_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            IP_len.append(packet["IP"].len)
        except IndexError:
            pass
        yield packet, dev_name

    IP_len_list.append(IP_len)
    IP_len = []

    for i, (data) in enumerate(IP_len_list):
        min_ip_len = min(data)  # minimum IP packet size
        max_ip_len = max(data)  # maximum IP packet size
        q1_ip_len = np.percentile(data, 25)  # first quartile of IP packet size
        median_ip_len = np.percentile(data, 50)  # median of IP packet size
        mean_ip_len = np.mean(data)  # mean of IP packet size
        q3_ip_len = np.percentile(data, 75)  # third quartile of IP packet size
        var_ip_len = np.var(data)  # variance of IP packet size

        print(i, "IP packet size features: ", min_ip_len, max_ip_len, q1_ip_len, median_ip_len, mean_ip_len, q3_ip_len, var_ip_len)

        feature_list[i].append(min_ip_len)
        feature_list[i].append(max_ip_len)
        feature_list[i].append(q1_ip_len)
        feature_list[i].append(median_ip_len)
        feature_list[i].append(mean_ip_len)
        feature_list[i].append(q3_ip_len)
        feature_list[i].append(var_ip_len)

    # plot_list(IP_len_list, "IP packet size variation pattern with number of packets (%s)" % filter_con, "Packet count",
    #           "IP packet size")


def calc_IP_header_size_features(packet_list, filter_con):
    global IP_header_len
    global IP_header_len_list
    IP_header_len_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            IP_header_len.append(packet["IP"].ihl)
        except IndexError:
            pass
        yield packet, dev_name

    IP_header_len_list.append(IP_header_len)
    IP_header_len = []

    for i, (data) in enumerate(IP_header_len_list):
        min_iph_len = min(data)  # minimum IP packet header size
        max_iph_len = max(data)  # maximum IP packet header size
        q1_iph_len = np.percentile(data, 25)  # first quartile of IP packet header size
        median_iph_len = np.percentile(data, 50)  # median of IP packet header size
        mean_iph_len = np.mean(data)  # mean of IP packet header size
        q3_iph_len = np.percentile(data, 75)  # third quartile of IP packet header size
        var_iph_len = np.var(data)  # variance of IP packet header size

        print(i, "IP packet header size features: ", min_iph_len, max_iph_len, q1_iph_len, median_iph_len, mean_iph_len, q3_iph_len, var_iph_len)

        feature_list[i].append(min_iph_len)
        feature_list[i].append(max_iph_len)
        feature_list[i].append(q1_iph_len)
        feature_list[i].append(median_iph_len)
        feature_list[i].append(mean_iph_len)
        feature_list[i].append(q3_iph_len)
        feature_list[i].append(var_iph_len)

    # plot_list(IP_header_len_list, "IP packet header size variation pattern with number of packets (%s)" % filter_con, "Packet count",
    #           "IP packet header size")


def calc_num_of_pkts(packet_list, filter_con):
    global pkt_counter
    global pkt_count_list

    pkt_count_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        pkt_counter = pkt_counter + 1
        yield packet, dev_name

    pkt_count_list.append(pkt_counter)
    pkt_counter = 0
    print("length of Packet counts list: ", len(pkt_count_list))

    for i, (data) in enumerate(pkt_count_list):
        feature_list[i].append(data)


def calc_pkt_directions(packet_list, filter_con):
    global pkt_direction
    global pkt_direction_list
    global source_mac_add

    pkt_direction_list = []
    pkt_direction = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            if packet[0].src == source_mac_add:
                pkt_direction.append(0)
            elif packet[0].dst == source_mac_add:
                pkt_direction.append(1)
        except IndexError:
            pass
        # yield packet, dev_name

    pkt_direction_list.append(pkt_direction)

    for i, (data) in enumerate(pkt_direction_list):
        for j in range(10):
            if j < len(data):
                feature_list[i].append(data[j])
            else:
                feature_list[i].append(2)


def end_generator(packet_list):
    for i, (packet, dev_name) in enumerate(packet_list):
        pass


def load_behavior_features(folder):
    global feature_list
    global device_list

    filter = "bidirectional"
    # load packet data based on filter conditions: bidirectional, Src_to_Other, Other_to_Src
    packet_list_bidirec = load_data(folder, filter)

    piped_to_IA = initiate_feature_list(packet_list_bidirec)

    # Calculate the features for packet list
    piped_to_eth_size = calc_IA_features(piped_to_IA, filter)
    piped_to_ip_size = calc_ethsize_features(piped_to_eth_size, filter)
    piped_to_ip_header_size = calc_IP_size_features(piped_to_ip_size, filter)
    piped_to_pkt_count = calc_IP_header_size_features(piped_to_ip_header_size, filter)
    piped_to_pkt_direction = calc_num_of_pkts(piped_to_pkt_count, filter)
    calc_pkt_directions(piped_to_pkt_direction, filter)


    filter = "Src_to_Other"
    # load packet data based on filter conditions: bidirectional, Src_to_Other, Other_to_Src
    packet_list_from_Src = load_data(folder, filter)

    # piped_to_IA = initiate_feature_list(packet_list_from_Src)

    # Calculate the features for packet list
    piped_to_eth_size = calc_IA_features(packet_list_from_Src, filter)
    piped_to_ip_size = calc_ethsize_features(piped_to_eth_size, filter)
    piped_to_ip_header_size = calc_IP_size_features(piped_to_ip_size, filter)
    piped_to_pkt_count = calc_IP_header_size_features(piped_to_ip_header_size, filter)
    piped_to_pkt_direction = calc_num_of_pkts(piped_to_pkt_count, filter)
    end_generator(piped_to_pkt_direction)


    filter = "Other_to_Src"
    # load packet data based on filter conditions: bidirectional, Src_to_Other, Other_to_Src
    packet_list_to_Src = load_data(folder, filter)

    # piped_to_IA = initiate_feature_list(packet_list_to_Src)

    # Calculate the features for packet list
    piped_to_eth_size = calc_IA_features(packet_list_to_Src, filter)
    piped_to_ip_size = calc_ethsize_features(piped_to_eth_size, filter)
    piped_to_ip_header_size = calc_IP_size_features(piped_to_ip_size, filter)
    piped_to_pkt_count = calc_IP_header_size_features(piped_to_ip_header_size, filter)
    piped_to_pkt_direction = calc_num_of_pkts(piped_to_pkt_count, filter)
    end_generator(piped_to_pkt_direction)

    return feature_list, device_list


# Location where the training dataset is available
pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel\\captures_behavioral"
# pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel\\Test"

try:
    dataset_X = pickle.load(open("behav_features.pickle", "rb"))
    dataset_y = pickle.load(open("behav_Devices.pickle", "rb"))
    print("Pickling successful behavioral features ......")
except (OSError, IOError) as e:
    print("No pickle datasets are available....")
    dataset_X, dataset_y = load_behavior_features(pcap_folder)
    pickle.dump(dataset_X, open("behav_features.pickle", "wb"))
    pickle.dump(dataset_y, open("behav_Devices.pickle", "wb"))
    feature_list = []
    device_list = []


test_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel\\not trained data behavioral"
X_unknown, y_unknown = load_behavior_features(test_folder)
X_unknown = np.array(X_unknown)
y_unknown = np.array(y_unknown)
print("len(X_unknown), len(y_unknown): ", len(X_unknown), len(y_unknown))

Number_of_features = len(dataset_X[0])
print("Number of features: ", Number_of_features)
print("Number of captures: ", len(dataset_X))

dataset_X = np.array(dataset_X)
dataset_y = np.array(dataset_y)

device_set = set(dataset_y)     # list of unique device labels
print("Number of devices: ", len(device_set))
print("Device set: ", device_set)

device_fp_counter = {}
for device in device_set:  # get the number of fingerprints for each device under predicted vendor (not all vendors)
    count = 0
    for record in dataset_y:
        if record == device:
            count += 1
        device_fp_counter[device] = count

print("device_fp_counter: ", device_fp_counter)
key_min = min(device_fp_counter,
              key=device_fp_counter.get)  # find the device with minimum device fingerprints for the predicted vendor
min_fp = device_fp_counter[
    key_min]  # number of minimum device fingerprints to be extracted from each device for the predicted vendor


data_DX = []
data_DY = []

for device in device_set:
    temp_X = dataset_X[dataset_y == device]     # filter all fps for a particular device
    print("temp_X: ", len(temp_X))
    out_list = sample(list(temp_X), min_fp)     # select a data sample from temp_X for a device
    for fp in out_list:
        data_DX.append(fp)                      # append device specific fingerprints to the training data set
        data_DY.append(device)                  # append device name to the respective training data set

data_DX = np.array(data_DX)         # convert training data lists to numpy arrays
data_DY = np.array(data_DY)

print("len(data_DX): ", len(data_DX))
print(data_DX)
print("len(data_Dy): ",len(data_DY))
print(data_DY)

for i, (data) in enumerate(data_DX):
    print(len(data), data_DY[i])

X_train, X_test, y_train, y_test = train_test_split(data_DX, data_DY, test_size=0, random_state=0)

num_of_iter = 20
dev_pred_accuracy = {}      # records prediction accuracy
f_importance = {}            # records the feature importance in classification

for iter in range(num_of_iter):
    print("Prediction iteration ", iter)
    clf = RandomForestClassifier(n_estimators=10)
    clf.fit(X_train, y_train)

    importances = clf.feature_importances_  # calculates the feature importance
    print("Importance: ", importances)
    std = np.std([tree.feature_importances_ for tree in clf.estimators_], axis=0)
    indices = np.argsort(importances)[::-1]
    for f in range(X_train.shape[1]):
        if indices[f] % Number_of_features not in f_importance:
            f_importance[indices[f] % Number_of_features] = importances[indices[f]]
        else:
            f_importance[indices[f] % Number_of_features] += importances[indices[f]]

    y_predict = clf.predict(X_unknown)

    for i in range(len(y_unknown)):
        if y_unknown[i] == y_predict[i]:
            if y_unknown[i] not in dev_pred_accuracy:
                dev_pred_accuracy[y_unknown[i]] = 1
            else:
                dev_pred_accuracy[y_unknown[i]] += 1

for d in device_set:       # check if there are devices which were not predicted correctly at least once
    if d not in dev_pred_accuracy:
        dev_pred_accuracy[d] = 0

for key, value in dev_pred_accuracy.items():
    dev_pred_accuracy[key] = value/num_of_iter  # produce the accuracy as a fraction

for key, value in f_importance.items():
    f_importance[key] = value/num_of_iter  # produce the accuracy as a fraction

plot_results(dev_pred_accuracy, "Single classifier RF - Flowbased analysis", 1, True, "Accuracy")
plot_results(f_importance, "Feature importance RF - Flowbased analysis", 1, True, "Importance")

print(f_importance)