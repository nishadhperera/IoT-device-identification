import os
import fnmatch
import pyshark
import numpy as np
import matplotlib.pyplot as plt
import pickle
import random
import operator
from random import randint
from scapy.all import *
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from random import sample
from pyxdameraulevenshtein import damerau_levenshtein_distance, normalized_damerau_levenshtein_distance
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.metrics import log_loss

#import feature_extraction as fe
import features_scapy as fe

dest_ip_set = {}    # stores the destination IP set, a global variable
dst_ip_counter = 0  # keeps destination counter value, a global variable
last_vector = []    # for the comparison of consecutive identical packets
capture_len = 0
feature_set = []
prev_class = ""
concat_feature = []
count = 0
source_mac_add = ""


def pcap_class_generator(folder):
    for path, dir_list, file_list in os.walk(folder):
        for name in fnmatch.filter(file_list, "*.pcap"):
            global dst_ip_counter
            global dest_ip_set
            dest_ip_set.clear()  # stores the destination IP set
            dst_ip_counter = 0
            global feature_set
            global prev_class
            global concat_feature
            print(os.path.join(path, name))
            prev_class = ""
            concat_feature = []
            feature_set = []
            yield os.path.join(path, name), os.path.basename(os.path.dirname(path)), os.path.basename(os.path.normpath(path))


def packet_class_generator(pcap_class_gen):
    for pcapfile, vendor_, class_ in pcap_class_gen:
        capture = rdpcap(pcapfile)
        global capture_len
        global source_mac_add
        global count
        count = 0
        capture_len = 0
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
        capture_len = src_mac_address_list[source_mac_add]

        for i, (packet) in enumerate(capture):
            if packet[0].src == source_mac_add:
                yield packet, vendor_, class_


def feature_class_generator(packet_class_gen):
    for packet, vendor_, class_ in packet_class_gen:
        global dst_ip_counter
        global dest_ip_set
        global last_vector
        global count
        count = count + 1

        #  0   1    2   3       4      5     6    7    8      9     10    11     12   13   14    15     16         17         18         19             20                21         22
        #ARP |LLC |IP |ICMP |ICMPv6 |EAPoL |TCP |UDP |HTTP |HTTPS |DHCP |BOOTP |SSDP |DNS |MDNS |NTP |padding |RouterAlert |size(int) |rawData |dst_ip_counter(int) |src_pc(int) |dst_pc(int)
        fvector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        nl_pro = "None"     # stores network layer protocol
        tl_pro = "None"     # stores transport layer protocol

        fvector[18] = fe.get_length_feature(packet) # Packet length
        fvector[1] = fe.get_LLC_feature(packet)     # check for LLC layer header
        fvector[16] = fe.get_padding_feature(packet)   # check for padding layer header
        fvector[0] = fe.get_arp_feature(packet)     # ARP feature
        fvector[2], nl_pro = fe.get_ip_feature(packet)      # IP feature
        fvector[5] = fe.get_eapol_feature(packet)   # EAPoL feature
        fvector[19] = fe.get_rawdata_feature(packet)    # RawData feature

        if nl_pro == "IP":      # Inspecting the IP layer
            fvector[3], fvector[4] = fe.get_icmp_feature(packet)    # ICMP, ICMPv6 features
            fvector[6], fvector[7], tl_pro = fe.get_tcpudp_feature(packet)  # TCP, UDP features
            fvector[17] = fe.get_r_alert_feature(packet)            # Router Alert feature
            fvector[20], dest_ip_set, dst_ip_counter = fe.get_dest_ip_counter_feature(packet, dest_ip_set, dst_ip_counter)    # Destination ip counter feature

        if tl_pro == "TCP" or tl_pro == "UDP":
            fvector[13] = fe.get_dns_feature(packet, tl_pro)    # DNS feature
            fvector[10], fvector[11] = fe.get_bootp_dhcp_feature(packet, tl_pro)    # DHCP and BOOTP features
            fvector[8] = fe.get_http_feature(packet, tl_pro)    # HTTP feature
            fvector[15] = fe.get_ntp_feature(packet, tl_pro)    # NTP feature
            fvector[9] = fe.get_https_feature(packet, tl_pro)   # HTTPS feature
            fvector[12] = fe.get_ssdp_feature(packet, tl_pro)   # SSDP feature
            fvector[14] = fe.get_mdns_feature(packet, tl_pro)   # MDNS feature
            fvector[21] = fe.get_srcpc_feature(packet, tl_pro)  # source port class feature
            fvector[22] = fe.get_dstpc_feature(packet, tl_pro)  # destination port class feature

        yield fvector, vendor_, class_

features_DL = {}
all_features_DL = {}
f_array = []


def dataset(feature_class_gen):
    global feature_set
    global prev_class
    global concat_feature
    global capture_len
    global count
    global f_array

    def g():
        global feature_set
        global prev_class
        global concat_feature
        global capture_len
        global count
        global f_array
        global last_vector

        for i, (feature, vendor_, class_) in enumerate(feature_class_gen):
            # This block removes the consecutive identical features from the data set
            if not last_vector:
                last_vector = feature
            else:
                if all(i == j for i, j in zip(last_vector, feature)):
                    if capture_len == count and len(concat_feature) < 276:  # if the number of feature count is < 276,
                        while len(concat_feature) < 276:  # add 0's as padding
                            concat_feature = concat_feature + [0]
                        yield concat_feature, vendor_, class_
                        print("capture_len == count", concat_feature)
                    continue
                last_vector = feature

            # Generating the F' vector from F matrix
            if (len(feature_set) < 12) or (prev_class != class_):       # Get 12 unique features for each device type
                if not prev_class:                                      # concatenated into a 276 dimensional vector
                    prev_class = class_
                    feature_set.append(feature)
                    concat_feature = concat_feature + feature
                else:
                    if prev_class is class_:
                        if not feature in feature_set:  # Adding a unique feature
                            feature_set.append(feature)
                            concat_feature = concat_feature + feature
                            if len(feature_set) == 12:
                                yield concat_feature, vendor_, class_
                                print("len(feature_set) == 12", concat_feature)
                    else:
                        prev_class = ""
                        feature_set = []
                        concat_feature = []
                        feature_set.append(feature)
                        concat_feature = concat_feature + feature

            if capture_len == count and len(concat_feature) < 276:  # if the number of feature count is < 276,
                while len(concat_feature) < 276:                    # add 0's as padding
                    concat_feature = concat_feature + [0]
                yield concat_feature, vendor_, class_
                print("capture_len == count", concat_feature)
    return zip(*g())


def load_data(pcap_folder_name):
    pcap_gen = pcap_class_generator(pcap_folder_name)
    packet_gen = packet_class_generator(pcap_gen)
    feature_gen = feature_class_generator(packet_gen)
    dataset_X, dataset_v, dataset_y = dataset(feature_gen)
    dataset_X = np.array(dataset_X)
    dataset_v = np.array(dataset_v)
    dataset_y = np.array(dataset_y)
    return dataset_X, dataset_v, dataset_y

def plot_results(pred_accuracy):
    dataset = sorted(pred_accuracy.items(), key=operator.itemgetter(1),
                     reverse=True)  # sort the dictionary with values

    # plot the results (device type vs accuracy of prediction)
    device = list(zip(*dataset))[0]
    accuracy = list(zip(*dataset))[1]

    x_pos = np.arange(len(device))

    plt.bar(x_pos, accuracy, align='edge')
    plt.xticks(x_pos, device, rotation=315, ha='left')
    plt.ylabel('Accuracy')
    plt.title("Two step classifier (vendor & device prediction)")
    plt.show()

pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel\\Vendor_based"

try:
    dataset_X = pickle.load(open("vendor_dataset_X.pickle", "rb"))
    dataset_v = pickle.load(open("vendor_dataset_v.pickle", "rb"))
    dataset_y = pickle.load(open("vendor_dataset_y.pickle", "rb"))
    print("Pickling successful......")
except (OSError, IOError) as e:
    print("No pickle datasets are available....")
    dataset_X, dataset_v, dataset_y = load_data(pcap_folder)
    pickle.dump(dataset_X, open("vendor_dataset_X.pickle", "wb"))
    pickle.dump(dataset_v, open("vendor_dataset_v.pickle", "wb"))
    pickle.dump(dataset_y, open("vendor_dataset_y.pickle", "wb"))
    all_features_DL = features_DL
    features_DL = {}

vendor_set = set(dataset_v)         # set of unique device vendor labels
all_devices_set = set(dataset_y)        # set of all device types with fingerprints

vendor_fp_counter = {}
for vendor in vendor_set:       # get the number of fingerprints for each device vendor
    count = 0
    for record in dataset_v:
        if record == vendor:
            count += 1
    vendor_fp_counter[vendor] = count

print("Number of different vendors: ", len(vendor_set), vendor_set)
key_min = min(vendor_fp_counter, key=vendor_fp_counter.get)     # find the vendor with minimum device fingerprints
min_fp = vendor_fp_counter[key_min]                             # number of minimum device fingerprints to be extracted from each vendor
print("Min fp device: ", key_min, min_fp)

test_folder="F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel\\not trained data vendor based"
X_unknown, v_unknown, y_unknown = load_data(test_folder)
X_unknown = np.array(X_unknown)
y_unknown = np.array(y_unknown)

num_of_iter = 20
dev_pred_accuracy = {}      # records device prediction accuracy
vendor_pred_accuracy = {}      # records vendor prediction accuracy

for j in range(num_of_iter):         # repeat for j times
    data_VX = []
    data_VV = []

    for vendor in vendor_set:
        temp_X = dataset_X[dataset_v == vendor]     # filter all fps for a particular vendor
        out_list = sample(list(temp_X), min_fp)     # select a data sample from temp_X for a vendor
        for fp in out_list:
            data_VX.append(fp)                      # append vendor specific fingerprints to the training data set
            data_VV.append(vendor)                  # append vendor name to the respective training data set

    data_VX = np.array(data_VX)     # convert training data lists to numpy arrays
    data_VV = np.array(data_VV)

    X_train, X_test, v_train, v_test = train_test_split(data_VX, data_VV, test_size=0, random_state=0)  # split the data sets

    clf = RandomForestClassifier(n_estimators=10)
    clf.fit(X_train, v_train)       # training the classifier for vendor detection

    v_predict = clf.predict(X_unknown)  # predict vendor types for unknown data (outputs a list of predictions, one for each unknown capture file)
    print("Predicted vendor: ", v_predict)

    for k in range(len(X_unknown)):
        if v_unknown[k] == v_predict[k]:  # calculate the vendor prediction accuracy
            if y_unknown[k] not in vendor_pred_accuracy:
                vendor_pred_accuracy[y_unknown[k]] = 1
            else:
                vendor_pred_accuracy[y_unknown[k]] += 1

    for i, (pre_vendor) in enumerate(v_predict):    # loop for predicting the device for the unknown fp based on predicted vendor
        data_y = dataset_y[dataset_v == pre_vendor]
        device_set = set(data_y)  # list of unique device labels for predicted vendor
        print("Device set: ", device_set)
        device_fp_counter = {}
        for device in device_set:  # get the number of fingerprints for each device under predicted vendor (not all vendors)
            count = 0
            for record in data_y:
                if record == device:
                    count += 1
                device_fp_counter[device] = count

        print("device_fp_counter: ", device_fp_counter)
        key_min = min(device_fp_counter,
                      key=device_fp_counter.get)  # find the device with minimum device fingerprints for the predicted vendor
        min_fp = device_fp_counter[
            key_min]  # number of minimum device fingerprints to be extracted from each device for the predicted vendor

        print("Minimum record: ", key_min, min_fp)
        data_DX = []
        data_DY = []

        for device in device_set:
            temp_X = dataset_X[dataset_y == device]     # filter all fps for a particular device
            out_list = sample(list(temp_X), min_fp)     # select a data sample from temp_X for a device
            for fp in out_list:
                data_DX.append(fp)                      # append device specific fingerprints to the training data set
                data_DY.append(device)                  # append device name to the respective training data set

        data_DX = np.array(data_DX)         # convert training data lists to numpy arrays
        data_DY = np.array(data_DY)

        X_train, X_test, y_train, y_test = train_test_split(data_DX, data_DY, test_size=0, random_state=0)      # split data
        clf_dev = RandomForestClassifier(n_estimators=10)
        clf_dev.fit(X_train, y_train)       # training the classifier for device detection under the predicted vendor

        unknown_fp = []
        unknown_fp.append(X_unknown[i])
        dev_predict = clf_dev.predict(unknown_fp)   # predict the device for each predicted vendor (one at a time)
        print("Predicted device: ", dev_predict, "\tPredicted vendor: ", pre_vendor, "\tActual device: ", y_unknown[i])

        if y_unknown[i] == dev_predict[0]:      # calculate the device prediction accuracy
            if y_unknown[i] not in dev_pred_accuracy:
                dev_pred_accuracy[y_unknown[i]] = 1
            else:
                dev_pred_accuracy[y_unknown[i]] += 1

print(len(dev_pred_accuracy))
print(dev_pred_accuracy)

for d in all_devices_set:       # check if there are devices which were not predicted correctly at least once
    if d not in dev_pred_accuracy:
        dev_pred_accuracy[d] = 0

for key, value in dev_pred_accuracy.items():
    dev_pred_accuracy[key] = value / num_of_iter  # produce the accuracy as a fraction for device predictions

print(len(dev_pred_accuracy))
print(dev_pred_accuracy)
print(len(vendor_pred_accuracy))
print(vendor_pred_accuracy)

plot_results(vendor_pred_accuracy)
plot_results(dev_pred_accuracy)