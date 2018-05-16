# This program contains a re-production of IoT sentinel approach of device identification
# Source file is a .pcap file and scapy has been used to manipulate packets
# Author: Nishadh Aluthge

import fnmatch
import numpy as np
import features_scapy as fe
from sklearn.model_selection import StratifiedKFold
from random import randint
from scapy.all import *
from random import sample
from sklearn.ensemble import RandomForestClassifier

concat_feature = [] # Holds the list of feature values
feature_set = []
last_vector = []    # for the comparison of consecutive identical packets
index_array = []
f_array = []
all_features_DL = {}
dest_ip_set = {}    # stores the destination IP set, a global variable
features_DL = {}
dst_ip_counter = 0  # keeps destination counter value, a global variable
packet_index = 0
capture_len = 0     # contains length of a capture
count = 0
source_mac_add = "" #source mac address of the device
prev_class = ""     # name of the previous device type

vectors_edit_distance = {}  # stores the vectors for edit distance calculation


def pcap_class_generator(folder):
    """ Generator function to generate a list of .pcap files """
    for path, dir_list, file_list in os.walk(folder):
        for name in fnmatch.filter(file_list, "*.pcap"):
            print(os.path.join(path, name), os.path.basename(os.path.normpath(path)))   # current file name
            global dst_ip_counter
            global dest_ip_set
            global packet_index
            global feature_set
            global prev_class
            global concat_feature
            dest_ip_set.clear()  # stores the destination IP set
            dst_ip_counter = 0
            prev_class = ""
            packet_index = 0
            concat_feature = []
            feature_set = []
            yield os.path.join(path, name), os.path.basename(os.path.normpath(path))


def packet_class_generator(pcap_class_gen):
    """ Generator function to filter packets based on mac-address """
    for pcapfile, class_ in pcap_class_gen:
        global capture_len
        global source_mac_add
        global count
        capture = rdpcap(pcapfile)      # Reading the network capture file usig scapy's rdpcap method
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
            if packet[0].src == source_mac_add:         # filter packets originated from the device
                yield packet, class_


def feature_class_generator(packet_class_gen):
    """ Generator function to extract features from a packet """
    for packet, class_ in packet_class_gen:
        global dst_ip_counter
        global dest_ip_set
        global last_vector
        global count
        count += 1

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

        yield fvector, class_


def dataset(feature_class_gen):
    """ Function to generate the complete dataset with 176 dimensional feature vectors """
    global feature_set
    global prev_class
    global concat_feature
    global capture_len
    global count
    global f_array
    global index_array
    global packet_index

    def g():
        global feature_set
        global prev_class
        global concat_feature
        global capture_len
        global count
        global f_array
        global last_vector
        global index_array
        global packet_index

        for i, (feature, class_) in enumerate(feature_class_gen):
            packet_index += 1
            if not last_vector:
                last_vector = feature
            else:
                if all(x == y for x, y in zip(last_vector, feature)):
                    if capture_len == count and len(concat_feature) < 276:  # if the number of feature count is < 276,
                        while len(concat_feature) < 276:  # add 0's as padding
                            concat_feature = concat_feature + [0]
                        index_array.append(packet_index)
                        yield concat_feature, class_
                    continue
                last_vector = feature

            if not class_ in features_DL:
                f_array = []
                f_array.append(feature)
                features_DL[class_] = f_array
            else:
                if len(f_array) == 5:
                    features_DL[class_] = f_array
                    f_array.append("End")
                elif len(f_array) < 5:
                    f_array.append(feature)

            # Generating the F' vector from F matrix
            if (len(feature_set) < 12) or (prev_class != class_):       # Get 12 unique features for each device type
                if not prev_class:                                      # concatenated into a 276 dimensional vector
                    prev_class = class_
                    feature_set.append(feature)
                    concat_feature = concat_feature + feature
                else:
                    if prev_class is class_:
                        if feature not in feature_set:  # Adding a unique feature
                            feature_set.append(feature)
                            concat_feature = concat_feature + feature
                            if len(feature_set) == 5:
                                if class_ not in vectors_edit_distance:
                                    vectors_edit_distance[class_] = feature_set[0:5]
                            if len(feature_set) == 12:
                                index_array.append(packet_index)
                                yield concat_feature, class_
                    else:
                        prev_class = ""
                        feature_set = []
                        concat_feature = []
                        feature_set.append(feature)
                        concat_feature = concat_feature + feature

            if capture_len == count and len(concat_feature) < 276:  # if the number of feature count is < 276,
                while len(concat_feature) < 276:                    # add 0's as padding
                    concat_feature = concat_feature + [0]
                index_array.append(packet_index)
                yield concat_feature, class_

    return zip(*g())


def load_data(pcap_folder_name):
    """ Loading the data from the generator functions """
    pcap_gen = pcap_class_generator(pcap_folder_name)
    packet_gen = packet_class_generator(pcap_gen)
    feature_gen = feature_class_generator(packet_gen)
    dataset_X, dataset_y = dataset(feature_gen)
    dataset_X = np.array(dataset_X)
    dataset_y = np.array(dataset_y)
    return dataset_X, dataset_y


def damerau_levenshtein(seq1, seq2):
    """ Function to calculate damerau_levenshtein edi distance """
    oneago = None
    thisrow = list(range(1, len(seq2) + 1)) + [0]
    for x in range(len(seq1)):
        twoago, oneago, thisrow = oneago, thisrow, [0] * len(seq2) + [x + 1]
        for y in range(len(seq2)):
            delcost = oneago[y] + 1
            addcost = thisrow[y - 1] + 1
            subcost = oneago[y - 1] + (seq1[x] != seq2[y])

            if x > 1 and y > 1 and seq1[x] == seq2[y - 1] and seq1[x - 1] == seq2[y]:
                transposition = twoago[y - 2]
                thisrow[y] = min(delcost, addcost, subcost, transposition)
            else:
                thisrow[y] = min(delcost, addcost, subcost)
    return float(thisrow[len(seq2) - 1]) / float(max(len(seq1), len(seq2)))


def calc_feature_importance(classifier, Number_of_features, f_impor, iterationwise_fimpor):
    """ Function to calculate feature importance in sklearn classifiers """
    importances = classifier.feature_importances_  # calculates the feature importance
    std = np.std([tree.feature_importances_ for tree in classifier.estimators_], axis=0)
    indices = np.argsort(importances)[::-1]
    for f in range(276):
        if indices[f] % Number_of_features not in f_impor:
            f_impor[indices[f] % Number_of_features] = importances[indices[f]]
            iterationwise_fimpor[indices[f] % Number_of_features] = [importances[indices[f]]]
        else:
            f_impor[indices[f] % Number_of_features] += importances[indices[f]]
            iterationwise_fimpor[indices[f] % Number_of_features].append(importances[indices[f]])
    return f_impor, iterationwise_fimpor


def plot(device_labels, accuracy, y_lbl, title):
    """ Function to plot the device prediction accuracy """
    x_pos = np.arange(len(device_labels))

    real_accuracy = [1.0, 1.0, 1.0, 1.0, 1.0, 0.98, 0.98, 0.95, 0.97, 0.96, 1.0, 1.0, 0.97, 1.0, 1.0, 1.0, 0.90, 0.62,
                     0.50, 0.42, 0.38, 0.65, 0.55, 0.625, 0.575, 0.45, 0.42]
    width = 0.35
    fig, ax = plt.subplots()
    rects1 = ax.bar(x_pos, real_accuracy, width, color='r')
    rects2 = ax.bar(x_pos + width, accuracy, width, color='y')
    ax.set_xticks(x_pos + width / 2)
    ax.set_xticklabels(device_labels)
    ax.legend((rects1[0], rects2[0]), ('Real Implementation', 'Current Implementation'))

    plt.bar(x_pos, accuracy, align='edge')
    plt.xticks(x_pos, device_labels, rotation=315, ha='left')
    plt.ylabel(y_lbl)
    plt.title(title)
    plt.grid(linestyle='dotted')
    plt.show()


if __name__ == "__main__":
    # Folder containing the network trace files
    pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel_all\\captures_IoT-Sentinel"

    device_labels = ['Aria', 'HomeMaticPlug', 'Withings', 'MAXGateway', 'HueBridge', 'HueSwitch', 'EdnetGateway',
                     'EdnetCam', 'EdimaxCam', 'Lightify', 'WeMoInsightSwitch', 'WeMoLink', 'WeMoSwitch',
                     'D-LinkHomeHub', 'D-LinkDoorSensor', 'D-LinkDayCam', 'D-LinkCam', 'D-LinkSwitch',
                     'D-LinkWaterSensor', 'D-LinkSiren', 'D-LinkSensor', 'TP-LinkPlugHS110', 'TP-LinkPlugHS100',
                     'EdimaxPlug1101W', 'EdimaxPlug2101W', 'SmarterCoffee', 'iKettle2']

    try:
        # Loading the pickeld data. PLEASE RELOAD data after adding a new feature
        dataset_X = pickle.load(open("Sentinel_dataset_X.pickle", "rb"))
        dataset_y = pickle.load(open("Sentinel_dataset_y.pickle", "rb"))
        vectors_edit_distance = pickle.load(open("Sentinel_features_DL.pickle", "rb"))
        print("Pickling successful IoTSentinel_random_forest......")
    except (OSError, IOError) as e:
        # Extract the features from packet traces and generate a new dataset and pickle it after that
        dataset_X, dataset_y = load_data(pcap_folder)
        pickle.dump(dataset_X, open("Sentinel_dataset_X.pickle", "wb"))
        pickle.dump(dataset_y, open("Sentinel_dataset_y.pickle", "wb"))
        pickle.dump(vectors_edit_distance, open("Sentinel_features_DL.pickle", "wb"))

    num_of_iter = 10            # number of iterations the prediction happens
    same_to_other_ratio = 10    # Dataset split ratio
    dev_pred_accuracy = {}      # records pred_vector accuracy
    test_dev_counter = {}
    all_tested = []
    all_predicted = []
    f_importance = {}
    iterationwise_fimportance = {}
    Number_of_features = 23

    for j in range(num_of_iter):
        print("Running the iteration number: ", j)
        classifier_list = {}  # stores the computed classifiers

        skf = StratifiedKFold(n_splits=10, shuffle=True)
        for train_index, test_index in skf.split(dataset_X, dataset_y):
            X_train, X_test = dataset_X[train_index], dataset_X[test_index]
            y_train, y_test = dataset_y[train_index], dataset_y[test_index]

            X_unknown = X_test
            y_unknown = y_test

            device_set = set(y_train)  # list of unique device labels
            device_fp_counter = {}  # stores the fp count for each device

            for device in device_set:  # calculates the number of fps for each device
                count = 0
                for record in y_train:
                    if record == device:
                        count += 1
                device_fp_counter[device] = count

            test_set = set(y_unknown)  # list of unique device labels

            Curr_test_dev_counter = collections.Counter(y_unknown)
            test_dev_counter = { k: test_dev_counter.get(k, 0) + Curr_test_dev_counter.get(k, 0)
                                 for k in set(test_dev_counter) | set(Curr_test_dev_counter) }

            for device in device_set:
                data_DX = []
                data_Dy = []

                temp_X = X_train[y_train == device]                     # filter all fps for a particular device
                out_list = sample(list(temp_X), device_fp_counter[device])  # select all data samples from temp_X for a device
                for fp in out_list:
                    data_DX.append(fp)      # append device specific fingerprints to the training data set
                    data_Dy.append(device)  # append device name to the respective training data set

                other_X = X_train[y_train != device]            # filter all fps NOT related to above device
                out_list = sample(list(other_X), device_fp_counter[device] * same_to_other_ratio)  # select 10 times more data samples from other classes for a device
                for fp in out_list:
                    data_DX.append(fp)          # append other fingerprints to the training data set
                    data_Dy.append("Other")     # append device label as other to the respective training data set

                data_DX = np.array(data_DX)     # convert training data lists to numpy arrays
                data_Dy = np.array(data_Dy)

                clf = RandomForestClassifier(n_estimators=50, max_depth=3)
                clf.fit(data_DX, data_Dy)       # create a binary classifier for each device type
                f_importance, iterationwise_fimportance = calc_feature_importance(clf, Number_of_features, f_importance, iterationwise_fimportance)
                classifier_list[device] = clf   # store the classifiers in dictionary object

            # 27 classifiers generated by this point
            for i in range(len(X_unknown)):
                classifiers_results = []  # stores the positive classifier results
                all_tested.append(y_unknown[i])

                for device, classifier in classifier_list.items():
                    unknown_dev = []
                    unknown_dev.append(X_unknown[i])

                    dev_predict_proba = classifier.predict_proba(unknown_dev)
                    probabilities = dev_predict_proba[0]
                    for k, (pred) in enumerate(probabilities):
                        if (pred >= 0.2) and (classifier.classes_[k] != "Other"):
                            classifiers_results.append(classifier.classes_[k])

                print("classifiers_results: ", classifiers_results)
                if len(classifiers_results) > 1:
                    ED_results = {}         # stores results of edit distance calculations
                    for prediction in classifiers_results:
                        if prediction in vectors_edit_distance:   # previously all_features_DL
                            count = 0
                            edit_distance = 0

                            temp_comp = X_train[y_train == prediction]  # filter all fps for a particular device
                            out_list = sample(list(temp_comp), 5)  # select all data samples from temp_X for a device
                            for fp in out_list:
                                edit_distance += damerau_levenshtein(str(list(X_unknown[i])), str(list(fp)))
                            ED_results[prediction] = edit_distance

                    if len(ED_results) > 1:
                        lowest = min(ED_results.values())
                        final_preds = []
                        for k, v in ED_results.items():
                            if v == lowest:
                                final_preds.append(k)

                        if len(final_preds) == 1:
                            all_predicted.append(final_preds[0])
                            if final_preds[0] == y_unknown[i]:
                                if y_unknown[i] not in dev_pred_accuracy:
                                    dev_pred_accuracy[y_unknown[i]] = 1
                                else:
                                    dev_pred_accuracy[y_unknown[i]] += 1
                        else:
                            rand_val = randint(0, len(final_preds)-1)
                            all_predicted.append(final_preds[rand_val])
                            if final_preds[rand_val] == y_unknown[i]:
                                if y_unknown[i] not in dev_pred_accuracy:
                                    dev_pred_accuracy[y_unknown[i]] = 1
                                else:
                                    dev_pred_accuracy[y_unknown[i]] += 1

                elif len(classifiers_results) == 1:
                    all_predicted.append(classifiers_results[0])
                    if classifiers_results[0] == y_unknown[i]:
                        if y_unknown[i] not in dev_pred_accuracy:
                            dev_pred_accuracy[y_unknown[i]] = 1
                        else:
                            dev_pred_accuracy[y_unknown[i]] += 1

                else:
                    all_predicted.append("None")

    for d in device_set:       # check if there are devices which were not predicted correctly at least once
        if d not in dev_pred_accuracy:
            dev_pred_accuracy[d] = 0

    for key, value in dev_pred_accuracy.items():
        dev_pred_accuracy[key] = value/(test_dev_counter[key])  # produce the accuracy as a fraction

    accuracy = []
    for dev in device_labels:
        for key, value in dev_pred_accuracy.items():
            if key == dev:
                accuracy.append(value)

    # Plotting the device prediction accuracy
    y_lbl = 'Accuracy'
    title = 'Random Forest Prediction with Edit Distance (IoT Sentinel)'
    plot(device_labels, accuracy, y_lbl, title)
