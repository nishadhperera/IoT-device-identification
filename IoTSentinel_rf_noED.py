import os
import fnmatch
import pyshark
import numpy as np
import pickle
import random
import operator
from random import randint
from scapy.all import *
from random import sample
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from pyxdameraulevenshtein import damerau_levenshtein_distance, normalized_damerau_levenshtein_distance
from sklearn import svm
from sklearn.metrics import classification_report, precision_recall_fscore_support
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
features_DL = {}
all_features_DL = {}
f_array = []
big_vector = []

vectors_edit_distance = {}  # stores the vectors for edit distance calculation


def pcap_class_generator(folder):
    for path, dir_list, file_list in os.walk(folder):
        for name in fnmatch.filter(file_list, "*.pcap"):
            global dst_ip_counter
            global dest_ip_set
            dest_ip_set.clear()  # stores the destination IP set
            dst_ip_counter = 0
            global feature_set
            global prev_class
            global big_vector
            global concat_feature
            print(os.path.join(path, name))
            prev_class = ""
            concat_feature = []
            feature_set = []
            big_vector = []
            yield os.path.join(path, name), os.path.basename(os.path.normpath(path))


def packet_class_generator(pcap_class_gen):
    for pcapfile, class_ in pcap_class_gen:
        #capture = pyshark.FileCapture(pcapfile)
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

        print(mac_address_list)
        print(src_mac_address_list)
        highest = max(mac_address_list.values())
        for k, v in mac_address_list.items():
            if v == highest:
                if k in src_mac_address_list:
                    source_mac_add = k
        capture_len = src_mac_address_list[source_mac_add]
        print("Source MAC ", source_mac_add)

        # for packet in capture:
        #     yield packet, class_

        for i, (packet) in enumerate(capture):
            if packet[0].src == source_mac_add:
                yield packet, class_


def feature_class_generator(packet_class_gen):

    for packet, class_ in packet_class_gen:
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

        yield fvector, class_


def dataset(feature_class_gen):
    global feature_set
    global prev_class
    global concat_feature
    global capture_len
    global count
    global f_array

    global big_vector
    big_vector = []

    def g():
        global feature_set
        global prev_class
        global concat_feature
        global capture_len
        global count
        global f_array
        global last_vector
        global big_vector

        for i, (feature, class_) in enumerate(feature_class_gen):
            print("Count = ", count)
            # This block removes the consecutive identical features from the data set
            if not last_vector:
                last_vector = feature
            else:
                if all(k == j for k, j in zip(last_vector, feature)):
                    print("Consecutive identical packet detected")
                    if capture_len == count:  # if the number of feature count is < 276,
                        print("Feature vector added_1:", class_, len(big_vector), big_vector)
                        yield big_vector, class_
                    continue
                last_vector = feature

            # Generate F Matrix from features
            if True:
                if not prev_class:
                    prev_class = class_
                    feature_set.append(feature)
                    concat_feature = concat_feature + feature
                    big_vector.append(feature)
                else:
                    if prev_class is class_:
                        feature_set.append(feature)
                        concat_feature = concat_feature + feature
                        big_vector.append(feature)
                        if len(feature_set) == 5:
                            if not class_ in vectors_edit_distance:
                                vectors_edit_distance[class_] = feature_set[0:5]
                    else:
                        prev_class = ""
                        feature_set = []
                        concat_feature = []
                        big_vector = []
                        feature_set.append(feature)
                        concat_feature = concat_feature + feature
                        big_vector.append(feature)

            # Generating the F' vector from F matrix
            if True:       # Get 12 unique features for each device type
                if not prev_class:                                      # concatenated into a 276 dimensional vector
                    prev_class = class_
                    feature_set.append(feature)
                    concat_feature = concat_feature + feature
                else:
                    if prev_class is class_:
                        if not feature in feature_set:  # Adding a unique feature
                            feature_set.append(feature)
                            concat_feature = concat_feature + feature
                            if len(feature_set) == 5:
                                if not class_ in vectors_edit_distance:
                                    vectors_edit_distance[class_] = feature_set[0:5]
                            # if len(feature_set) == 12:
                            #     yield concat_feature, class_
                            #     print("len(feature_set) == 12", len(concat_feature))
                    else:
                        prev_class = class_
                        feature_set = []
                        concat_feature = []
                        feature_set.append(feature)
                        concat_feature = concat_feature + feature

            if capture_len == count:  # if the number of feature count is < 276,
                print("Last packet of the file detected")
                # while len(concat_feature) < 276:                    # add 0's as padding
                #     concat_feature = concat_feature + [0]
                print("Feature vector added_2:", class_, len(big_vector), big_vector)
                # print("capture_len == count", len(concat_feature))
                yield big_vector, class_

    return zip(*g())


def load_data(pcap_folder_name):
    pcap_gen = pcap_class_generator(pcap_folder_name)
    packet_gen = packet_class_generator(pcap_gen)
    feature_gen = feature_class_generator(packet_gen)
    dataset_X, dataset_y = dataset(feature_gen)
    dataset_X = np.array(dataset_X)
    dataset_y = np.array(dataset_y)
    return dataset_X, dataset_y


def damerau_levenshtein(seq1, seq2):
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


def generate_f_dash(fp_set):
    added = []
    f_dash = []
    for fp in fp_set:
        print("fp: ", fp)
        if not added:
            print("added is empty, first unique feature detected and added")
            added.append(fp)
            f_dash = f_dash + fp
        else:
            if not fp in added:
                print("Unique feature detected and added")
                added.append(fp)
                f_dash = f_dash + fp

        if len(added) == 12:
            print("Returning f_dash")
            return f_dash

    if len(added) < 12:
        while len(f_dash) < 276:  # add 0's as padding
            f_dash = f_dash + [0]
        print("Returning f_dash after completing it to 276")
        return f_dash


if __name__ == "__main__":
    # pcap_folder="F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel_all\\Special"
    pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel_all\\captures_IoT-Sentinel"

    try:
        dataset_X = pickle.load(open("Org_Sentinel_dataset_X.pickle", "rb"))
        dataset_y = pickle.load(open("Org_Sentinel_dataset_y.pickle", "rb"))
        vectors_edit_distance = pickle.load(open("Org_Sentinel_features_DL.pickle", "rb"))
        print("Pickling successful IoTSentinel_random_forest......")
    except (OSError, IOError) as e:
        print("No pickle datasets are available....")
        dataset_X, dataset_y = load_data(pcap_folder)
        pickle.dump(dataset_X, open("Org_Sentinel_dataset_X.pickle", "wb"))
        pickle.dump(dataset_y, open("Org_Sentinel_dataset_y.pickle", "wb"))
        pickle.dump(vectors_edit_distance, open("Org_Sentinel_features_DL.pickle", "wb"))
        # all_features_DL = features_DL
        # features_DL = {}

    # features_DL = all_features_DL

    num_of_iter = 10
    same_to_other_ratio = 10
    dev_pred_accuracy = {}      # records pred_vector accuracy
    test_dev_counter = {}
    all_tested = []
    all_predicted = []

    from sklearn.model_selection import StratifiedKFold

    for j in range(num_of_iter):
        classifier_list = {}  # stores the computed classifiers

        # X_train, X_test, y_train, y_test = train_test_split(dataset_X, dataset_y, stratify=dataset_y, test_size=0.25,
        #                                                                             random_state=42)  # split dataset

        inner_iteration = 0
        skf = StratifiedKFold(n_splits=10, shuffle=True)
        for train_index, test_index in skf.split(dataset_X, dataset_y):
            X_train, X_test = dataset_X[train_index], dataset_X[test_index]
            y_train, y_test = dataset_y[train_index], dataset_y[test_index]

            X_unknown = X_test
            y_unknown = y_test

            device_set = set(y_train)  # list of unique device labels

            inner_iteration += 1
            # if inner_iteration > 1:
            #     break

            device_fp_counter = {}  # stores the fp count for each device

            for device in device_set:  # calculates the number of fps for each device
                count = 0
                # if not device in vectors_edit_distance:
                #     data = X_train[y_train == device]
                #     a = np.split(data[0], 12)
                #     vectors_edit_distance[device] = a[0:5]

                for record in y_train:
                    if record == device:
                        count += 1
                device_fp_counter[device] = count

            # print(len(vectors_edit_distance),  " Vectors_edit_distance: ", vectors_edit_distance)

            print("Number of different devices: ", len(device_set), device_set)

            test_set = set(y_unknown)  # list of unique device labels
            print("Number of test devices: ", len(test_set))
            print("Test Device set: ", test_set)

            Curr_test_dev_counter = collections.Counter(y_unknown)
            test_dev_counter = { k: test_dev_counter.get(k, 0) + Curr_test_dev_counter.get(k, 0)
                                 for k in set(test_dev_counter) | set(Curr_test_dev_counter)}

            # create the F' feature vectors and train the classifier
            for device in device_set:
                data_DX = []
                data_Dy = []

                temp_X = X_train[y_train == device]  # filter all fps for a particular device
                out_list = sample(list(temp_X), device_fp_counter[device])
                print("Out list generated with length: ", len(out_list))
                for fp_set in out_list:
                    print("Device: ", device, "fp_set length:", len(fp_set))
                    f_dash = generate_f_dash(fp_set)
                    data_DX.append(f_dash)
                    data_Dy.append(device)
                    print("f_dash added ", device, len(f_dash), f_dash)

                other_X = X_train[y_train != device]  # filter all fps NOT related to above device
                out_list = sample(list(other_X), device_fp_counter[
                    device] * same_to_other_ratio)  # select 10 times more data samples from other classes for a device
                print("Out list generated with length: ", len(out_list))
                for fp_set in out_list:
                    print("Device: ", device, "fp_set length:", len(fp_set))
                    f_dash = generate_f_dash(fp_set)
                    data_DX.append(f_dash)  # append other fingerprints to the training data set
                    data_Dy.append("Other")  # append device label as other to the respective training data set

                data_DX = np.array(data_DX)  # convert training data lists to numpy arrays
                data_Dy = np.array(data_Dy)
                print(j, inner_iteration, "Device: ", device, "Same size: ", len(temp_X), "other size: ", len(out_list),
                      "All size: ", len(data_DX), len(data_DX))

                clf = RandomForestClassifier(n_estimators=50, max_depth=3)
                clf.fit(data_DX, data_Dy)  # create a binary classifier for each device type
                classifier_list[device] = clf  # store the classifiers in dictionary object


            # for device in device_set:
            #     data_DX = []
            #     data_Dy = []
            #
            #     temp_X = X_train[y_train == device]                     # filter all fps for a particular device
            #     out_list = sample(list(temp_X), device_fp_counter[device])  # select all data samples from temp_X for a device
            #     for fp in out_list:
            #         data_DX.append(fp[:276])      # append device specific fingerprints to the training data set
            #         data_Dy.append(device)  # append device name to the respective training data set
            #
            #     other_X = X_train[y_train != device]            # filter all fps NOT related to above device
            #     out_list = sample(list(other_X), device_fp_counter[device] * same_to_other_ratio)  # select 10 times more data samples from other classes for a device
            #     for fp in out_list:
            #         data_DX.append(fp[:276])          # append other fingerprints to the training data set
            #         data_Dy.append("Other")     # append device label as other to the respective training data set
            #
            #     data_DX = np.array(data_DX)     # convert training data lists to numpy arrays
            #     data_Dy = np.array(data_Dy)
            #     print(j, inner_iteration, "Device: ", device, "Same size: ", len(temp_X), "other size: ", len(out_list), "All size: ", len(data_DX), len(data_DX))
            #
            #     clf = RandomForestClassifier(n_estimators=50, max_depth=3)
            #     clf.fit(data_DX, data_Dy)       # create a binary classifier for each device type
            #     classifier_list[device] = clf   # store the classifiers in dictionary object

            print("len(classifier_list): ", len(classifier_list))
            print(len(X_unknown), len(y_unknown))

            test_DX = []
            test_Dy = []
            for device in test_set:
                test_X = list(X_unknown[y_unknown == device])  # filter all fps for a particular device
                print("Test list generated with length: ", len(test_X))
                for fp_set in test_X:
                    print("Test Device: ", device, "fp_set length:", len(fp_set))
                    f_dash = generate_f_dash(fp_set)
                    test_DX.append(f_dash)
                    test_Dy.append(device)
                    print("Test f_dash added ", device, len(f_dash), f_dash)

            print("test_Dy:", test_Dy)
            print("test_DX:", test_DX)

            # 27 classifiers generated by this point
            for i in range(len(test_DX)):
                classifiers_results = []  # stores the positive classifier results
                all_tested.append(test_Dy[i])

                for device, classifier in classifier_list.items():
                    unknown_dev = []
                    unknown_dev.append(test_DX[i])

                    # dev_predict = classifier.predict(unknown_dev)
                    # if device == dev_predict[0]:
                    #     classifiers_results.append(device)
                    # print(y_unknown[i], "with ", device, "| classifier.predict_proba:", dev_predict, dev_predict_proba, "Classes:", classifier.classes_)

                    dev_predict_proba = classifier.predict_proba(unknown_dev)
                    probabilities = dev_predict_proba[0]
                    for k, (pred) in enumerate(probabilities):
                        # print(i, classifier.classes_[i], pred)
                        if (pred >= 0.2) and (classifier.classes_[k] != "Other"):
                            # print("Prediction appended", pred, classifier.classes_[i])
                            classifiers_results.append(classifier.classes_[k])

                print("Device: ", test_Dy[i], "Predicted classifiers: ", classifiers_results)

                if len(classifiers_results) > 1:
                    ED_results = {}         # stores results of edit distance calculations
                    for prediction in classifiers_results:
                        if prediction in vectors_edit_distance:   # previously all_features_DL
                            count = 0
                            edit_distance = 0
                            edit_distance_1 = 0

                            temp_comp = X_train[y_train == prediction]  # filter all fps for a particular device
                            out_list = sample(list(temp_comp), 5)  # select 5 data samples from temp_X for a device

                            for fp in out_list:
                                # print("Two vectors:")
                                # print("Ref_vector  :", str(fp))
                                # print("Unknown_vector:", str(X_unknown[i]))
                                edit_distance = edit_distance + normalized_damerau_levenshtein_distance(
                                    str(fp), str(X_unknown[i]))
                                print("edit_distance:", edit_distance)
                                # edit_distance = edit_distance + damerau_levenshtein(str(fp), str(X_unknown[i]))
                                # print("edit_distance: ", edit_distance)       # from IoT Sentinel


                            # for vector in vectors_edit_distance[pred_vector]:  # previously all_features_DL
                            #     # if vector == "End":
                            #     #     break
                            #     f_arr = []
                            #     for k in range(23):
                            #         f_arr.append(X_unknown[i][count+k])
                            #     # edit_distance = edit_distance + normalized_damerau_levenshtein_distance(str(features_DL[y_unknown[i]][count]), str(vector))
                            #     # print("Two vectors:")
                            #     # print("f_arr:", f_arr)
                            #     # print("vector", vector)
                            #     edit_distance = edit_distance + damerau_levenshtein(f_arr, vector)
                            #     count += 23
                            ED_results[prediction] = edit_distance

                    print("Edit distance results: ", ED_results.items())

                    if len(ED_results) > 1:
                        lowest = min(ED_results.values())
                        final_preds = []
                        for k, v in ED_results.items():
                            if v == lowest:
                                final_preds.append(k)

                        if len(final_preds) == 1:
                            print("lowest ED: ", final_preds[0])
                            all_predicted.append(final_preds[0])
                            if final_preds[0] == y_unknown[i]:
                                if y_unknown[i] not in dev_pred_accuracy:
                                    dev_pred_accuracy[y_unknown[i]] = 1
                                else:
                                    dev_pred_accuracy[y_unknown[i]] += 1
                        else:
                            rand_val = randint(0, len(final_preds)-1)
                            print("lowest ED: ", final_preds[rand_val])
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

    print(len(dev_pred_accuracy))
    print(dev_pred_accuracy)

    for d in device_set:       # check if there are devices which were not predicted correctly at least once
        if d not in dev_pred_accuracy:
            dev_pred_accuracy[d] = 0

    print(len(dev_pred_accuracy))
    print(dev_pred_accuracy)

    print("len(all_tested), len(all_predicted): ", len(all_tested), len(all_predicted))
    print("All tested: ", all_tested)
    print("All predicted: ", all_predicted)

    print(classification_report(all_tested, all_predicted))
    print(confusion_matrix(all_tested, all_predicted))

    for key, value in dev_pred_accuracy.items():
        dev_pred_accuracy[key] = value/(test_dev_counter[key])  # produce the accuracy as a fraction

    device_labels = ['Aria', 'HomeMaticPlug', 'Withings', 'MAXGateway', 'HueBridge', 'HueSwitch', 'EdnetGateway',
                     'EdnetCam', 'EdimaxCam', 'Lightify', 'WeMoInsightSwitch', 'WeMoLink', 'WeMoSwitch',
                     'D-LinkHomeHub', 'D-LinkDoorSensor', 'D-LinkDayCam', 'D-LinkCam', 'D-LinkSwitch',
                     'D-LinkWaterSensor', 'D-LinkSiren', 'D-LinkSensor', 'TP-LinkPlugHS110', 'TP-LinkPlugHS100',
                     'EdimaxPlug1101W', 'EdimaxPlug2101W', 'SmarterCoffee', 'iKettle2']

    prec, rec, f1_sco, supp = precision_recall_fscore_support(all_tested, all_predicted, labels=device_labels)

    # write the device pred_vector results into file
    file = open("F:\\MSC\\Master Thesis\\Results\\Files from python code\\IOT_sentinel_results.txt", "w")
    file.write("# Results of Device pred_vector accuracy\n")
    file.write("class_Name\t Accuracy\t precision\t recall\t f1-score\t support\n")
    for i in range(len(prec)):
        file.write(str(device_labels[i]) + "\t" + str(dev_pred_accuracy[device_labels[i]]) + "\t"
                   + str(prec[i]) + "\t" + str(rec[i]) + "\t" + str(f1_sco[i]) + "\t" + str(supp[i]) + "\n")
    file.close()

    accuracy = []
    for dev in device_labels:
        for key, value in dev_pred_accuracy.items():
            if key == dev:
                accuracy.append(value)

    x_pos = np.arange(len(device_labels))

    real_accuracy = [1.0, 1.0, 1.0, 1.0, 1.0, 0.98, 0.98, 0.95, 0.97, 0.96, 1.0, 1.0, 0.97, 1.0, 1.0, 1.0, 0.90, 0.62,
                     0.50, 0.42, 0.38, 0.65, 0.55, 0.625, 0.575, 0.45, 0.42]
    real_accuracy = [1.0, 0.45, 0.42]

    width = 0.35
    fig, ax = plt.subplots()
    rects1 = ax.bar(x_pos, real_accuracy, width, color='r')
    rects2 = ax.bar(x_pos + width, accuracy, width, color='y')
    ax.set_xticks(x_pos + width / 2)
    ax.set_xticklabels(device_labels, rotation=315, ha='left')
    ax.legend((rects1[0], rects2[0]), ('Original', 'Reproduced'))

    # plt.bar(x_pos, accuracy, align='edge')
    # plt.xticks(x_pos, all_device_labels, rotation=315, ha='left')
    # plt.ylabel('Accuracy')
    # plt.title('Random forest with Edit Distance (Identical to IoT Sentinel)')
    plt.grid(linestyle='dotted')
    plt.show()

# print(clf.score(X_test, y_test))