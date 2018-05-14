from scapy.all import *
import fnmatch
import matplotlib.pyplot as plt
import numpy as np
from scipy.fftpack import fft
import bottleneck
import math
from random import sample
import operator
import collections
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from scipy.spatial import distance
from sklearn.metrics import confusion_matrix, f1_score, classification_report, precision_recall_fscore_support
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.model_selection import StratifiedKFold
import datetime

from sklearn import svm
from sklearn.svm import LinearSVC
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.gaussian_process.kernels import RBF
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import MinMaxScaler
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis


import features_scapy as fe

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
dest_ip_set = {}    # stores the destination IP set, a global variable
dst_ip_counter = 0  # keeps destination counter value, a global variable
dest_ip_seq = []
dest_ip_counter_list = []
src_port_class_list = []
dst_port_class_list = []
src_port_cls = []
dst_port_cls = []
dhcp_opt_sum = []
dhcp_options_sum_list = []
rate_start_time = 0
pkt_rate = []
pkt_rate_list = []
source_mac_add = ""
new_device = False
slice_length = 0

feature_list = []       # stores the features
feature_name_list = []  # stores the feature names
device_list = []        # stores the device names

import IoTSentinel_rf
IoTobject = IoTSentinel_rf


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
    global dst_ip_counter
    global dest_ip_set
    global dest_ip_seq
    global dest_ip_counter_list
    global src_port_class_list
    global dst_port_class_list
    global src_port_cls
    global dst_port_cls
    global dhcp_opt_sum
    global dhcp_options_sum_list
    global pkt_rate
    global pkt_counter
    global rate_start_time

    for path, dir_list, file_list in os.walk(pcap_folder):

        for name in fnmatch.filter(file_list, "*.pcap"):
            print(os.path.join(path, name), os.path.basename(os.path.normpath(path)))
            new_device = True

            if IA_times:
                IA_times_list.append(IA_times)
                IA_times = []
                prev_packet = ""
            if ether_len:
                # print("ether_len", ether_len)
                ether_len_list.append(ether_len)
                ether_len = []
            if IP_len:
                # print("IP_len", IP_len)
                IP_len_list.append(IP_len)
                IP_len = []
            if IP_header_len:
                IP_header_len_list.append(IP_header_len)
                IP_header_len = []
            if pkt_counter > 0:
                pkt_rate.append(pkt_counter)
                pkt_rate_list.append(pkt_rate)
                pkt_rate = []
                pkt_counter = 0
                rate_start_time = 0
            # if pkt_counter > 0:
            #     pkt_count_list.append(pkt_counter)
            #     pkt_counter = 0
            if pkt_direction:
                pkt_direction_list.append(pkt_direction)
                pkt_direction = []
            if len(dest_ip_seq) > 0:
                dest_ip_counter_list.append(dest_ip_seq)
                dst_ip_counter = 0
                dest_ip_set = {}
                dest_ip_seq = []
            if src_port_cls:
                src_port_class_list.append(src_port_cls)
                dst_port_class_list.append(dst_port_cls)
                src_port_cls = []
                dst_port_cls = []
            if dhcp_opt_sum:
                print("dhcp_opt_sum", dhcp_opt_sum)
                dhcp_options_sum_list.append(dhcp_opt_sum)
                dhcp_opt_sum = []
            IoTobject.prev_class = ""
            IoTobject.concat_feature = []
            IoTobject.feature_set = []
            IoTobject.dest_ip_set.clear()
            IoTobject.dst_ip_counter = 0
            yield os.path.join(path, name), os.path.basename(os.path.normpath(path))


def packet_filter_generator(pcap_class_gen, filter_con):
    global source_mac_add

    for pcapfile, device_name in pcap_class_gen:
        capture = rdpcap(pcapfile)
        mac_address_list = {}
        src_mac_address_list = {}
        IoTobject.capture_len = 0
        IoTobject.count = 0

        mac_addresses = {'Aria': ['20:f8:5e:ca:91:52'], 'D-LinkCam': ['b0:c5:54:25:5b:0e'],
                         'D-LinkDayCam': ['b0:c5:54:1c:71:85'],
                         'D-LinkDoorSensor': ['1c:5f:2b:aa:fd:4e'], 'D-LinkHomeHub': ['1c:5f:2b:aa:fd:4e'],
                         'D-LinkSensor': ['90:8d:78:a8:e1:43'], 'D-LinkSiren': ['90:8d:78:dd:0d:60'],
                         'D-LinkSwitch': ['90:8d:78:a9:3d:6f'], 'D-LinkWaterSensor': ['6c:72:20:c5:17:5a'],
                         'EdimaxCam': ['74:da:38:80:79:fc', '74:da:38:80:7a:08'],
                         'EdimaxPlug1101W': ['74:da:38:4a:76:49'],
                         'EdimaxPlug2101W': ['74:da:38:23:22:7b'],
                         'EdnetCam': ['3c:49:37:03:17:f0', '3c:49:37:03:17:db'],
                         'EdnetGateway': ['ac:cf:23:62:3c:6e'], 'HomeMaticPlug': ['00:1a:22:05:c4:2e'],
                         'HueBridge': ['00:17:88:24:76:ff'], 'HueSwitch': ['00:17:88:24:76:ff'],
                         'iKettle2': ['5c:cf:7f:06:d9:02'],
                         'Lightify': ['84:18:26:7b:5f:6b'], 'MAXGateway': ['00:1a:22:03:cb:be'],
                         'SmarterCoffee': ['5c:cf:7f:07:ae:fb'], 'TP-LinkPlugHS100': ['50:c7:bf:00:fc:a3'],
                         'TP-LinkPlugHS110': ['50:c7:bf:00:c7:03'], 'WeMoInsightSwitch': ['94:10:3e:41:c2:05'],
                         'WeMoLink': ['94:10:3e:cd:37:65'], 'WeMoSwitch': ['94:10:3e:35:01:c1'],
                         'Withings': ['00:24:e4:24:80:2a']}

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

        # highest = max(mac_address_list.values())
        # for k, v in mac_address_list.items():
        #     if v == highest:
        #         if k in src_mac_address_list:
        #             source_mac_add = k
        # IoTobject.capture_len = src_mac_address_list[source_mac_add]
        # print("Source MAC ", source_mac_add)

        highest = max(mac_address_list.values())
        real_mac = mac_addresses[device_name]
        for k, v in mac_address_list.items():
            if v == highest and k in real_mac:
                if k in src_mac_address_list:
                    source_mac_add = k
        print("Source MAC ", source_mac_add)

        count_pkts = 0
        t_21 = 0

        for i, (packet) in enumerate(capture):
            if filter_con == "bidirectional":           # filter bidirectional traffic on source
                if packet[0].src == source_mac_add or packet[0].dst == source_mac_add:
                    count_pkts += 1
                    if count_pkts > slice_length:
                        break
                    else:
                        yield packet, device_name
            elif filter_con == "Src_to_Other":          # filter traffic originated from source
                if packet[0].src == source_mac_add:
                    count_pkts += 1

                    if count_pkts == 1:
                        if t_21 > 0:
                            duration = t_21 - t_1
                            print("Duration:", duration)
                            min_capture_durations.append(duration)
                        t_1 = packet.time
                        print("1st packet.time: ", t_1)
                    elif count_pkts == slice_length:
                        # t_21 = packet.time
                        print("21st packet.time: ", t_21)
                        # duration = t_21 - t_1
                        # print("Duration:", duration)
                        # min_capture_durations.append(duration)
                    t_21 = packet.time

                    if count_pkts > slice_length:
                        break
                    else:
                        yield packet, device_name
            elif filter_con == "Other_to_Src":          # filter traffic destined to source
                if packet[0].dst == source_mac_add:
                    count_pkts += 1
                    if count_pkts > slice_length:
                        break
                    else:
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


def plot_results(dict_obj, title, item_index, reverse, y_lable):
    dataset = sorted(dict_obj.items(), key=operator.itemgetter(item_index),
                     reverse=reverse)  # sort the dictionary with values

    # plot the results (device type vs accuracy of pred_vector)
    device = list(zip(*dataset))[0]
    accuracy = list(zip(*dataset))[1]

    x_pos = np.arange(len(device))

    plt.stem(x_pos, accuracy, align='edge', color='g')
    plt.xticks(x_pos, device, rotation=315, ha='center')
    plt.ylabel(y_lable)
    plt.title(title)
    plt.grid(linestyle='dotted')
    plt.show()


def plot_confusion_matrix(cm, classes, normalize, title='Confusion matrix', cmap=plt.cm.Blues):
    """
    This function prints and plots the confusion matrix.
    Normalization can be applied by setting `normalize=True`.
    """
    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        print("Normalized confusion matrix")
    else:
        print('Confusion matrix, without normalization')

    print(cm)

    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title, y=-0.08)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45, ha='left')
    plt.tick_params('x', labelbottom='off', labeltop='on')
    plt.yticks(tick_marks, classes)

    fmt = '.2f' if normalize else 'd'
    thresh = cm.max() / 2.
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, format(cm[i, j], fmt),
                 horizontalalignment="center",
                 color="white" if cm[i, j] > thresh else "black")

    # plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.show()


def plot_pred_accuracy(pred_accuracy, title, item_index, reverse, y_lable):
    score = 1.96

    print("pred_accuracy:", pred_accuracy)
    mean_accuracy = {}
    stdDev_accuracy = {}
    sample_size = {}
    # skipped_devices_list = ['Aria', 'HomeMaticPlug', 'Withings', 'MAXGateway', 'HueBridge', 'EdnetGateway',
    #                         'HueSwitch', 'WeMoInsightSwitch', 'WeMoLink', 'D-LinkHomeHub', 'D-LinkDoorSensor',
    #                         'D-LinkDayCam']
    skipped_devices_list = []

    for key, value in pred_accuracy.items():
        if not key in skipped_devices_list:
            mean_accuracy[key] = np.round(np.mean(value), 2)
            stdDev_accuracy[key] = np.std(value)
            sample_size[key] = len(value)

    print("mean_accuracy:", mean_accuracy)
    print("stdDev_accuracy:", stdDev_accuracy)

    dataset = sorted(mean_accuracy.items(), key=operator.itemgetter(item_index),
                     reverse=reverse)  # sort the dictionary with values

    # plot the results (device type vs accuracy of pred_vector)
    # device_list = list(zip(*dataset))[0]
    # accuracy = list(zip(*dataset))[1]

    device_list = ['HueBridge', 'Withings', 'WeMoSwitch', 'HomeMaticPlug', 'Aria', 'EdimaxCam', 'WeMoLink', 'D-LinkCam',
                   'D-LinkDayCam', 'D-LinkHomeHub', 'EdnetGateway', 'EdnetCam', 'HueSwitch', 'WeMoInsightSwitch',
                   'MAXGateway', 'Lightify', 'D-LinkDoorSensor', 'D-LinkSwitch', 'TP-LinkPlugHS100', 'TP-LinkPlugHS110',
                   'EdimaxPlug2101W', 'iKettle2', 'D-LinkSensor', 'SmarterCoffee', 'EdimaxPlug1101W', 'D-LinkSiren',
                   'D-LinkWaterSensor']

    x_pos = np.arange(len(device_list))

    std_dev = []
    accuracy = []
    for dev in device_list:
        std_dev.append(score * (stdDev_accuracy[dev]/np.sqrt(sample_size[dev])))
        accuracy.append(mean_accuracy[dev])

    yerr_lower = np.zeros(len(accuracy))
    yerr_upper = np.zeros(len(accuracy))
    for i, (data) in enumerate(accuracy):
        if (data+std_dev[i]) >= 1:
            yerr_upper[i] = (1 - data)
        else:
            yerr_upper[i] = std_dev[i]
        if (data-std_dev[i]) <= 0:
            yerr_lower[i] = (data)
        else:
            yerr_lower[i] = std_dev[i]

    print("Device_list", device_list)
    print("Accuracy:", accuracy)
    # print("std_dev:", std_dev)
    # print("yerr_upper:", yerr_upper)
    # print("yerr_lower:", yerr_lower)

    plt.rcParams.update({'font.size': 26})
    plt.rc('axes', labelsize="32", labelweight='bold')
    plt.rcParams["figure.figsize"] = [16, 8]

    # plt.stem(x_pos, accuracy, align='edge', color='g')
    plt.bar(x_pos, accuracy, align='center', color='#0485d1', edgecolor='k', linewidth=0.1)
    plt.errorbar(x_pos, accuracy, yerr=[yerr_lower, yerr_upper], fmt='none', ecolor='k', capsize=3)
    plt.xticks(x_pos, device_list, rotation=315, ha='left')
    plt.ylabel(y_lable)
    # plt.title(title)
    plt.grid(linestyle='dotted')

    plt.savefig("F:\\MSC\\Master Thesis\\Results\\Classifier comparison\\fig_clf_RF.pdf",
                bbox_inches='tight')
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
    global slice_length

    IA_times_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        if prev_packet == "":
            pass
        else:
            time_gap = packet.time - prev_packet.time
            IA_times.append(abs(time_gap))
        prev_packet = packet
        yield packet, dev_name

    IA_times_list.append(IA_times)
    IA_times = []
    prev_packet = ""
    # print("len(IA_times_list)", len(IA_times_list))

    for i, (data) in enumerate(IA_times_list):
        data = data[:min(slice_length, len(data)-1)]
        min_IAT = min(data)  # minimum packet inter-arrival time
        max_IAT = max(data)  # maximum packet inter-arrival time
        q1_IAT = np.percentile(data, 25)    # first quartile of inter-arrival time
        median_IAT = np.percentile(data, 50)    # median of inter-arrival time
        mean_IAT = np.mean(data)                # mean of inter-arrival time
        q3_IAT = np.percentile(data, 75)    # third quartile of inter-arrival time
        var_IAT = np.var(data)              # variance of inter-arrival time
        iqr_IAT = q3_IAT - q1_IAT           # inter quartile range of inter-arrival time

        # print(i, "IA features: ", filter_con, min_IAT, max_IAT, q1_IAT, median_IAT, mean_IAT, q3_IAT, var_IAT, iqr_IAT)

        feature_list[i].append(min_IAT)
        feature_list[i].append(max_IAT)
        feature_list[i].append(q1_IAT)
        feature_list[i].append(median_IAT)
        feature_list[i].append(mean_IAT)
        feature_list[i].append(q3_IAT)
        feature_list[i].append(var_IAT)
        feature_list[i].append(iqr_IAT)

        # FFT calculation for inter-arrival times
        data = np.array(data[:min(slice_length, len(data)-1)])
        min_len = min(len(data), 10)        # get 10 fft components or the minimum length of input data to fft
        fft_data = fft(data)                # calculate fft with scipy
        fft_data = np.abs(fft_data)         # get the magnitudes of fft components
        z = -bottleneck.partition(-fft_data, min_len - 1)[:min_len]     # get the max components
        sorted_fft = np.sort(z)
        sorted_fft[:] = sorted_fft[::-1]    # sort the fft components from largest to smallest

        if len(sorted_fft) < 10:            # pad the array with zeros if at least 10 fft components are not there
            sorted_fft = np.append(sorted_fft, np.zeros(10 - len(sorted_fft)))

        # print(i, "FFT features: ", filter_con, sorted_fft)
        for fft_val in sorted_fft:          # append fft values to feature list
            feature_list[i].append(fft_val)


    # plot_list(IA_times_list, "Inter arrival time variation with the packet count (%s)" % filter_con, "Packet count",
    #           "Inter arrival time (s)")


def calc_ethsize_features(packet_list, filter_con):
    global ether_len
    global ether_len_list
    global slice_length
    ether_len_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            ether_len.append(len(packet))
        except IndexError:
            pass
        yield packet, dev_name

        # try:
        #     pad_len = len(packet["Padding"])
        #     e_len = len(packet) - len(packet.payload) + pad_len
        # except IndexError:
        #     pad_len = 0
        #     e_len = len(packet) - len(packet.payload) + pad_len
        # ether_len.append(e_len)
        # yield packet, dev_name

    # print("ether_len", ether_len)
    ether_len_list.append(ether_len)
    ether_len = []

    for i, (data) in enumerate(ether_len_list):
        data = data[:min(slice_length, len(data)-1)]
        min_ethlen = min(data)  # minimum ethernet packet size
        max_ethlen = max(data)  # maximum ethernet packet size
        q1_ethlen = np.percentile(data, 25)  # first quartile of ethernet packet size
        median_ethlen = np.percentile(data, 50)  # median of ethernet packet size
        mean_ethlen = np.mean(data)  # mean of ethernet packet size
        q3_ethlen = np.percentile(data, 75)  # third quartile of ethernet packet size
        var_ethlen = np.var(data)  # variance of ethernet packet size
        iqr_ethlen = q3_ethlen - q1_ethlen      # IQR of ethernet packet size

        print(i, "Ethernet packet size features: ", min_ethlen, max_ethlen, q1_ethlen, median_ethlen, mean_ethlen,
              q3_ethlen, var_ethlen, iqr_ethlen)

        feature_list[i].append(min_ethlen)
        feature_list[i].append(max_ethlen)
        feature_list[i].append(q1_ethlen)
        feature_list[i].append(median_ethlen)
        feature_list[i].append(mean_ethlen)
        feature_list[i].append(q3_ethlen)
        feature_list[i].append(var_ethlen)
        feature_list[i].append(iqr_ethlen)

    # plot_list(ether_len_list, "Ethernet packet size variation pattern with number of packets (%s)" % filter_con, "Packet count",
    #           "Ethernet packet size")


def calc_IP_payload_size_features(packet_list, filter_con):
    global IP_len
    global IP_len_list
    global slice_length
    IP_len_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            IP_len.append(packet["IP"].len - packet["IP"].ihl)
        except IndexError:
            # IP_len.append(0)
            pass
        yield packet, dev_name

    # print("IP_len", IP_len)
    IP_len_list.append(IP_len)
    IP_len = []

    for i, (data) in enumerate(IP_len_list):
        if len(data) == 0:
            data.append(0)
        data = data[:min(slice_length, len(data)-1)]
        min_ip_len = min(data)  # minimum IP packet size
        max_ip_len = max(data)  # maximum IP packet size
        q1_ip_len = np.percentile(data, 25)  # first quartile of IP packet size
        median_ip_len = np.percentile(data, 50)  # median of IP packet size
        mean_ip_len = np.mean(data)  # mean of IP packet size
        q3_ip_len = np.percentile(data, 75)  # third quartile of IP packet size
        var_ip_len = np.var(data)  # variance of IP packet size
        iqr_ip_len = q3_ip_len - q1_ip_len  # IQR of IP packet size

        # print(i, "IP payload size features: ", min_ip_len, max_ip_len, q1_ip_len, median_ip_len, mean_ip_len, q3_ip_len, var_ip_len, iqr_ip_len)

        feature_list[i].append(min_ip_len)
        feature_list[i].append(max_ip_len)
        feature_list[i].append(q1_ip_len)
        feature_list[i].append(median_ip_len)
        feature_list[i].append(mean_ip_len)
        feature_list[i].append(q3_ip_len)
        feature_list[i].append(var_ip_len)
        feature_list[i].append(iqr_ip_len)

    # plot_list(IP_len_list, "IP packet size variation pattern with number of packets (%s)" % filter_con, "Packet count",
    #           "IP packet size")


def calc_IP_header_size_features(packet_list, filter_con):
    global IP_header_len
    global IP_header_len_list
    global slice_length
    IP_header_len_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            IP_header_len.append(packet["IP"].ihl)
        except IndexError:
            # IP_header_len.append(0)
            pass
        yield packet, dev_name

    IP_header_len_list.append(IP_header_len)
    IP_header_len = []

    for i, (data) in enumerate(IP_header_len_list):
        if len(data) == 0:
            data.append(0)
        data = data[:min(slice_length, len(data)-1)]
        min_iph_len = min(data)  # minimum IP packet header size
        max_iph_len = max(data)  # maximum IP packet header size
        q1_iph_len = np.percentile(data, 25)  # first quartile of IP packet header size
        median_iph_len = np.percentile(data, 50)  # median of IP packet header size
        mean_iph_len = np.mean(data)  # mean of IP packet header size
        q3_iph_len = np.percentile(data, 75)  # third quartile of IP packet header size
        var_iph_len = np.var(data)  # variance of IP packet header size
        iqr_iph_len = q3_iph_len - q1_iph_len   # IQR of IP packet header size

        print(i, "IP packet header size features: ", min_iph_len, max_iph_len, q1_iph_len, median_iph_len, mean_iph_len, q3_iph_len, var_iph_len, iqr_iph_len)

        feature_list[i].append(min_iph_len)
        feature_list[i].append(max_iph_len)
        feature_list[i].append(q1_iph_len)
        feature_list[i].append(median_iph_len)
        feature_list[i].append(mean_iph_len)
        feature_list[i].append(q3_iph_len)
        feature_list[i].append(var_iph_len)
        feature_list[i].append(iqr_iph_len)

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
    # print("length of Packet counts list: ", len(pkt_count_list))

    for i, (data) in enumerate(pkt_count_list):
        feature_list[i].append(data)


def calc_pkt_directions(packet_list, filter_con):
    global pkt_direction
    global pkt_direction_list
    global source_mac_add
    global slice_length

    pkt_direction_list = []
    pkt_direction = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            if packet[0].src == source_mac_add:
                pkt_direction.append(0)
            elif packet[0].dst == source_mac_add:
                pkt_direction.append(1)
        except IndexError:
            pkt_direction.append(2)
        yield packet, dev_name

    pkt_direction_list.append(pkt_direction)

    for i, (data) in enumerate(pkt_direction_list):
        concat_pkt_dir = ""
        # for j in range(slice_length):
        #     if j < len(data):
        #         concat_pkt_dir = concat_pkt_dir + str(data[j])
        #         # ethernet_len_list[i].append(data[j])
        #         # if i == 0:
        #         #     feature_name_list.append("Packet direction #" + str(j) + " (" + filter_con + ")")
        #     else:
        #         concat_pkt_dir = concat_pkt_dir + str(2)
        #         # ethernet_len_list[i].append(2)
        #         # if i == 0:
        #         #     feature_name_list.append("Packet direction #" + str(j) + " (" + filter_con + ")")
        # # print(i, "Packet direction vector: ", concat_pkt_dir)
        # print("----------------------------------")
        # print(concat_pkt_dir)

        data.extend([2] * max(slice_length - len(data), 0))
        concat_pkt_dir = ''.join(map(str, data))

        feature_list[i].append(int(concat_pkt_dir))


def calc_pkt_rate(packet_list, filter_con):
    global pkt_counter
    global rate_start_time
    global rate_end_time
    global pkt_rate
    global pkt_rate_list
    global slice_length

    pkt_rate = []
    pkt_rate_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        if rate_start_time == 0:
            rate_start_time = packet.time
        try:
            packet_not_added = True
            while packet_not_added:
                if packet.time < (rate_start_time + (len(pkt_rate) + 1)):
                    pkt_counter += 1
                    packet_not_added = False
                else:
                    pkt_rate.append(pkt_counter)
                    pkt_counter = 0
        except IndexError:
            pass
        yield packet, dev_name

    pkt_rate.append(pkt_counter)
    pkt_rate_list.append(pkt_rate)
    pkt_rate = []
    pkt_counter = 0
    rate_start_time = 0
    rate_end_time = 0

    for i, (data) in enumerate(pkt_rate_list):
        concat_pkt_rate = ""
        for j in range(5):
            if j < len(data):
                concat_pkt_rate += str(data[j])
            else:
                concat_pkt_rate += str(0)
        # print(i, "Packet rate vector: ", concat_pkt_rate)
        feature_list[i].append(int(concat_pkt_rate))
        # if i == 0:
        #     feature_name_list.append("Packet rate vector (" + filter_con + ")")


def calc_IP_destinations(packet_list, filter_con):
    global dest_ip_counter_list
    global dest_ip_set
    global dst_ip_counter
    global dest_ip_seq
    global slice_length

    dest_ip_counter_list = []
    dst_ip_counter = 0
    dest_ip_seq = []
    dest_ip_set = {}

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            if packet["IP"].dst not in dest_ip_set:  # Counting the Destination IP counter value
                dest_ip_set[packet["IP"].dst] = 1
                dst_ip_counter = dst_ip_counter + 1
            else:
                dest_ip_set[packet["IP"].dst] += 1
        except IndexError:
            pass
        dest_ip_seq.append(dst_ip_counter)
        yield packet, dev_name

    dest_ip_counter_list.append(dest_ip_seq)
    dst_ip_counter = 0
    dest_ip_set = {}
    dest_ip_seq = []
    # print("dest_ip_counter_list: ", len(dest_ip_counter_list), dest_ip_counter_list)

    for i, (data) in enumerate(dest_ip_counter_list):
        concat_ip_destinations = ""
        for j in range(slice_length):
            if j < len(data):
                concat_ip_destinations += str(data[j])
                # ethernet_len_list[i].append(data[j])
            else:
                concat_ip_destinations += str(data[len(data)-1])
                # ethernet_len_list[i].append(0)
        # print(i, "Number of Ip destinations: ", concat_ip_destinations)
        feature_list[i].append(int(concat_ip_destinations))


def calc_port_class(packet_list, filter_con):
    global src_port_class_list
    global dst_port_class_list
    global src_port_cls
    global dst_port_cls
    global slice_length

    src_port_class_list = []
    dst_port_class_list = []
    src_port_cls = []
    dst_port_cls = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            tcp, udp, tl_pro = fe.get_tcpudp_feature(packet)    # TCP, UDP features
            src_port_cls.append(fe.get_srcpc_feature(packet, tl_pro))                # source port class feature
            dst_port_cls.append(fe.get_dstpc_feature(packet, tl_pro))
        except IndexError:
            src_port_cls.append(0)
            dst_port_cls.append(0)
            # pass
        yield packet, dev_name

    src_port_class_list.append(src_port_cls)
    dst_port_class_list.append(dst_port_cls)
    # print("src_port_class_list: ", len(dst_port_class_list), dst_port_class_list)

    for i, (data) in enumerate(src_port_class_list):
        concat_src_prtclass = ""
        for j in range(slice_length):
            if j < len(data):
                concat_src_prtclass += str(data[j])
                # ethernet_len_list[i].append(data[j])
            else:
                concat_src_prtclass += str(0)
                # ethernet_len_list[i].append(0)
        # print(i, "Source port class vector:", concat_src_prtclass)
        feature_list[i].append(int(concat_src_prtclass))
        # if i == 0:
        #     feature_name_list.append("Source port class (" + filter_con + ")")

    for i, (data) in enumerate(dst_port_class_list):
        concat_dst_prtclass = ""
        for j in range(slice_length):
            if j < len(data):
                concat_dst_prtclass += str(data[j])
                # ethernet_len_list[i].append(data[j])
            else:
                concat_dst_prtclass += str(0)
                # ethernet_len_list[i].append(0)
        # print(i, "Destination port class vector:", concat_dst_prtclass)
        feature_list[i].append(int(concat_dst_prtclass))

        # if i == 0:
        #     feature_name_list.append("Destination port class (" + filter_con + ")")


def calc_dhcp_options(packet_list, filter_con):
    global dhcp_opt_sum
    global dhcp_options_sum_list
    dhcp_opt_sum = []
    dhcp_options_sum_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            x = packet["DHCP options"].options
            for i, (a) in enumerate(x):
                if a[0] == "param_req_list":
                    sum = 0
                    for j in range(len(a[1])):
                        sum = sum + a[1][j]
                    dhcp_opt_sum.append(sum)
        except (IndexError, AttributeError) as e:
            dhcp_opt_sum.append(0)

        yield packet, dev_name

    dhcp_options_sum_list.append(dhcp_opt_sum)
    dhcp_opt_sum = []

    for i, (data) in enumerate(dhcp_options_sum_list):
        if len(data) == 0:
            data.append(0)
        min_dhcp = min(data)  # minimum packet inter-arrival time
        max_dhcp = max(data)  # maximum packet inter-arrival time
        q1_dhcp = np.percentile(data, 25)    # first quartile of inter-arrival time
        median_dhcp = np.percentile(data, 50)    # median of inter-arrival time
        mean_dhcp = np.mean(data)                # mean of inter-arrival time
        q3_dhcp = np.percentile(data, 75)    # third quartile of inter-arrival time
        var_dhcp = np.var(data)              # variance of inter-arrival time

        # print(i, "DHCP option sum features: ", filter_con, min_dhcp, max_dhcp, q1_dhcp, median_dhcp, mean_dhcp, q3_dhcp, var_dhcp)

        feature_list[i].append(round(min_dhcp, 2))
        feature_list[i].append(round(max_dhcp, 2))
        feature_list[i].append(round(q1_dhcp, 2))
        feature_list[i].append(round(median_dhcp, 2))
        feature_list[i].append(round(mean_dhcp, 2))
        feature_list[i].append(round(q3_dhcp, 2))
        feature_list[i].append(round(var_dhcp, 2))


def import_IoT_sentinel_features(packet_list):
    global feature_list

    feature_gen = IoTobject.feature_class_generator(packet_list)
    feat_X, dev_y = IoTobject.dataset(feature_gen)

    for i, (data) in enumerate(feat_X):
        feature_list[i] = feature_list[i] + data

    return 0


def end_generator(packet_list):
    for i, (packet, dev_name) in enumerate(packet_list):
        pass

    # for i, (data) in enumerate(IP_len_list):
    #     print("--------------------------------------------------------")
    #     print(ether_len_list[i])
    #     print(IP_len_list[i])
    #     print([a - b for a, b in zip(ether_len_list[i], IP_len_list[i])])


def load_behavior_features(folder):
    global feature_list
    global device_list
    global extraction_times

    filter = "bidirectional"
    # load packet data based on filter conditions: bidirectional, Src_to_Other, Other_to_Src
    packet_list_bidirec = load_data(folder, filter)

    piped_to_IA = initiate_feature_list(packet_list_bidirec)

    # Calculate the features for packet list
    t1 = time.time()
    piped_to_eth_size = calc_IA_features(piped_to_IA, filter)
    piped_to_ip_size = calc_ethsize_features(piped_to_eth_size, filter)
    piped_to_ip_header_size = calc_IP_payload_size_features(piped_to_ip_size, filter)
    piped_to_pkt_rate = calc_IP_header_size_features(piped_to_ip_header_size, filter)
    piped_to_pkt_direction = calc_pkt_rate(piped_to_pkt_rate, filter)
    piped_to_end_generator = calc_pkt_directions(piped_to_pkt_direction, filter)
    end_generator(piped_to_end_generator)
    t2 = time.time()


    filter = "Src_to_Other"
    # load packet data based on filter conditions: bidirectional, Src_to_Other, Other_to_Src
    packet_list_from_Src = load_data(folder, filter)

    # piped_to_IA = initiate_feature_list(packet_list_from_Src)

    # Calculate the features for packet list
    t3 = time.time()
    piped_to_eth_size = calc_IA_features(packet_list_from_Src, filter)
    piped_to_ip_size = calc_ethsize_features(piped_to_eth_size, filter)
    piped_to_ip_header_size = calc_IP_payload_size_features(piped_to_ip_size, filter)
    piped_to_pkt_rate = calc_IP_header_size_features(piped_to_ip_header_size, filter)
    piped_to_ip_destinations = calc_pkt_rate(piped_to_pkt_rate, filter)
    piped_to_port_class = calc_IP_destinations(piped_to_ip_destinations, filter)
    piped_to_end_generator = calc_port_class(piped_to_port_class, filter)
    # piped_to_end_generator = calc_dhcp_options(piped_to_dhcp_options, filter)
    end_generator(piped_to_end_generator)
    t4 = time.time()
    print("Duration_1:", t2 - t1)
    print("Duration_2:", t4 - t3)
    tot_time = (t4 - t3) + (t2 - t1)
    extraction_times.append(tot_time)

    # filter = "Other_to_Src"
    # # load packet data based on filter conditions: bidirectional, Src_to_Other, Other_to_Src
    # packet_list_to_Src = load_data(folder, filter)
    #
    # # piped_to_IA = initiate_feature_list(packet_list_to_Src)
    #
    # # Calculate the features for packet list
    # piped_to_eth_size = calc_IA_features(packet_list_to_Src, filter)
    # piped_to_ip_size = calc_ethsize_features(piped_to_eth_size, filter)
    # piped_to_ip_header_size = calc_IP_payload_size_features(piped_to_ip_size, filter)
    # piped_to_pkt_count = calc_IP_header_size_features(piped_to_ip_header_size, filter)
    # piped_to_end_generator = calc_num_of_pkts(piped_to_pkt_count, filter)
    # end_generator(piped_to_end_generator)

    return feature_list, device_list



# Location where the training dataset is available
pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel_all\\captures_IoT-Sentinel"
# pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel_all\\special"
# pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel\\Test"


# slice_length_list = np.arange(10, 25, 1)
# file = open("F:\\MSC\\Master Thesis\\Results\\Files from python code\\slice_length_vs_accuracy_09_11.txt", "w")
# file.write("#" + str(datetime.datetime.now()) + "\n")
# file.write("#Slice_length\t Average_accuracy\t Accuracy_list\n")
# file.close()

extraction_times = []
min_capture_durations = []

for s in range(1):
    slice_length = 21
    print("slice_length = ", slice_length)

    try:
        feature_name_list = pickle.load(open("Ven_behav_feature_name_list.pickle", "rb"))
        dataset_X = pickle.load(open("Dev_behav_features.pickle", "rb"))
        dataset_y = pickle.load(open("Dev_behav_devices.pickle", "rb"))
        print("Pickling successful behavioral features ......")
    except (OSError, IOError) as e:
        print("No pickle datasets are available....")
        dataset_X, dataset_y = load_behavior_features(pcap_folder)
        pickle.dump(dataset_X, open("Dev_behav_features_noIP.pickle", "wb"))
        pickle.dump(dataset_y, open("Dev_behav_devices_noIP.pickle", "wb"))
        feature_list = []
        device_list = []

    Number_of_features = len(dataset_X[0])
    print("Number of features: ", Number_of_features)
    print("Number of captures: ", len(dataset_X))

    dataset_X = np.array(dataset_X, dtype=object)
    dataset_y = np.array(dataset_y)

    device_labels = ['Aria', 'HomeMaticPlug', 'Withings', 'MAXGateway', 'HueBridge', 'HueSwitch', 'EdnetGateway',
                         'EdnetCam', 'EdimaxCam', 'Lightify', 'WeMoInsightSwitch', 'WeMoLink', 'WeMoSwitch',
                         'D-LinkHomeHub', 'D-LinkDoorSensor', 'D-LinkDayCam', 'D-LinkCam', 'D-LinkSwitch',
                         'D-LinkWaterSensor', 'D-LinkSiren', 'D-LinkSensor', 'TP-LinkPlugHS110', 'TP-LinkPlugHS100',
                         'EdimaxPlug1101W', 'EdimaxPlug2101W', 'SmarterCoffee', 'iKettle2']     # IoT Sentinel sequence


    no_of_feature_list = []
    f1_score_list = {}
    precision_list = {}
    recall_list = {}
    pred_times = []

    # for num_features in range(Number_of_features, 0, -1):
    for num_features in range(1):
        # print("num_features", num_features)

        # dataset_X = SelectKBest(chi2, k=num_features).fit_transform(dataset_X, dataset_y)

        device_set = set(dataset_y)     # list of unique device labels
        print("Number of devices: ", len(device_set))
        print("Device set: ", device_set)

        # device_fp_counter = {}
        # for device in device_set:  # get the number of fingerprints for each device under predicted vendor (not all vendors)
        #     count = 0
        #     for record in dataset_y:
        #         if record == device:
        #             count += 1
        #         device_fp_counter[device] = count
        #
        # print("device_fp_counter: ", device_fp_counter)
        # key_min = min(device_fp_counter,
        #               key=device_fp_counter.get)  # find the device with minimum device fingerprints for the predicted vendor
        # min_fp = device_fp_counter[
        #     key_min]  # number of minimum device fingerprints to be extracted from each device for the predicted vendor

        # data_DX = []
        # data_DY = []
        #
        # for device in device_set:
        #     temp_X = dataset_X[dataset_y == device]     # filter all fps for a particular device
        #     # print("temp_X: ", len(temp_X))
        #     out_list = sample(list(temp_X), min_fp)     # select a data sample from temp_X for a device
        #     for fp in out_list:
        #         data_DX.append(fp)                      # append device specific fingerprints to the training data set
        #         data_DY.append(device)                  # append device name to the respective training data set
        #
        # data_DX = np.array(data_DX)         # convert training data lists to numpy arrays
        # data_DY = np.array(data_DY)

        # data_DX = dataset_X
        # data_DY = dataset_y
        #
        # print("len(data_DX): ", len(data_DX))
        # print("len(data_Dy): ", len(data_DY))

        num_of_iter = 10
        k_folds = 10
        total_dev_pred_accuracy = {}    # records pred_vector accuracy
        f_importance = {}               # records the feature importance in classification
        all_tested = []
        all_predicted = []
        test_dev_counter = {}
        iterationwise_device_pred_accuracy = {}
        iterationwise_precision = {}
        iterationwise_recall = {}
        iterationwise_f1score = {}
        iterationwise_fimportance = {}
        f1_score_array = []
        precision_array = []
        recall_array = []
        score_list = []

        for iter in range(num_of_iter):
            iteration = 0
            skf = StratifiedKFold(n_splits=k_folds, shuffle=True)

            for train_index, test_index in skf.split(dataset_X, dataset_y):
                print(iter, "K_fold inner_iter: ", iteration)
                iteration += 1
                X_train, X_test = dataset_X[train_index], dataset_X[test_index]
                y_train, y_test = dataset_y[train_index], dataset_y[test_index]

                scaling = MinMaxScaler(feature_range=(-1, 1)).fit(X_train)
                X_train = scaling.transform(X_train)
                X_test = scaling.transform(X_test)

                X_unknown = X_test
                y_unknown = y_test

                test_set = set(y_unknown)  # list of unique device labels
                print("Number of test devices: ", len(test_set))
                print("Test Device set: ", test_set)

                Curr_test_dev_counter = collections.Counter(y_test)
                print("Current test device counter", dict(Curr_test_dev_counter))
                test_dev_counter = {k: test_dev_counter.get(k, 0) + Curr_test_dev_counter.get(k, 0)
                                    for k in set(test_dev_counter) | set(Curr_test_dev_counter)}

                clf = RandomForestClassifier(n_estimators=100)
                # clf = AdaBoostClassifier(DecisionTreeClassifier(), n_estimators=50, learning_rate=1)
                # clf = AdaBoostClassifier(RandomForestClassifier(), n_estimators=50, learning_rate=1)
                # clf = KNeighborsClassifier(3)
                # clf = SVC(gamma=2, C=1)
                # clf = SVC(kernel='linear', C=1)
                # clf = DecisionTreeClassifier()
                # clf = MLPClassifier(alpha=1)
                # clf = GaussianNB()
                # clf = QuadraticDiscriminantAnalysis()

                clf.fit(X_train, y_train)
                # score_list.append(clf.score(X_unknown, y_unknown))

                # importances = clf.feature_importances_  # calculates the feature importance
                # std = np.std([tree.feature_importances_ for tree in clf.estimators_], axis=0)
                # indices = np.argsort(importances)[::-1]
                # for f in range(X_train.shape[1]):
                #     if indices[f] % Number_of_features not in f_importance:
                #         f_importance[indices[f] % Number_of_features] = importances[indices[f]]
                #         iterationwise_fimportance[indices[f] % Number_of_features] = [importances[indices[f]]]
                #     else:
                #         f_importance[indices[f] % Number_of_features] += importances[indices[f]]
                #         iterationwise_fimportance[indices[f] % Number_of_features].append(importances[indices[f]])

                t = time.time()
                y_predict = clf.predict(X_unknown)
                pred_times.append(time.time() - t)

                for i in range(len(y_unknown)):
                    all_tested.append(y_unknown[i])
                    all_predicted.append(y_predict[i])
                    if y_unknown[i] == y_predict[i]:
                        if y_unknown[i] not in total_dev_pred_accuracy:
                            total_dev_pred_accuracy[y_unknown[i]] = 1
                        else:
                            total_dev_pred_accuracy[y_unknown[i]] += 1

                for key, value in Curr_test_dev_counter.items():
                    if key not in total_dev_pred_accuracy:
                        total_dev_pred_accuracy[key] = 0
                print("total_dev_pred_accuracy:", total_dev_pred_accuracy)

                for key, value in total_dev_pred_accuracy.items():
                    if key not in iterationwise_device_pred_accuracy:
                        iterationwise_device_pred_accuracy[key] = [value / Curr_test_dev_counter[key]]
                    else:
                        i = sum(iterationwise_device_pred_accuracy[key])
                        iterationwise_device_pred_accuracy[key].append(value / Curr_test_dev_counter[key] - i)
                print("Iterationwise_device_pred_accuracy:", iterationwise_device_pred_accuracy)

                current_test = y_unknown
                current_predcited = y_predict
                precision, recall, f1_sco, supp = precision_recall_fscore_support(current_test, current_predcited,
                                                                                    labels=device_labels)
                for i, (device) in enumerate(device_labels):
                    if device not in iterationwise_precision:
                        iterationwise_precision[device] = [precision[i]]
                        iterationwise_recall[device] = [recall[i]]
                        iterationwise_f1score[device] = [f1_sco[i]]
                    else:
                        iterationwise_precision[device].append(precision[i])
                        iterationwise_recall[device].append(recall[i])
                        iterationwise_f1score[device].append(f1_sco[i])

                f1_score_array.append(np.mean(f1_sco))       # stores F1 score values for a certain number of features
                precision_array.append(np.mean(precision))   # stores precision values for a certain number of features
                recall_array.append(np.mean(recall))         # stores recall values for a certain number of features

                # print("Iterationwise:")
                # print("Precision:  ", iterationwise_precision)
                # print("Recall:     ", iterationwise_recall)
                # print("F1-score:   ", iterationwise_f1score)
                # print("F_importance:", iterationwise_fimportance)

            # --------------------------- End of k-fold cross-validation loop --------------------------------

        # ---------------------------- End of multiple iterating loop ----------------------------------------
        if not num_features in f1_score_list:
            no_of_feature_list.append(num_features)
            f1_score_list[num_features] = f1_score_array
            precision_list[num_features] = precision_array
            recall_list[num_features] = recall_array

        # print("Number of feature:", num_features)
        # print("f1_score_list: ", f1_score_list)
        # print("precision_list:", precision_list)
        # print("recall_list:   ", recall_list)

        # print("All_test_dev_counter: ", total_test_dev_counter)
        # print("Final Iterationwise_prediction:", iterationwise_device_pred_accuracy)
        # print("Final Iterationwise_precision: ", iterationwise_precision)
        # print("Final Iterationwise_recall:    ", iterationwise_recall)
        # print("Final Iterationwise_F1-score:  ", iterationwise_f1score)
        # print("Final Iterationwise_F_importance:", iterationwise_fimportance)

        for d in device_set:       # check if there are devices which were not predicted correctly at least once
            if d not in total_dev_pred_accuracy:
                total_dev_pred_accuracy[d] = 0

        for key, value in total_dev_pred_accuracy.items():
            total_dev_pred_accuracy[key] = value / (test_dev_counter[key])  # produce the accuracy as a fraction

        for key, value in f_importance.items():
            f_importance[key] = value/(num_of_iter)  # produce the accuracy as a fraction

    # -------------------------- End of loop for changing number of features -----------------------------------------

    # print("Number of feature list:", num_features)
    # print("Final f1_score_list (with no.of.features):", f1_score_list)
    # print("Final precision_list(with no.of.features):", precision_list)
    # print("Final recall_list (with no.of.features)  :", recall_list)

    # file = open("F:\\MSC\\Master Thesis\\Results\\Files from python code\\F1_prec_rec_vs_NumOfFeatures.txt", "w")
    # file.write("# F1 score vs Number of features\n")
    # file.write(str(f1_score_list) + "\n")
    # file.write("# Precision vs Number of features\n")
    # file.write(str(precision_list) + "\n")
    # file.write("# Recall vs Number of features\n")
    # file.write(str(recall_list) + "\n")
    # file.close()


    # print(f1_score_list)
    # plt.plot(no_of_feature_list, f1_score_list)
    # plt.xlabel('Number of features')
    # plt.ylabel('F1 score')
    # plt.show()

    # file = open("F:\\MSC\\Master Thesis\\Results\\Files from python code\\F1_vs_NumOfFeatures.txt", "w")
    # file.write("# F1 score vs Number of features\n")
    # file.write("Number_of_features\t F1_score\n")
    # for i in range(len(f1_score_list)):
    #     file.write(str(no_of_feature_list[i]) + "\t" + str(f1_score_list[i]) + "\n")
    # file.close()

    # write the feature importance values onto a file
    # file = open("F:\\MSC\\Master Thesis\\Results\\Files from python code\\seq_based_feature_importance.txt", "w")
    # file.write("# Results of Device pred_vector feature importance\n")
    # file.write("Index\t Feature_name\t importance\n")
    # index = 0
    # for key, value in f_importance.items():
    #     file.write(str(key) + "\t" + str(feature_name_list[index]) + "\t"
    #                + str(value) + "\n")
    #     index += 1
    # file.close()

    # print(len(all_tested), len(all_predicted))
    # print("All_tested:", all_tested)
    # print("All_predicted:", all_predicted)
    # print("Total_dev_pred_accuracy: ", total_dev_pred_accuracy)

    # # plot_results(total_dev_pred_accuracy, "Single classifier RF - Flowbased analysis", 1, True, "Accuracy")
    # plot_pred_accuracy(iterationwise_device_pred_accuracy, "Single classifier RF - Sequence Based", 1, True, "Accuracy")
    # plot_pred_accuracy(iterationwise_precision, "Precision - Sequence Based", 1, True, "Precision")
    # plot_pred_accuracy(iterationwise_recall, "Recall - Sequence Based", 1, True, "Recall")
    plot_pred_accuracy(iterationwise_f1score, "F1 score - Sequence Based", 1, True, "F$_1$-score")
    # plot_pred_accuracy(iterationwise_fimportance, "Feature importance - Sequence Based", 1, True, "Importance value")
    # plot_results(f_importance, "Feature importance RF - Flowbased analysis", 1, True, "Importance")
    # print(classification_report(all_tested, all_predicted))
    # print(confusion_matrix(all_tested, all_predicted))
    # print(f_importance)
    # print(feature_name_list)

    # file = open("F:\\MSC\\Master Thesis\\Results\\Files from python code\\Device_prediction_sequence_Based_All_data.txt", "w")
    # file.write(str(datetime.datetime.now()) + "\n")
    # file.write(str(len(all_tested)) + "," + str(len(all_predicted)) + "\n")
    # file.write("#Total_dev_pred_accuracy\n")
    # file.write(str(total_dev_pred_accuracy) + "\n")
    # file.write("#Final_iterationwise_device_prediction\n")
    # file.write(str(iterationwise_device_pred_accuracy) + "\n")
    # file.write("#All_tested\n")
    # file.write(str(all_tested) + "\n")
    # file.write("#All_predicted\n")
    # file.write(str(all_predicted) + "\n")
    # file.write("#Final_iterationwise_precision\n")
    # file.write(str(iterationwise_precision) + "\n")
    # file.write("#Final_iterationwise_recall\n")
    # file.write(str(iterationwise_recall) + "\n")
    # file.write("#Final_iterationwise_F1-score\n")
    # file.write(str(iterationwise_f1score) + "\n")
    # file.write("#Classification_report\n")
    # file.write(str(classification_report(all_tested, all_predicted)) + "\n")
    # file.write("#Confusion_matrix\n")
    # file.write(str(confusion_matrix(all_tested, all_predicted)) + "\n")
    # file.close()

    # file = open("F:\\MSC\\Master Thesis\\Results\\Files from python code\\Device_prediction_classification_report.txt", "w")
    # file.write("# Classification Report \n")
    # file.write(str(classification_report(all_tested, all_predicted)))
    # file.close()

    # file = open("F:\\MSC\\Master Thesis\\Results\\Files from python code\\slice_length_vs_accuracy_09_11.txt", "a")
    # file.write(str(slice_length) + "\t" + str(sum((total_dev_pred_accuracy.values()))/len(total_dev_pred_accuracy))
    #            + "\t" + str(total_dev_pred_accuracy) + "\n")
    # file.close()

# print(iterationwise_device_pred_accuracy)
# print("################################################################################################")
# print("################################################################################################")
# print("################################################################################################")
# print("################################################################################################")

print("iterationwise_device_pred_accuracy", iterationwise_device_pred_accuracy)
seq_based_mean_accuracy = []
for i, (device) in enumerate(device_labels):
    for key, value in iterationwise_device_pred_accuracy.items():
        if key == device:
            seq_based_mean_accuracy.append(np.mean(value))
print(seq_based_mean_accuracy)
print("mean accuracy", np.mean(seq_based_mean_accuracy))

print("iterationwise_f1score", iterationwise_f1score)
seq_based_f1_accuracy = []
for i, (device) in enumerate(device_labels):
    for key, value in iterationwise_f1score.items():
        if key == device:
            seq_based_f1_accuracy.append(np.mean(value))
print(seq_based_f1_accuracy)
print("Avg f1-score", np.mean(seq_based_f1_accuracy))

iterationwise_f1_list = []
for i in range(100):
    f1_list = []
    for key, value in iterationwise_f1score.items():
        f1_list.append(value[i])
    iterationwise_f1_list.append(np.mean(f1_list))

print(len(iterationwise_f1_list), iterationwise_f1_list)
print("Avg f1-score", np.mean(iterationwise_f1_list))
print("Min f1-score", np.min(iterationwise_f1_list))
print("Max f1-score", np.max(iterationwise_f1_list))
print("Var f1-score", np.var(iterationwise_f1_list))

# cnf_matrix = confusion_matrix(all_tested, all_predicted, device_labels)
# plot_confusion_matrix(cnf_matrix, device_labels, False, 'Confusion matrix, without normalization')

# print("Prediction times:", pred_times)
# print("Mean prediction time = ", np.mean(pred_times))
# print("Mean prediction time per device = ", np.mean(pred_times)/54)
# print("################################################################################################")
# # print("Num_pkts:", slice_length, "Prediction_accuracy:", sum((total_dev_pred_accuracy.values()))/len(total_dev_pred_accuracy))
# # print("score_list:", score_list)
# print("Mean score:", np.mean(score_list))

# print("extraction_times: ", extraction_times)
# print("min_capture_durations: ", min_capture_durations)