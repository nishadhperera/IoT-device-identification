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
from scipy.spatial import distance
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report

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
prev_EucD_packet = ""
Euc_distances = []
Euc_distance_list = []
source_mac_add = ""
new_device = False

feature_list = []       # stores the features
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
    global prev_EucD_packet
    global Euc_distances
    global Euc_distance_list

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
            if dst_ip_counter > 0:
                dest_ip_counter_list.append(dest_ip_seq)
                dst_ip_counter = 0
                dest_ip_set = {}
                dest_ip_seq = []
            if src_port_cls:
                src_port_class_list.append(src_port_cls)
                dst_port_class_list.append(dst_port_cls)
                src_port_cls = []
                dst_port_cls = []
            if Euc_distances:
                Euc_distance_list.append(Euc_distances)
                Euc_distances = []
                prev_EucD_packet = ""
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
        IoTobject.capture_len = src_mac_address_list[source_mac_add]
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
        iqr_IAT = q3_IAT - q1_IAT           # inter quartile range of inter-arrival time

        print(i, "IA features: ", filter_con, min_IAT, max_IAT, q1_IAT, median_IAT, mean_IAT, q3_IAT, var_IAT, iqr_IAT)

        feature_list[i].append(min_IAT)
        feature_list[i].append(max_IAT)
        feature_list[i].append(q1_IAT)
        feature_list[i].append(median_IAT)
        feature_list[i].append(mean_IAT)
        feature_list[i].append(q3_IAT)
        feature_list[i].append(var_IAT)
        feature_list[i].append(iqr_IAT)

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
        iqr_ip_len = q3_ip_len - q1_ip_len  # IQR of IP packet size

        print(i, "IP packet size features: ", min_ip_len, max_ip_len, q1_ip_len, median_ip_len, mean_ip_len, q3_ip_len, var_ip_len, iqr_ip_len)

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
        yield packet, dev_name

    pkt_direction_list.append(pkt_direction)

    for i, (data) in enumerate(pkt_direction_list):
        for j in range(12):
            if j < len(data):
                feature_list[i].append(data[j])
            else:
                feature_list[i].append(2)


def calc_IP_destinations(packet_list, filter_con):
    global dest_ip_counter_list
    global dest_ip_set
    global dst_ip_counter
    global dest_ip_seq

    dest_ip_counter_list = []
    dst_ip_counter = 0
    dest_ip_seq = []

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
    print("dest_ip_counter_list: ", len(dest_ip_counter_list), dest_ip_counter_list)

    for i, (data) in enumerate(dest_ip_counter_list):
        for j in range(12):
            if j < len(data):
                feature_list[i].append(data[j])
            else:
                feature_list[i].append(0)


def calc_port_class(packet_list, filter_con):
    global src_port_class_list
    global dst_port_class_list
    global src_port_cls
    global dst_port_cls

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
            pass
        yield packet, dev_name

    src_port_class_list.append(src_port_cls)
    dst_port_class_list.append(dst_port_cls)
    print("src_port_class_list: ", len(dst_port_class_list), dst_port_class_list)

    for i, (data) in enumerate(src_port_class_list):
        for j in range(12):
            if j < len(data):
                feature_list[i].append(data[j])
            else:
                feature_list[i].append(0)

    for i, (data) in enumerate(dst_port_class_list):
        for j in range(12):
            if j < len(data):
                feature_list[i].append(data[j])
            else:
                feature_list[i].append(0)


def calc_euclidean_distance(packet_list, filter_con):
    global prev_EucD_packet
    global Euc_distances
    global Euc_distance_list
    Euc_distance_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        if prev_EucD_packet == "":
            pass
        else:
            Euc_distances.append(distance.euclidean(np.array(packet), np.array(prev_EucD_packet)))
        prev_EucD_packet = packet
        yield packet, dev_name

    Euc_distance_list.append(Euc_distances)
    Euc_distances = []
    prev_packet = ""
    print("len(Euc_distance_list)", len(Euc_distance_list))

    for i, (data) in enumerate(Euc_distance_list):

        min_euc_D = min(data)  # minimum packet inter-arrival time
        max_euc_D = max(data)  # maximum packet inter-arrival time
        q1_euc_D = np.percentile(data, 25)    # first quartile of inter-arrival time
        median_euc_D = np.percentile(data, 50)    # median of inter-arrival time
        mean_euc_D = np.mean(data)                # mean of inter-arrival time
        q3_euc_D = np.percentile(data, 75)    # third quartile of inter-arrival time
        var_euc_D = np.var(data)              # variance of inter-arrival time

        print(data)
        print(i, "Euclidean distance features: ", filter_con, min_euc_D, max_euc_D, q1_euc_D, median_euc_D, mean_euc_D, q3_euc_D, var_euc_D)

        feature_list[i].append(round(min_euc_D, 2))
        feature_list[i].append(round(max_euc_D, 2))
        feature_list[i].append(round(q1_euc_D, 2))
        feature_list[i].append(round(median_euc_D, 2))
        feature_list[i].append(round(mean_euc_D, 2))
        feature_list[i].append(round(q3_euc_D, 2))
        feature_list[i].append(round(var_euc_D, 2))


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
    piped_to_end_generator = calc_pkt_directions(piped_to_pkt_direction, filter)
    # piped_to_port_class = calc_IP_destinations(piped_to_ip_destinations, filter)
    # piped_to_end_generator = calc_port_class(piped_to_port_class, filter)
    end_generator(piped_to_end_generator)


    filter = "Src_to_Other"
    # load packet data based on filter conditions: bidirectional, Src_to_Other, Other_to_Src
    packet_list_from_Src = load_data(folder, filter)

    # piped_to_IA = initiate_feature_list(packet_list_from_Src)

    # Calculate the features for packet list
    piped_to_eth_size = calc_IA_features(packet_list_from_Src, filter)
    piped_to_ip_size = calc_ethsize_features(piped_to_eth_size, filter)
    piped_to_ip_header_size = calc_IP_size_features(piped_to_ip_size, filter)
    piped_to_pkt_count = calc_IP_header_size_features(piped_to_ip_header_size, filter)
    piped_to_ip_destinations = calc_num_of_pkts(piped_to_pkt_count, filter)
    piped_to_port_class = calc_IP_destinations(piped_to_ip_destinations, filter)
    piped_to_end_generator = calc_port_class(piped_to_port_class, filter)
    # piped_to_end_generator = calc_euclidean_distance(piped_to_IA, filter)
    # import_IoT_sentinel_features(piped_to_IoT_sentinel)
    end_generator(piped_to_end_generator)


    # filter = "Other_to_Src"
    # # load packet data based on filter conditions: bidirectional, Src_to_Other, Other_to_Src
    # packet_list_to_Src = load_data(folder, filter)
    #
    # # piped_to_IA = initiate_feature_list(packet_list_to_Src)
    #
    # # Calculate the features for packet list
    # piped_to_eth_size = calc_IA_features(packet_list_to_Src, filter)
    # piped_to_ip_size = calc_ethsize_features(piped_to_eth_size, filter)
    # piped_to_ip_header_size = calc_IP_size_features(piped_to_ip_size, filter)
    # piped_to_pkt_count = calc_IP_header_size_features(piped_to_ip_header_size, filter)
    # piped_to_end_generator = calc_num_of_pkts(piped_to_pkt_count, filter)
    # end_generator(piped_to_end_generator)

    return feature_list, device_list


# Location where the training dataset is available
pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel_all\\captures_IoT-Sentinel"
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


Number_of_features = len(dataset_X[0])
print("Number of features: ", Number_of_features)
print("Number of captures: ", len(dataset_X))

# test_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel\\not trained data behavioral"
# X_unknown, y_unknown = load_behavior_features(test_folder)
# X_unknown = np.array(X_unknown)
# y_unknown = np.array(y_unknown)
# print("len(X_unknown), len(y_unknown): ", len(X_unknown), len(y_unknown))

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
print("len(data_Dy): ", len(data_DY))
print(data_DY)

for i, (data) in enumerate(data_DX):
    print(len(data), data_DY[i])



# X_train, X_test, y_train, y_test = train_test_split(data_DX, data_DY, test_size=0.2, random_state=0)
# X_unknown = X_test
# y_unknown = y_test
# print("Splitted y-Unknown: ", y_unknown)
#
# test_set = set(y_unknown)     # list of unique device labels
# print("Number of test devices: ", len(test_set))
# print("Test Device set: ", test_set)
#
#
# for device in test_set:  # get the number of fingerprints for each device under predicted vendor (not all vendors)
#     count = 0
#     for record in y_unknown:
#         if record == device:
#             count += 1
#             test_dev_counter[device] = count

num_of_iter = 1
dev_pred_accuracy = {}      # records prediction accuracy
f_importance = {}            # records the feature importance in classification
all_tested = []
all_predicted = []
test_dev_counter = {}


for iter in range(num_of_iter):
    print("Prediction iteration ", iter)

    X_train, X_test, y_train, y_test = train_test_split(data_DX, data_DY, test_size=0.25, random_state=21)
    X_unknown = X_test
    y_unknown = y_test
    print("Splitted y-Unknown: ", y_unknown)

    test_set = set(y_unknown)  # list of unique device labels
    print("Number of test devices: ", len(test_set))
    print("Test Device set: ", test_set)

    for device in test_set:  # get the number of fingerprints for each device under predicted vendor (not all vendors)
        if iter == 0:
            count = 0
        else:
            count = test_dev_counter[device]
        for record in y_unknown:
            if record == device:
                count += 1
                test_dev_counter[device] = count

    clf = RandomForestClassifier(n_estimators=50)
    clf.fit(X_train, y_train)

    importances = clf.feature_importances_  # calculates the feature importance
    std = np.std([tree.feature_importances_ for tree in clf.estimators_], axis=0)
    indices = np.argsort(importances)[::-1]
    for f in range(X_train.shape[1]):
        if indices[f] % Number_of_features not in f_importance:
            f_importance[indices[f] % Number_of_features] = importances[indices[f]]
        else:
            f_importance[indices[f] % Number_of_features] += importances[indices[f]]

    y_predict = clf.predict(X_unknown)

    for i in range(len(y_unknown)):
        all_tested.append(y_unknown[i])
        all_predicted.append(y_predict[i])
        if y_unknown[i] == y_predict[i]:
            if y_unknown[i] not in dev_pred_accuracy:
                dev_pred_accuracy[y_unknown[i]] = 1
            else:
                dev_pred_accuracy[y_unknown[i]] += 1

print("test_dev_counter: ", test_dev_counter)

for d in device_set:       # check if there are devices which were not predicted correctly at least once
    if d not in dev_pred_accuracy:
        dev_pred_accuracy[d] = 0

for key, value in dev_pred_accuracy.items():
    dev_pred_accuracy[key] = value/(test_dev_counter[key])  # produce the accuracy as a fraction

for key, value in f_importance.items():
    f_importance[key] = value/(num_of_iter)  # produce the accuracy as a fraction

print(len(all_tested))
print(len(all_predicted))
print("dev_pred_accuracy: ", dev_pred_accuracy)

plot_results(dev_pred_accuracy, "Single classifier RF - Flowbased analysis", 1, True, "Accuracy")
plot_results(f_importance, "Feature importance RF - Flowbased analysis", 1, True, "Importance")
print(classification_report(all_tested, all_predicted))
print(confusion_matrix(all_tested, all_predicted))

print(f_importance)


