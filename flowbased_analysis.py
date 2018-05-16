# This program is a novel way of identifying IoT devices using sequential features
# Source file is a .pcap file and scapy has been used to manipulate packets
# Author: Nishadh Aluthge

import fnmatch
import numpy as np
import bottleneck
import operator
from scapy.all import *
from scipy.fftpack import fft
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import MinMaxScaler

import features_scapy as fe     # class containing methods to extract features from  packet

IA_times = []               # list to keep packet inter-arrival time related features for a packet
IA_times_list = []          # list to keep packet inter-arrival time related features for all packets
ether_len = []              # list to keep packet length related features
ether_len_list = []
IP_len = []                 # list to keep packet IP length related features
IP_len_list = []
IP_header_len = []          # list to keep packet IP header length related features
IP_header_len_list = []
pkt_count_list = []         # list to keep packet count related features
pkt_direction = []          # list to keep packet direction related features
pkt_direction_list = []
dest_ip_set = {}    # stores the destination IP set, a global variable
dest_ip_seq = []
dest_ip_counter_list = []   # list to keep packet destination IP counter related features
src_port_class_list = []    # list to keep packet source port related features
dst_port_class_list = []    # list to keep packet destination port related features
src_port_cls = []
dst_port_cls = []
dhcp_opt_sum = []           # list to keep packet DHCP options related features
dhcp_options_sum_list = []
pkt_rate = []               # list to keep packet rate related features
pkt_rate_list = []
rate_start_time = 0
dst_ip_counter = 0          # keeps destination counter value, a global variable
slice_length = 0
pkt_counter = 0
new_device = False
source_mac_add = ""         # stores source mac address of a device
prev_packet = ""

feature_list = []       # stores the features
feature_name_list = []  # stores the feature names
device_list = []        # stores the device names


def pcap_class_generator(pcap_folder):
    """ Generator function to generate a list of .pcap files """
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
            print(os.path.join(path, name), os.path.basename(os.path.normpath(path)))   # current file name
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
                pkt_rate.append(pkt_counter)
                pkt_rate_list.append(pkt_rate)
                pkt_rate = []
                pkt_counter = 0
                rate_start_time = 0
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
                dhcp_options_sum_list.append(dhcp_opt_sum)
                dhcp_opt_sum = []
            yield os.path.join(path, name), os.path.basename(os.path.normpath(path))


def packet_filter_generator(pcap_class_gen, filter_con):
    """ Generator function to filter packets based on mac-address """
    global source_mac_add

    for pcapfile, device_name in pcap_class_gen:
        capture = rdpcap(pcapfile)      # Read the trace file using scapy rdpcap module
        mac_address_list = {}
        src_mac_address_list = {}

        mac_addresses = {
            'Aria': ['20:f8:5e:ca:91:52'], 'D-LinkCam': ['b0:c5:54:25:5b:0e'], 'D-LinkDayCam': ['b0:c5:54:1c:71:85'],
            'D-LinkDoorSensor': ['1c:5f:2b:aa:fd:4e'], 'D-LinkHomeHub': ['1c:5f:2b:aa:fd:4e'],
            'D-LinkSensor': ['90:8d:78:a8:e1:43'], 'D-LinkSiren': ['90:8d:78:dd:0d:60'],
            'D-LinkSwitch': ['90:8d:78:a9:3d:6f'], 'D-LinkWaterSensor': ['6c:72:20:c5:17:5a'],
            'EdimaxCam': ['74:da:38:80:79:fc', '74:da:38:80:7a:08'], 'EdimaxPlug1101W': ['74:da:38:4a:76:49'],
            'EdimaxPlug2101W': ['74:da:38:23:22:7b'], 'EdnetCam': ['3c:49:37:03:17:f0', '3c:49:37:03:17:db'],
            'EdnetGateway': ['ac:cf:23:62:3c:6e'], 'HomeMaticPlug': ['00:1a:22:05:c4:2e'],
            'HueBridge': ['00:17:88:24:76:ff'], 'HueSwitch': ['00:17:88:24:76:ff'], 'iKettle2': ['5c:cf:7f:06:d9:02'],
            'Lightify': ['84:18:26:7b:5f:6b'], 'MAXGateway': ['00:1a:22:03:cb:be'],'SmarterCoffee': ['5c:cf:7f:07:ae:fb'],
            'TP-LinkPlugHS100': ['50:c7:bf:00:fc:a3'], 'TP-LinkPlugHS110': ['50:c7:bf:00:c7:03'],
            'WeMoInsightSwitch': ['94:10:3e:41:c2:05'], 'WeMoLink': ['94:10:3e:cd:37:65'],
            'WeMoSwitch': ['94:10:3e:35:01:c1'], 'Withings': ['00:24:e4:24:80:2a']
            }

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
        real_mac = mac_addresses[device_name]
        for k, v in mac_address_list.items():
            if v == highest and k in real_mac:
                if k in src_mac_address_list:
                    source_mac_add = k

        count_pkts = 0
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
    """ Loading the filtered packets """
    file_list = pcap_class_generator(folder)
    packet_list = packet_filter_generator(file_list, filter_con)
    return packet_list


def plot_list(list, title, x_label, y_label):
    """ Plot a graph with x vs y """
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


def plot_confusion_matrix(cm, classes, normalize, title='Confusion matrix', cmap=plt.cm.Blues):
    """ Function prints and plots the confusion matrix. Normalization can be applied by setting `normalize=True`."""
    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        print("Normalized confusion matrix")
    else:
        print('Confusion matrix, without normalization')

    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45, ha='left')
    plt.yticks(tick_marks, classes)
    plt.title(title, y=-0.08)
    plt.colorbar()
    plt.tick_params('x', labelbottom='off', labeltop='on')

    fmt = '.2f' if normalize else 'd'
    thresh = cm.max() / 2.
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, format(cm[i, j], fmt),
                 horizontalalignment="center",
                 color="white" if cm[i, j] > thresh else "black")

    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.show()


def plot_pred_accuracy(pred_accuracy, title, item_index, reverse, y_lable):
    """ Function plots the prediction accuracy for each device type """
    score = 1.96        # z-score value for confidence interval
    mean_accuracy = {}
    stdDev_accuracy = {}
    sample_size = {}
    skipped_devices_list = []

    for key, value in pred_accuracy.items():
        if not key in skipped_devices_list:
            mean_accuracy[key] = np.round(np.mean(value), 2)
            stdDev_accuracy[key] = np.std(value)
            sample_size[key] = len(value)

    dataset = sorted(mean_accuracy.items(), key=operator.itemgetter(item_index),
                     reverse=reverse)  # sort the dictionary with values

    device_list = ['HueBridge', 'Withings', 'WeMoSwitch', 'HomeMaticPlug', 'Aria', 'EdimaxCam', 'WeMoLink', 'D-LinkCam',
                   'D-LinkDayCam', 'D-LinkHomeHub', 'EdnetGateway', 'EdnetCam', 'HueSwitch', 'WeMoInsightSwitch',
                   'MAXGateway', 'Lightify', 'D-LinkDoorSensor', 'D-LinkSwitch', 'TP-LinkPlugHS100', 'TP-LinkPlugHS110',
                   'EdimaxPlug2101W', 'iKettle2', 'D-LinkSensor', 'SmarterCoffee', 'EdimaxPlug1101W', 'D-LinkSiren',
                   'D-LinkWaterSensor']

    std_dev = []
    accuracy = []
    x_pos = np.arange(len(device_list))
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

    plt.rcParams.update({'font.size': 26})
    plt.rc('axes', labelsize="32", labelweight='bold')
    plt.rcParams["figure.figsize"] = [16, 8]
    plt.bar(x_pos, accuracy, align='center', color='#0485d1', edgecolor='k', linewidth=0.1)
    plt.errorbar(x_pos, accuracy, yerr=[yerr_lower, yerr_upper], fmt='none', ecolor='k', capsize=3)
    plt.xticks(x_pos, device_list, rotation=315, ha='left')
    plt.ylabel(y_lable)
    plt.grid(linestyle='dotted')

    plt.savefig("figure_clf_RandomForest.pdf", bbox_inches='tight')
    plt.show()


def initiate_feature_list(packet_list):
    """ This function initiates the data structure to store features """
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
    """ function to calculate inter-arrival times related features """
    global prev_packet
    global IA_times
    global IA_times_list
    global device_list
    global slice_length

    IA_times_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        if prev_packet == "":
            print("No previous packet to calculate inter-arrival time")
        else:
            time_gap = packet.time - prev_packet.time
            IA_times.append(abs(time_gap))
        prev_packet = packet
        yield packet, dev_name

    IA_times_list.append(IA_times)
    IA_times = []
    prev_packet = ""

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

        for fft_val in sorted_fft:
            feature_list[i].append(fft_val) # append fft values to feature list


def calc_ethsize_features(packet_list, filter_con):
    """ function to calculate ethernet packet size related features """
    global ether_len
    global ether_len_list
    global slice_length
    ether_len_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            ether_len.append(len(packet))
        except IndexError as e:
            print("Error message: ", str(e))
        yield packet, dev_name

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

        feature_list[i].append(min_ethlen)
        feature_list[i].append(max_ethlen)
        feature_list[i].append(q1_ethlen)
        feature_list[i].append(median_ethlen)
        feature_list[i].append(mean_ethlen)
        feature_list[i].append(q3_ethlen)
        feature_list[i].append(var_ethlen)
        feature_list[i].append(iqr_ethlen)


def calc_IP_payload_size_features(packet_list, filter_con):
    """ function to calculate IP packet size related features """
    global IP_len
    global IP_len_list
    global slice_length
    IP_len_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            IP_len.append(packet["IP"].len - packet["IP"].ihl)
        except IndexError as e:
            print("Error message: ", str(e))
        yield packet, dev_name

    IP_len_list.append(IP_len)
    IP_len = []

    for i, (data) in enumerate(IP_len_list):
        if len(data) == 0:      # For ethernet only packets
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

        feature_list[i].append(min_ip_len)
        feature_list[i].append(max_ip_len)
        feature_list[i].append(q1_ip_len)
        feature_list[i].append(median_ip_len)
        feature_list[i].append(mean_ip_len)
        feature_list[i].append(q3_ip_len)
        feature_list[i].append(var_ip_len)
        feature_list[i].append(iqr_ip_len)


def calc_IP_header_size_features(packet_list, filter_con):
    """ function to calculate IP header size related features """
    global IP_header_len
    global IP_header_len_list
    global slice_length
    IP_header_len_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            IP_header_len.append(packet["IP"].ihl)
        except IndexError as e:
            print("Error message: ", str(e))
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

        feature_list[i].append(min_iph_len)
        feature_list[i].append(max_iph_len)
        feature_list[i].append(q1_iph_len)
        feature_list[i].append(median_iph_len)
        feature_list[i].append(mean_iph_len)
        feature_list[i].append(q3_iph_len)
        feature_list[i].append(var_iph_len)
        feature_list[i].append(iqr_iph_len)


def calc_num_of_pkts(packet_list, filter_con):
    """ function to calculate packet count related features """
    global pkt_counter
    global pkt_count_list

    pkt_count_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        pkt_counter = pkt_counter + 1
        yield packet, dev_name

    pkt_count_list.append(pkt_counter)
    pkt_counter = 0

    for i, (data) in enumerate(pkt_count_list):
        feature_list[i].append(data)


def calc_pkt_directions(packet_list, filter_con):
    """ function to calculate packet direction related features """
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
        data.extend([2] * max(slice_length - len(data), 0))
        concat_pkt_dir = ''.join(map(str, data))        # generating a single string with individual direction values
        feature_list[i].append(int(concat_pkt_dir))


def calc_pkt_rate(packet_list, filter_con):
    """ function to calculate packet rate related features """
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
        except IndexError as e:
            print("Error message: ", str(e))
        yield packet, dev_name

    pkt_rate.append(pkt_counter)
    pkt_rate_list.append(pkt_rate)
    pkt_rate = []
    pkt_counter = 0
    rate_start_time = 0
    rate_end_time = 0

    for i, (data) in enumerate(pkt_rate_list):
        concat_pkt_rate = ""
        for j in range(5):          # Filtering the first five packet rate values
            if j < len(data):
                concat_pkt_rate += str(data[j])
            else:
                concat_pkt_rate += str(0)
        feature_list[i].append(int(concat_pkt_rate))


def calc_IP_destinations(packet_list, filter_con):
    """ function to calculate number of destination IPs related features """
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
        except IndexError as e:
            print("Error message: ", str(e))
        dest_ip_seq.append(dst_ip_counter)
        yield packet, dev_name

    dest_ip_counter_list.append(dest_ip_seq)
    dst_ip_counter = 0
    dest_ip_seq = []
    dest_ip_set = {}

    for i, (data) in enumerate(dest_ip_counter_list):
        concat_ip_destinations = ""
        for j in range(slice_length):
            if j < len(data):
                concat_ip_destinations += str(data[j])
            else:
                concat_ip_destinations += str(data[len(data)-1])
        feature_list[i].append(int(concat_ip_destinations))


def calc_port_class(packet_list, filter_con):
    """ function to calculate source/ destination port related features """
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
            tcp, udp, tl_pro = fe.get_tcpudp_feature(packet)                # Get the TCP, UDP feature status
            src_port_cls.append(fe.get_srcpc_feature(packet, tl_pro))       # Getting source port class value
            dst_port_cls.append(fe.get_dstpc_feature(packet, tl_pro))       # Getting destination port class value
        except IndexError:
            src_port_cls.append(0)
            dst_port_cls.append(0)
        yield packet, dev_name

    src_port_class_list.append(src_port_cls)
    dst_port_class_list.append(dst_port_cls)

    for i, (data) in enumerate(src_port_class_list):
        concat_src_prtclass = ""
        for j in range(slice_length):
            if j < len(data):
                concat_src_prtclass += str(data[j])
            else:
                concat_src_prtclass += str(0)
        feature_list[i].append(int(concat_src_prtclass))        # Appending source port class feature

    for i, (data) in enumerate(dst_port_class_list):
        concat_dst_prtclass = ""
        for j in range(slice_length):
            if j < len(data):
                concat_dst_prtclass += str(data[j])
            else:
                concat_dst_prtclass += str(0)
        feature_list[i].append(int(concat_dst_prtclass))        # Appending destination port class feature


def calc_dhcp_options(packet_list, filter_con):
    """ function to calculate DHCP options related features """
    global dhcp_opt_sum
    global dhcp_options_sum_list
    dhcp_opt_sum = []
    dhcp_options_sum_list = []

    for i, (packet, dev_name) in enumerate(packet_list):
        try:
            x = packet["DHCP options"].options      # Analysing the DHCP options header
            for i, (a) in enumerate(x):
                if a[0] == "param_req_list":        # Extract the parameters in the 'param_req_list' of the header
                    sum = 0
                    for j in range(len(a[1])):      # Get the sum of parameter values
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

        feature_list[i].append(round(min_dhcp, 2))
        feature_list[i].append(round(max_dhcp, 2))
        feature_list[i].append(round(q1_dhcp, 2))
        feature_list[i].append(round(median_dhcp, 2))
        feature_list[i].append(round(mean_dhcp, 2))
        feature_list[i].append(round(q3_dhcp, 2))
        feature_list[i].append(round(var_dhcp, 2))


def end_generator(packet_list):
    for i, (packet, dev_name) in enumerate(packet_list):        # This can be used to extend the generator function
        pass


def load_behavior_features(folder):
    # This function loads packet data based on filter conditions: bidirectional, Src_to_Other, Other_to_Src
    global feature_list
    global device_list

    filter = "bidirectional"
    packet_list_bidirec = load_data(folder, filter)

    # Initiate the variables to store the features
    piped_to_IA = initiate_feature_list(packet_list_bidirec)

    # Calculate the features for packet list
    piped_to_eth_size = calc_IA_features(piped_to_IA, filter)
    piped_to_ip_size = calc_ethsize_features(piped_to_eth_size, filter)
    piped_to_ip_header_size = calc_IP_payload_size_features(piped_to_ip_size, filter)
    piped_to_pkt_rate = calc_IP_header_size_features(piped_to_ip_header_size, filter)
    piped_to_pkt_direction = calc_pkt_rate(piped_to_pkt_rate, filter)
    piped_to_end_generator = calc_pkt_directions(piped_to_pkt_direction, filter)
    end_generator(piped_to_end_generator)

    filter = "Src_to_Other"
    packet_list_from_Src = load_data(folder, filter)
    piped_to_eth_size = calc_IA_features(packet_list_from_Src, filter)
    piped_to_ip_size = calc_ethsize_features(piped_to_eth_size, filter)
    piped_to_ip_header_size = calc_IP_payload_size_features(piped_to_ip_size, filter)
    piped_to_pkt_rate = calc_IP_header_size_features(piped_to_ip_header_size, filter)
    piped_to_ip_destinations = calc_pkt_rate(piped_to_pkt_rate, filter)
    piped_to_port_class = calc_IP_destinations(piped_to_ip_destinations, filter)
    piped_to_end_generator = calc_port_class(piped_to_port_class, filter)
    end_generator(piped_to_end_generator)

    return feature_list, device_list


if __name__ == "__main__":
    # Location where the training dataset is available
    pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel_all\\captures_IoT-Sentinel"
    device_labels = ['Aria', 'HomeMaticPlug', 'Withings', 'MAXGateway', 'HueBridge', 'HueSwitch', 'EdnetGateway',
                     'EdnetCam', 'EdimaxCam', 'Lightify', 'WeMoInsightSwitch', 'WeMoLink', 'WeMoSwitch',
                     'D-LinkHomeHub', 'D-LinkDoorSensor', 'D-LinkDayCam', 'D-LinkCam', 'D-LinkSwitch',
                     'D-LinkWaterSensor', 'D-LinkSiren', 'D-LinkSensor', 'TP-LinkPlugHS110', 'TP-LinkPlugHS100',
                     'EdimaxPlug1101W', 'EdimaxPlug2101W', 'SmarterCoffee', 'iKettle2']
    no_of_feature_list = []
    f1_score_list = {}
    precision_list = {}
    recall_list = {}

    for s in range(1):
        slice_length = 21       # Extracting the filtered first 21 packets
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

        Number_of_features = len(dataset_X[0])          # number of features present in the feature set
        dataset_X = np.array(dataset_X, dtype=object)   # Dataset with the features
        dataset_y = np.array(dataset_y)                 # dataset with the device labels

        for num_features in range(1):
            device_set = set(dataset_y)     # list of unique device labels

            num_of_iter = 10
            k_folds = 10
            total_dev_pred_accuracy = {}    # records pred_vector accuracy
            f_importance = {}               # records the feature importance in classification
            iterationwise_device_pred_accuracy = {}     # stores iterationwise device prediction accuracy
            iterationwise_precision = {}                # stores iterationwise device prediction precision
            iterationwise_recall = {}                   # stores iterationwise device prediction recall
            iterationwise_f1score = {}                  # stores iterationwise device prediction F1-score
            iterationwise_fimportance = {}              # stores iterationwise feature importance
            all_tested = []             # list of all tested device labels
            all_predicted = []          # list of all predicted device labels
            test_dev_counter = {}       # Number of different test devices
            f1_score_array = []
            precision_array = []
            recall_array = []
            score_list = []

            for iter in range(num_of_iter):         # executes num_of_iter times to predict device types
                iteration = 0
                skf = StratifiedKFold(n_splits=k_folds, shuffle=True)   # splitting the dataset with k-folds

                for train_index, test_index in skf.split(dataset_X, dataset_y):
                    print("Iteration No: ", iter, " with K_fold inner iteration: ", iteration)
                    iteration += 1
                    X_train, X_test = dataset_X[train_index], dataset_X[test_index]     # train/ test feature set
                    y_train, y_test = dataset_y[train_index], dataset_y[test_index]     # train/ test device labels

                    # scaling is somtimes required if you decide to change the classification model
                    # scaling = MinMaxScaler(feature_range=(-1, 1)).fit(X_train)
                    # X_train = scaling.transform(X_train)
                    # X_test = scaling.transform(X_test)

                    X_unknown = X_test
                    y_unknown = y_test

                    test_set = set(y_unknown)  # list of unique device labels

                    Curr_test_dev_counter = collections.Counter(y_test)
                    test_dev_counter = {k: test_dev_counter.get(k, 0) + Curr_test_dev_counter.get(k, 0)
                                        for k in set(test_dev_counter) | set(Curr_test_dev_counter)}

                    clf = RandomForestClassifier(n_estimators=100)      # Initiating the Random forest ML classifier
                    clf.fit(X_train, y_train)                           # Training the Random forest ML classifier

                    importances = clf.feature_importances_              # calculates the feature importance
                    std = np.std([tree.feature_importances_ for tree in clf.estimators_], axis=0)
                    indices = np.argsort(importances)[::-1]
                    for f in range(X_train.shape[1]):
                        if indices[f] % Number_of_features not in f_importance:
                            f_importance[indices[f] % Number_of_features] = importances[indices[f]]
                            iterationwise_fimportance[indices[f] % Number_of_features] = [importances[indices[f]]]
                        else:
                            f_importance[indices[f] % Number_of_features] += importances[indices[f]]
                            iterationwise_fimportance[indices[f] % Number_of_features].append(importances[indices[f]])

                    y_predict = clf.predict(X_unknown)      # Predicting the device names for unknown fingerprints

                    for i in range(len(y_unknown)):
                        all_tested.append(y_unknown[i])     # List of all tested devices
                        all_predicted.append(y_predict[i])  # List of all predicted devices
                        if y_unknown[i] == y_predict[i]:    # Calculate the correctly predicted devices
                            if y_unknown[i] not in total_dev_pred_accuracy:
                                total_dev_pred_accuracy[y_unknown[i]] = 1
                            else:
                                total_dev_pred_accuracy[y_unknown[i]] += 1

                    for key, value in Curr_test_dev_counter.items():
                        if key not in total_dev_pred_accuracy:
                            total_dev_pred_accuracy[key] = 0

                    for key, value in total_dev_pred_accuracy.items():
                        if key not in iterationwise_device_pred_accuracy:
                            iterationwise_device_pred_accuracy[key] = [value / Curr_test_dev_counter[key]]
                        else:
                            i = sum(iterationwise_device_pred_accuracy[key])
                            iterationwise_device_pred_accuracy[key].append(value / Curr_test_dev_counter[key] - i)

                    current_test = y_unknown
                    current_predcited = y_predict
                    # Measure the performance evaluation metrics using sklearn
                    precision, recall, f1_sco, supp = precision_recall_fscore_support(current_test, current_predcited,
                                                                                      labels=device_labels)
                    for i, (device) in enumerate(device_labels):
                        if device not in iterationwise_precision:       # store iteration-wise performance matrics
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

                    # --------------------------- End of k-fold cross-validation loop --------------------------------

            # ---------------------------- End of multiple iterating loop ----------------------------------------
            if not num_features in f1_score_list:
                no_of_feature_list.append(num_features)
                f1_score_list[num_features] = f1_score_array
                precision_list[num_features] = precision_array
                recall_list[num_features] = recall_array

            for d in device_set:       # check if there are devices which were not predicted correctly at least once
                if d not in total_dev_pred_accuracy:
                    total_dev_pred_accuracy[d] = 0

            for key, value in total_dev_pred_accuracy.items():
                total_dev_pred_accuracy[key] = value / (test_dev_counter[key])  # produce the accuracy as a fraction

            for key, value in f_importance.items():
                f_importance[key] = value/(num_of_iter)  # produce the accuracy as a fraction

        # -------------------------- End of loop for changing number of features -----------------------------------------

        plot_pred_accuracy(iterationwise_f1score, "F1 score - Sequence Based", 1, True, "F$_1$-score")

    seq_based_mean_accuracy = []
    for i, (device) in enumerate(device_labels):
        for key, value in iterationwise_device_pred_accuracy.items():
            if key == device:
                seq_based_mean_accuracy.append(np.mean(value))

    seq_based_f1_accuracy = []
    for i, (device) in enumerate(device_labels):
        for key, value in iterationwise_f1score.items():
            if key == device:
                seq_based_f1_accuracy.append(np.mean(value))

    iterationwise_f1_list = []
    for i in range(100):
        f1_list = []
        for key, value in iterationwise_f1score.items():
            f1_list.append(value[i])
        iterationwise_f1_list.append(np.mean(f1_list))

    print("Avg f1-score", np.mean(iterationwise_f1_list))       # Display the Average F1-score
    print("Min f1-score", np.min(iterationwise_f1_list))        # Display the Minimum F1-score
    print("Max f1-score", np.max(iterationwise_f1_list))        # Display the Maximum F1-score
    print("Var f1-score", np.var(iterationwise_f1_list))        # Display the Variance of F1-scores
