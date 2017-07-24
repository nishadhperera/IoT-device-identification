from scapy.all import *
import fnmatch
import matplotlib.pyplot as plt
import numpy as np


prev_packet = ""
newfile = False
IA_times = []
IA_times_list = []
ether_len = []
ether_len_list = []

feature_list = []


def pcap_class_generator(pcap_folder):
    global IA_times
    global IA_times_list
    global prev_packet
    global newfile

    for path, dir_list, file_list in os.walk(pcap_folder):
        for name in fnmatch.filter(file_list, "*.pcap"):
            print(os.path.join(path, name))
            if IA_times:
                IA_times_list.append(IA_times)
                IA_times = []
                prev_packet = ""
            newfile = True
            yield os.path.join(path, name), name


def source_filtered_packet_generator(pcap_class_gen):
    for pcapfile, name in pcap_class_gen:
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
            if packet[0].src == source_mac_add:
                yield packet, name


def load_data(folder):
    file_list = pcap_class_generator(folder)
    packet_list = source_filtered_packet_generator(file_list)
    return packet_list


def cal_IA_features(packet_list):
    global prev_packet
    global newfile
    global IA_times_list
    global feature_list

    for i, (packet, name) in enumerate(packet_list):
        if newfile:
            newfile = False
        else:
            IA_times.append(packet.time - prev_packet.time)
        prev_packet = packet

    IA_times_list.append(IA_times)
    IA_times_list = np.array(IA_times_list)
    fig, axarr = plt.subplots(len(IA_times_list), sharex=True, sharey=True)

    for i, (data) in enumerate(IA_times_list):
        print(i, IA_times_list[i])
        min_IAT = min(IA_times_list[i])  # minimum packet inter-arrival time
        max_IAT = max(IA_times_list[i])  # maximum packet inter-arrival time
        q1_IAT = np.percentile(IA_times_list[i], 25)    # first quartile of inter-arrival time
        median_IAT = np.percentile(IA_times_list[i], 50)    # median of inter-arrival time
        mean_IAT = np.mean(IA_times_list[i])                # mean of inter-arrival time
        q3_IAT = np.percentile(IA_times_list[i], 75)    # third quartile of inter-arrival time
        var_IAT = np.var(IA_times_list[i])              # variance of inter-arrival time

        feature_list.append(min_IAT)
        feature_list.append(max_IAT)
        feature_list.append(q1_IAT)
        feature_list.append(median_IAT)
        feature_list.append(mean_IAT)
        feature_list.append(q3_IAT)
        feature_list.append(var_IAT)
        print(feature_list)

    for i, (data) in enumerate(IA_times_list):
        axarr[i].plot(data)

    plt.ylabel("Inter arrival time (s)")
    plt.xlabel("Packet count")
    plt.show()


# def cal_ethsize_features(packet_list):
#     for i, (packet, name) in enumerate(packet_list):
#         if newfile:
#             newfile = False
#         else:
#
#
#     IA_times_list.append(IA_times)

pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel\\Test\\D-LinkCam"

# Calculate the inter-arrival time of packets
packet_list = load_data(pcap_folder)
cal_IA_features(packet_list)



