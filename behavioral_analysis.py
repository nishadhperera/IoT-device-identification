from tkinter.ttk import tclobjs_to_py

from scapy.all import *
import fnmatch
import matplotlib.pyplot as plt
import numpy as np
from scipy.fftpack import fft
import bottleneck

import features_scapy as fe

prev_packet = ""
IA_times = []
IA_times_list = []
source_mac_add = ""
new_device = False

feature_list = []       # stores the features
device_list = []        # stores the device names


def pcap_class_generator(pcap_folder):
    global IA_times
    global IA_times_list
    global prev_packet
    global new_device

    for path, dir_list, file_list in os.walk(pcap_folder):

        for name in fnmatch.filter(file_list, "*_ON.pcap"):
            print(os.path.join(path, name), os.path.basename(os.path.normpath(path)))
            new_device = True
            if IA_times:
                IA_times_list.append(IA_times)
                IA_times = []
                prev_packet = ""
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
    plt.plot(list)
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.grid(linestyle='dotted')
    plt.show()


def subplot_list(list, title, x_label, y_label):
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

    print(len(IA_times_list[0]))
    print(IA_times_list)

    # plot_list(IA_times_list[0], "Inter arrival time variation with the packet count (%s traffic)" % filter_con, "Packet Number",
    #           "Inter arrival time (s)")


def calc_periodic_statistics(packet_list, period_in_minutes, filter_con):
    global prev_packet
    start_time = 0
    IA_array = []
    min_array = []
    max_array = []
    q1_IAT_array = []
    median_IAT_array = []
    mean_IAT_array = []
    q3_IAT_array = []
    var_IAT_array = []
    iqr_IAT_array = []

    periodic_time = period_in_minutes * 60

    for i, (packet, dev_name) in enumerate(packet_list):
        if start_time == 0:
            start_time = packet.time
        if prev_packet == "":
            pass
        else:
            if (packet.time - start_time) <= periodic_time:
                IA_array.append(packet.time - prev_packet.time)
            else:
                print("CALCULATE SUMMARY STATISTICS")
                min_array.append(min(IA_array))  # minimum packet inter-arrival time
                max_array.append(max(IA_array))  # maximum packet inter-arrival time
                q1_IAT_array.append(np.percentile(IA_array, 25))  # first quartile of inter-arrival time
                median_IAT_array.append(np.percentile(IA_array, 50))  # median of inter-arrival time
                mean_IAT_array.append(np.mean(IA_array))  # mean of inter-arrival time
                q3_IAT_array.append(np.percentile(IA_array, 75))  # third quartile of inter-arrival time
                var_IAT_array.append(np.var(IA_array))  # variance of inter-arrival time
                iqr_IAT_array.append(np.percentile(IA_array, 75) - np.percentile(IA_array, 25))  # inter quartile range of inter-arrival time
                start_time += periodic_time
                IA_array = []
        prev_packet = packet
        yield packet, dev_name

    # plot_list(min_array, "Minimum IAT per hr with the packet count (%s)" % filter_con,
    #           "Packet count", "Inter arrival time (s)")
    # plot_list(max_array, "Maximum IAT per hr with the packet count (%s)" % filter_con,
    #           "Packet count", "Inter arrival time (s)")
    # plot_list(q1_IAT_array, "IAT Q1 per hr with the packet count (%s)" % filter_con,
    #           "Packet count", "Inter arrival time (s)")
    # plot_list(median_IAT_array, "Median IAT per hr with the packet count (%s)" % filter_con,
    #           "Packet count", "Inter arrival time (s)")
    # plot_list(mean_IAT_array, "Mean IAT per hr with the packet count (%s)" % filter_con,
    #           "Packet count", "Inter arrival time (s)")
    # plot_list(q3_IAT_array, "IAT Q3 per hr with the packet count (%s)" % filter_con,
    #           "Packet count", "Inter arrival time (s)")
    # plot_list(var_IAT_array, "Variance of IAT per hr with the packet count (%s)" % filter_con,
    #           "Packet count", "Inter arrival time (s)")
    # plot_list(iqr_IAT_array, "IAT IQR per hr with the packet count (%s)" % filter_con,
    #           "Packet count", "Inter arrival time (s)")


def calc_protocol_freq(packet_list, period_in_minutes, filter_con):
    tcp_list = []
    udp_list = []
    http_list = []
    dhcp_list = []
    dns_list = []
    tcp_counter = 0
    udp_counter = 0
    http_counter = 0
    dhcp_counter = 0
    dns_counter = 0
    start_time = 0

    periodic_time = period_in_minutes * 60

    for i, (packet, dev_name) in enumerate(packet_list):
        if start_time == 0:
            start_time = packet.time

        tcp_val, udp_val, tl_pro = fe.get_tcpudp_feature(packet)
        http_val = fe.get_http_feature(packet, tl_pro)
        bootp_val, dhcp_val = fe.get_bootp_dhcp_feature(packet, tl_pro)
        dns_val = fe.get_dns_feature(packet, tl_pro)

        if (packet.time - start_time) <= periodic_time:
            tcp_counter = tcp_counter + tcp_val
            udp_counter = udp_counter + udp_val
            http_counter = http_counter + http_val
            dhcp_counter = dhcp_counter + dhcp_val
            dns_counter = dns_counter + dns_val
        else:
            tcp_list.append(tcp_counter)
            udp_list.append(udp_counter)
            http_list.append(http_counter)
            dhcp_list.append(dhcp_counter)
            dns_list.append(dns_counter)
            tcp_counter = tcp_val
            udp_counter = udp_val
            http_counter = http_val
            dhcp_counter = dhcp_val
            dns_counter = dns_val
            start_time += periodic_time
        yield packet, dev_name

    # plot_list(tcp_list, "Number of TCP packets per hr (%s)" % filter_con, "hr", "Packet count")
    # plot_list(udp_list, "Number of UDP packets per hr (%s)" % filter_con, "hr", "Packet count")
    # plot_list(http_list, "Number of HTTP packets per hr (%s)" % filter_con, "hr", "Packet count")
    # plot_list(dhcp_list, "Number of DHCP packets per hr (%s)" % filter_con, "hr", "Packet count")
    # plot_list(dns_list, "Number of DNS packets per hr (%s)" % filter_con, "hr", "Packet count")


def calc_pkt_rate(packet_list, period_in_minutes, filter_con):
    start_time = 0
    packet_count = 0
    pkt_rate = []

    periodic_time = period_in_minutes * 60

    for i, (packet, dev_name) in enumerate(packet_list):
        if start_time == 0:
            start_time = packet.time
        if (packet.time - start_time) <= periodic_time:
            packet_count += 1
        else:
            pkt_rate.append(packet_count)
            packet_count = 1
            start_time += periodic_time
        yield packet, dev_name

    # plot_list(pkt_rate, "Packet Rate (%s)" % filter_con, "minutes", "Packet count")


def calc_pkt_order(packet_list, filter_con):
    pkt_order = []

    for i, (packet, dev_name) in enumerate(packet_list):
        tcp_val, udp_val, tl_pro = fe.get_tcpudp_feature(packet)
        if tl_pro == "TCP":
            pkt_order.append(1)
        elif tl_pro == "UDP":
            pkt_order.append(2)
        else:
            pkt_order.append(0)
        yield packet, dev_name

    # plot_list(pkt_order, "Packet Order (%s)" % filter_con, "minutes", "Packet type (TCP=1, UDP=2, Other=0)")


def calc_payload_len(packet_list, filter_con):
    payload_lengths = []

    for i, (packet, dev_name) in enumerate(packet_list):
        payload_lengths.append(fe.get_payload_feature(packet))

    plot_list(payload_lengths, "Packet payload lengths (%s)" % filter_con, "Packet Number", "Payload length")


def end_generator(packet_list):
    for i, (packet, dev_name) in enumerate(packet_list):
        pass


def load_behavior_features(folder):
    global feature_list
    global device_list

    filter = "Src_to_Other"         # Other_to_Src, bidirectional, Src_to_Other
    # load packet data based on filter conditions: bidirectional, Src_to_Other, Other_to_Src
    packet_list = load_data(folder, filter)

    piped_to_IA = initiate_feature_list(packet_list)

    # Calculate the features for packet list
    sample_time = 1    # time in minutes
    piped_to_periodic_stat = calc_IA_features(piped_to_IA, filter)
    piped_to_prot_freq = calc_periodic_statistics(piped_to_periodic_stat, sample_time, filter)
    piped_to_pkt_rate = calc_protocol_freq(piped_to_prot_freq, sample_time, filter)
    piped_to_pkt_order = calc_pkt_rate(piped_to_pkt_rate, sample_time, filter)
    piped_to_payload_len = calc_pkt_order(piped_to_pkt_order, filter)
    piped_to_end_generator = calc_payload_len(piped_to_payload_len, filter)
    end_generator(piped_to_end_generator)

    return feature_list, device_list

pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\Behavioral_captures\\"

dataset_X, dataset_y = load_behavior_features(pcap_folder)