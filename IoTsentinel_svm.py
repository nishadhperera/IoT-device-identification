import os
import fnmatch
import pyshark
import pickle
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix

import feature_extraction as fe

dest_ip_set = {}  # stores the destination IP set, a global variable
dst_ip_counter = 0 # keeps destinatio counter value, a global variable

def pcap_class_generator(folder):
    for path, dir_list, file_list in os.walk(folder):
        for name in fnmatch.filter(file_list, "*.pcap"):
            global dst_ip_counter
            global dest_ip_set
            dest_ip_set.clear()  # stores the destination IP set
            dst_ip_counter = 0
            print(os.path.join(path, name))
            yield os.path.join(path, name), os.path.basename(os.path.normpath(path))


def packet_class_generator(pcap_class_gen):
    for pcapfile, class_ in pcap_class_gen:
        capture = pyshark.FileCapture(pcapfile)
        for packet in capture:
            yield packet, class_

def feature_class_generator(packet_class_gen):

    for packet, class_ in packet_class_gen:
        global dst_ip_counter
        global dest_ip_set

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

        if nl_pro == "IP":      #Inspecting the IP layer
            fvector[3], fvector[4] = fe.get_icmp_feature(packet)    # ICMP, ICMPv6 features
            fvector[6], fvector[7], tl_pro = fe.get_tcpudp_feature(packet)  # TCP, UDP features
            fvector[17] = fe.get_r_alert_feature(packet)            # Router Alert feature
            fvector[20], dest_ip_set, dst_ip_counter = fe.get_dest_ip_counter_feature(packet, dest_ip_set, dst_ip_counter)    # Destination ip counter feature

        if tl_pro == "TCP" or tl_pro == "UDP":
            fvector[13] = fe.get_dns_feature(packet, tl_pro)    #dns feature
            fvector[10], fvector[11] = fe.get_bootp_dhcp_feature(packet, tl_pro)    # DHCP and BOOTP features
            fvector[8] = fe.get_http_feature(packet, tl_pro)    # HTTP feature
            fvector[15] = fe.get_ntp_feature(packet, tl_pro)    # NTP feature
            fvector[9] = fe.get_https_feature(packet, tl_pro)   # HTTPS feature
            fvector[12] = fe.get_ssdp_feature(packet, tl_pro)   # SSDP feature
            fvector[14] = fe.get_mdns_feature(packet, tl_pro)   # MDNS feature
            fvector[21] = fe.get_srcpc_feature(packet, tl_pro)  # source port class feature
            fvector[22] = fe.get_dstpc_feature(packet, tl_pro)  # destination port class feature

        yield fvector, class_


def dataset(feature_class_gen, maxCount):
    def g():
        for i, (feature, class_) in enumerate(feature_gen):
            # if i > maxCount:
            #     continue
            yield feature, class_
    return zip(*g())


#pcap_folder="F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel\\Test"
pcap_folder = "F:\\MSC\\Master Thesis\\Network traces\\captures_IoT_Sentinel\\captures_IoT-Sentinel"

try:
    dataset_X = pickle.load(open("dataset_X.pickle", "rb"))
    dataset_y = pickle.load(open("dataset_y.pickle", "rb"))
    print("Pickling successful......")
except (OSError, IOError) as e:
    print("Calculating new datasets as no pickle files found....")
    pcap_gen = pcap_class_generator(pcap_folder)
    packet_gen = packet_class_generator(pcap_gen)
    feature_gen = feature_class_generator(packet_gen)
    dataset_X, dataset_y = dataset(feature_gen, 1)
    dataset_X = np.array(dataset_X)
    dataset_y = np.array(dataset_y)
    pickle.dump(dataset_X, open("dataset_X.pickle", "wb"))
    pickle.dump(dataset_y, open("dataset_y.pickle", "wb"))

X_train, X_test, y_train, y_test = train_test_split(dataset_X , dataset_y, test_size=0.25, random_state=0)

X_train.shape, y_train.shape
X_test.shape, y_test.shape

print("X_train: ", X_train)
print("y_train: ",y_train)
print("X_test: ",X_test)
print("y_test: ",y_test)

clf = svm.SVC(kernel='linear', C=1).fit(X_train, y_train)

y_predict = clf.predict(X_test)
print("y_test: ", y_test)
print("y_predicted: ", y_predict)
print(classification_report(y_test, y_predict))
print(clf.score(X_test, y_test))
print(confusion_matrix(y_test, y_predict))




