# This program contains methods to extract features from a packet
# Condition: packets are extracted using scapy rdpcap method
# Author: Nishadh Aluthge
from _csv import Error


def get_length_feature(packet):    # Extracts Packet length
    try:
        a = len(packet)
        return a
    except Error:
        return 0


def get_LLC_feature(packet):    # check for LLC layer header
    try:
        x = packet["LLC"]
        return 1
    except IndexError:
        return 0


def get_padding_feature(packet):   # check for padding layer header
    try:
        x = packet["Padding"]
        return 1
    except IndexError:
        return 0


def get_arp_feature(packet):
    try:
        if packet[0].type == 2054:  # ARP feature detected  (0 - Ethernet or 802.3 layer)
            return 1
        else:
            return 0
    except AttributeError:
        return 0


def get_ip_feature(packet):
    try:
        if packet[0].type == 2048:  # IP feature detected
            return 1, "IP"
        else:
            return 0, "None"
    except AttributeError:
        return 0, "None"


def get_eapol_feature(packet):
    try:
        if packet[0].type == 34958:  # EAPoL feature detected
            return 1
        else:
            return 0
    except AttributeError:
        return 0


def get_icmp_feature(packet):
    try:
        if packet["IP"].proto == 1:   # ICMP feature detected
            return 1, 0
        elif packet["IP"].proto == 58:  # ICMPv6 feature detected
            return 0, 1
        else:
            return 0, 0
    except IndexError:
        return 0, 0


def get_tcpudp_feature(packet):
    try:
        if packet["IP"].proto == 6:   # TCP feature detected
            return 1, 0, "TCP"
        elif packet["IP"].proto == 17:   # UDP feature detected
            return 0, 1, "UDP"
        else:
            return 0, 0, "None"
    except IndexError:
        return 0, 0, "None"


def get_r_alert_feature(packet):
    try:
        if int(packet["IP"].ihl) > 5:  # detecting Router Alert IP Option
            for op in packet["IP"].options:
                if int(op.option) == 20:
                    return 1
                else:
                    return 0
        else:
            return 0
    except IndexError:
        return 0


def get_dest_ip_counter_feature(packet, dest_ip_set, dst_ip_counter):
    if packet["IP"].dst not in dest_ip_set:  # Counting the Destination IP counter value
        dest_ip_set[packet["IP"].dst] = 1
        dst_ip_counter = dst_ip_counter + 1
    else:
        dest_ip_set[packet["IP"].dst] += 1
    return dst_ip_counter, dest_ip_set, dst_ip_counter


def get_dns_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].sport == 53 or packet['' + tl_pro + ''].dport == 53:  # DNS feature detected
            return 1
        else:
            return 0
    except IndexError:
        return 0


def get_bootp_dhcp_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].sport == 67 or packet['' + tl_pro + ''].sport == 68:  # BOOTP, DHCP feature detected
            return 1, 1
        else:
            return 0, 0
    except IndexError:
        return 0, 0


def get_http_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].sport == 80 or packet['' + tl_pro + ''].dport == 80:  # HTTP feature detected
            return 1
        else:
            return 0
    except IndexError:
        return 0


def get_ntp_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].sport == 123 or packet['' + tl_pro + ''].dport == 123:    # NTP feature detected
            return 1
        else:
            return 0
    except IndexError:
        return 0


def get_https_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].sport == 443:    # HTTPS feature detected
            return 1
        else:
            return 0
    except IndexError:
        return 0


def get_ssdp_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].sport == 1900:    # SSDP feature detected
            return 1
        else:
            return 0
    except IndexError:
        return 0


def get_mdns_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].sport == 5353:    # MDNS feature detected
            return 1
        else:
            return 0
    except IndexError:
        return 0


def get_srcpc_feature(packet, tl_pro):
    try:
        if int(packet['' + tl_pro + ''].sport) >= 49152:  # Calculating source port value
            return 3
        elif int(packet['' + tl_pro + ''].sport) >= 1024:
            return 2
        elif int(packet['' + tl_pro + ''].sport) >= 0:
            return 1
        else:
            return 0
    except IndexError:
        return 0


def get_dstpc_feature(packet, tl_pro):
    try:
        if int(packet['' + tl_pro + ''].dport) >= 49152:  # Calculating destination port value
            return 3
        elif int(packet['' + tl_pro + ''].dport) >= 1024:
            return 2
        elif int(packet['' + tl_pro + ''].dport) >= 0:
            return 1
        else:
            return 0
    except IndexError:
        return 0


def get_rawdata_feature(packet):        # Analyse for the presence of raw data in the payload
    try:
        x = packet["Raw"]
        return 1
    except IndexError:
        return 0


def get_payload_feature(packet):        # calculates the amount of rawdata present in the payload
    try:
        x = len(packet["Raw"])
    except (IndexError, AttributeError) as e:
        x = 0
    return x
