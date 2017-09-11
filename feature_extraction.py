from _csv import Error
import pyshark


def get_length_feature(packet):    # Packet length
    try:
        a = packet.length
        return a
    except Error:
        return 0

def get_LLC_feature(packet):    # check for LLC layer header
    try:
        x = packet["LLC"]
        return 1
    except KeyError:
        return 0

def get_padding_feature(packet):   # check for padding layer header
    try:
        x = packet["ETH"].padding
        return 1
    except AttributeError:
        return 0

def get_arp_feature(packet):
    try:
        if packet['ETH'].type == "0x00000806":  # ARP feature detected
            return 1
        else:
            return 0
    except AttributeError:
        return 0

def get_ip_feature(packet):
    try:
        if packet['ETH'].type == "0x00000800":  # IP feature detected
            return 1, "IP"
        else:
            return 0, "None"
    except AttributeError:
        return 0, "None"

def get_eapol_feature(packet):
    try:
        if packet['ETH'].type == "0x0000888e":  # EAPoL feature detected
            return 1
        else:
            return 0
    except AttributeError:
        return 0

def get_icmp_feature(packet):
    try:
        if packet['ip'].proto == "1":   # ICMP feature detected
            return 1, 0
        elif packet['ip'].proto == "58":  # ICMPv6 feature detected
            return 0, 1
        else:
            return 0, 0
    except Error:
        return 0, 0

def get_tcpudp_feature(packet):
    try:
        if packet['ip'].proto == "6":   # TCP feature detected
            return 1, 0, "TCP"
        elif packet['ip'].proto == "17":   # UDP feature detected
            return 0, 1, "UDP"
        else:
            return 0, 0, "None"
    except Error:
        return 0, 0, "None"

def get_r_alert_feature(packet):
    try:
        if int(packet['ip'].hdr_len) > 20:  # detecting Router Alert IP Option
            if int(packet['ip'].opt_type_number) == 20:
                return 1
            else:
                return 0
        else:
            return 0
    except Error:
        return 0

def get_dest_ip_counter_feature(packet, dest_ip_set, dst_ip_counter):
    if packet['ip'].dst not in dest_ip_set:  # Counting the Destination IP counter value
        dest_ip_set[packet['ip'].dst] = 1
        dst_ip_counter = dst_ip_counter + 1
    else:
        dest_ip_set[packet['ip'].dst] += 1
    return dst_ip_counter, dest_ip_set, dst_ip_counter


def get_dns_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].srcport == "53" or packet['' + tl_pro + ''].dstport == "53":  # DNS feature detected
            return 1
        else:
            return 0
    except Error:
        return 0

def get_bootp_dhcp_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].srcport == "67" or packet['' + tl_pro + ''].srcport == "68":  # BOOTP, DHCP feature detected
            return 1, 1
        else:
            return 0, 0
    except Error:
        return 0, 0

def get_http_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].srcport == "80" or packet['' + tl_pro + ''].dstport == "80":  # HTTP feature detected
            return 1
        else:
            return 0
    except Error:
        return 0

def get_ntp_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].srcport == "123" or packet['' + tl_pro + ''].dstport == "123":    # NTP feature detected
            return 1
        else:
            return 0
    except Error:
        return 0

def get_https_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].srcport == "443":    # HTTPS feature detected
            return 1
        else:
            return 0
    except Error:
        return 0

def get_ssdp_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].srcport == "1900":    # SSDP feature detected
            return 1
        else:
            return 0
    except Error:
        return 0

def get_mdns_feature(packet, tl_pro):
    try:
        if packet['' + tl_pro + ''].srcport == "5353":    # MDNS feature detected
            return 1
        else:
            return 0
    except Error:
        return 0

def get_srcpc_feature(packet, tl_pro):
    try:
        if int(packet['' + tl_pro + ''].srcport) >= 49152:  # Calculating source port value
            return 3
        elif int(packet['' + tl_pro + ''].srcport) >= 1024:
            return 2
        elif int(packet['' + tl_pro + ''].srcport) >= 0:
            return 1
        else:
            return 0
    except Error:
        return 0

def get_dstpc_feature(packet, tl_pro):
    try:
        if int(packet['' + tl_pro + ''].dstport) >= 49152:  # Calculating destination port value
            return 3
        elif int(packet['' + tl_pro + ''].dstport) >= 1024:
            return 2
        elif int(packet['' + tl_pro + ''].dstport) >= 0:
            return 1
        else:
            return 0
    except Error:
        return 0