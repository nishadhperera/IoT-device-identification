import pyshark

# Open saved trace file
capture = pyshark.FileCapture('F:/MSC/Master Thesis/Network traces/captures_IoT_Sentinel/captures_IoT-Sentinel/Aria/Setup-A-1-STA.pcap')

print("Capture file:", capture)

for i, (packet) in enumerate(capture):
    print(i, packet["ETH"].src)

