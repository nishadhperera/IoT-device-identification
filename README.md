# IoT Device fingerprinting with sequence based features

This code aims at Identifying Internet of Things (IoT) devices connecting to a network by passive traffic monitoring with the support of supervised machine learning.

The technique was implemented by extracting features from transmitted/ received IP packets and using machine learning to train a classification model. 
Technique was evaluated with a set of off-the-shelf IoT devices and able to achieve accuracy over 90%.

The code is developed in Python using numpy, scapy (reading pcap files) and sklearn (machine learning module) 
