# Packet Sniffer

This is a simple packet sniffer implemented in Python using the `tkinter` and `scapy` libraries. It allows you to capture and display network packets in real-time.

## Features
1. **Start Sniffing:** Begin capturing network packets.
2. **Stop Sniffing:** Stop capturing network packets.
3. **Download Log:** Save the captured packets to a log file.
   
![image](https://github.com/Pythonist-ux/PRODIGY_CS_05/assets/83156291/4ab35e0c-7f30-412c-a465-381ed6cf77c9)

## Usage
1. Click the "Start Sniffing" button to begin capturing packets.
2. The program will display information about each captured packet, including the source IP, destination IP, protocol, and payload.
3. Click the "Stop Sniffing" button to stop capturing packets.
4. You can download the captured packets as a log file by clicking the "Download Log" button.
   
![image](https://github.com/Pythonist-ux/PRODIGY_CS_05/assets/83156291/8a230c9b-a6fe-4ecc-9d03-447a0611e857)


## Logic
1. The program uses the scapy library to sniff packets on the network interface specified ("Wi-Fi" in this case).
2. Each captured packet is processed by the `packet_callback function`, which extracts and displays relevant information.
3. The program uses tkinter for the GUI, with a scrolled text widget to display the packet information.
Note: This program is for educational purposes only and should not be used for any illegal activities.

## Installation
1. Clone the repository:

        git clone https://github.com/Pythonist-ux/PRODIGY_CS_05.git
2. Install the required dependencies:

         pip install scapy


   
