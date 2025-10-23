# PacketSniffer
A basic packet sniffer program that can capture packets in a .txt file. This was made using the python language and the Scapy library.

This tool was created to demonstrate a simple packet sniffer. This was 
made possible using the following components:- 
1)Network Connection 
2)Device (Kali Linux OS) 
3)Python 3.12.7 
4)Scapy library 
5)A packet capture library for the OS  
(Npcap for Windows/Wiretap Kali Linux) 
6) Wireshark for Verification 
 
The device used for the project ran on Kali Linux Virtual Machine and 
utilized the inbuilt packet sniffer library, Wiretap. Python 3.12.7 was 
installed and used. The installation can be done using the following 
command on terminal 
>sudo apt-get install python 
Scapy, the packet manipulator library for Python is then installed using 
the command 
 >pip install scapy 
 
The tool is then coded and run on the system using the command 
 >python3 sniff.py <interface> <packet type> <verbose> 
The three arguments are used as input for the tool. This tool supports 
ethernet (eth0) and Loopback (lo) interfaces. It can choose to capture  
9 
 
either TCP or UDP packets only, or both of them during the same 
session. The verbose is an optional argument used to display 
additional information, in this case, TCP flags of captured packets. 
 
To stop capturing packets, enter ‘ctrl + c’ on the terminal. The log is 
then stored in the “sniffer_{interface}_log.txt” text file. The following 
data will be displayed:- 
1) Packet Type 
2) Source IP 
3) Source Port 
4) Destination IP 
5) Destination Port 
6) TCP Flags  [ if verbose is enabled ] 
 
The results can then be compared with the number of packets 
captured in Wireshark during the same duration.  
 
When program is executed again, the old logfile is cleared and re
written on.
