
#!/usr/bin/env python
import argparse
import scapy.all as scapy

#this is the main scanning function, it's two parameters are the port and ip from the parameters object
def scan(ip, port):
	arp_packet = scapy.ARP(pdst= ip)
	arp_packet.dport = port
	broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_broadcast_packet = broadcast_packet/arp_packet
	answered_list = scapy.srp(arp_broadcast_packet,timeout= 1, verbose=False)[0]	
	found_list = []
	for element in answered_list:
		client_dic = {"ip": element[1].prsrc, "mac": element[1].hwsrc}
		found_list.append(client_dic)

	return found_list

#this funciton reads in all the parameters passed through the command line, and documents their use
def read_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--targethost", dest="target_host", help="the host's ip you wish to scan")
	parser.add_argument("-p", "--port", dest="target_port", help="the host's port number you wish to scan")
	parameters = parser.parse_args()
	return parameters

#this function prints out the output received from the scan function, including the Mac address and IP address of the found devices
def output(input_list):
	print("IP \t\t\tMAC\n")
	for client in input_list:
		print(client["ip"] + "\t\t\t" + client["mac"])

#this is the executed code, first reading in the parameters, passing them in the scan funciton, then printing the results
parameters = read_args()
results = scan(parameters.target_host, parameters.target_port)


output(results)
