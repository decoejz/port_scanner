# Codigo construido informacoes do livro Violent Python, capitulo 2
# Autor: TJ O'Connor
import socket
from scapy.all import *

class PortScanner:

    def scanNetwork(self):
        pass

    # Funcao retirada de:
    # https://resources.infosecinstitute.com/port-scanning-using-scapy/#gref
    def udp_scan(self,dst_ip,dst_port,dst_timeout):
        udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
        if (str(type(udp_scan_resp))=="<class 'NoneType'>"):
            retrans = []
            for count in range(0,3):
                retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
            for item in retrans:
                if (str(type(item))!="<class 'NoneType'>"):
                    self.udp_scan(dst_ip,dst_port,dst_timeout)
                return "Open|Filtered"
        elif (udp_scan_resp.haslayer(UDP)):
            return "Open"
        elif(udp_scan_resp.haslayer(ICMP)):
            if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
                return "Closed"
            elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
                return "Filtered"
        else:
            return 'CHECK'

    def scanPorts(self,ip,portRange,tcp,udp):
        tcp_status = []
        udp_status = []
        pacote = b'----\r\n'

        for i in range(portRange[0],portRange[1]+1):
            if (tcp == 1):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip,i))
                    
                    s.send(b'----\r\n')
                    resposta = s.recv(100)
                    s.close()
                    tcp_status.append((i,str(resposta)[2:-1]))
                except:
                    pass
            if (udp == 1):
                udp_status.append((i,self.udp_scan(ip,i,10)))
        return(tcp_status,udp_status)

    def scanNet(self,ip):
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        pacote = ether/arp
        results = srp(pacote,timeout=3,verbose=0)[0]

        clientes = []
        for sent, received in results:
            clientes.append({'ip':received.psrc, 'mac':received.hwsrc})
        
        return clientes
