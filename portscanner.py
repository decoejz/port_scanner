# Codigo construido informacoes do livro Violent Python, capitulo 2
# Autor: TJ O'Connor
import socket

class PortScanner:

    def scanNetwork(self):
        pass

    def scanPorts(self,ip,portRange,tcp,udp):
        tcp_open = []
        udp_open = []

        for i in range(portRange[0],portRange[1]+1):
            if (tcp == 1):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip,i))
                    s.send(b'----\r\n')
                    results = s.recvmsg(100)
                    tcp_open.append(i)
                    s.close()
                except:
                    pass
            if (udp == 1):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect((ip,i))
                    udp_open.append(i)
                    s.close()
                except:
                    pass
        return(tcp_open,udp_open)