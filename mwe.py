#!/usr/bin/python

from netfilterqueue import NetfilterQueue
from scapy.all import *

def process(pkt):
    scapyPkt = IP(pkt.get_payload())

    if scapyPkt.haslayer('ICMP') and scapyPkt.haslayer('Raw'):
        icmpData = list(scapyPkt[Raw].load)
        message = sys.argv[2]

        icmpData[:len(message)] = [ord(i) for i in message]
        scapyPkt[Raw].remove_payload()
        scapyPkt[Raw].load = bytes(icmpData)
        del scapyPkt[IP].len
        del scapyPkt[ICMP].chksum

    pkt.set_payload(bytes(scapyPkt))
    pkt.accept()

os.system('sudo iptables -A OUTPUT -d ' + sys.argv[1] + ' -p icmp -j NFQUEUE --queue-num 1')
print('Press Ctrl+C to end injection of secret message!')
nfqueue = NetfilterQueue()
nfqueue.bind(1, process)
try:
    nfqueue.run()
except KeyboardInterrupt:
    os.system('sudo iptables -D OUTPUT -d ' + sys.argv[1] + ' -p icmp -j NFQUEUE --queue-num 1')
    nfqueue.unbind()
    sys.exit(0)
