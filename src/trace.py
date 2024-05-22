#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRACE_THE_WUMPUS
Copyright (C) 2014-2024 Leitwert GmbH

This software is distributed under the terms of the MIT license.
It can be found in the LICENSE file or at https://opensource.org/licenses/MIT.

Author Johann SCHLAMP <schlamp@leitwert.net>
"""

# Local imports
from wumpus.game import Game
from wumpus.const import FILTER_PREFIX_IPV6
from wumpus.const import FILTER_PREFIX_IPV4
# Scapy imports
import scapy.all as scapy
from scapy.all import Ether, ARP, IP, ICMP, UDP, TCP, Raw
from scapy.all import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, ICMPv6EchoRequest, ICMPv6EchoReply
# Constants
INTERFACE = "eth0"
# MAC address of interface eth0
HW_ADDR = scapy.get_if_hwaddr(INTERFACE)

# Globals
game = Game(debug=True)

# Sample game input
src, dst = "2001::1", "2a06:2904::10:10:10"
hops = game.handle_input(src, dst)

# Sample game output
print(f"Sample traceroute from {src} to {dst}:" + "\n".join(hops))

# TODO WWWWWWWWWWWWWW
# TODO W YOUR TASKS W
# TODO WWWWWWWWWWWWWW
# TODO

def is_icmp_echo_request(pkt: scapy.Packet) -> bool:
    return pkt.haslayer(ICMP) and pkt.getlayer(ICMP).code == 0 and pkt.getlayer(ICMP).type == 8


def callback(pkt: scapy.Packet) -> None:

    #print(pkt.summary())

    ## ARP stuff
    if pkt.haslayer(ARP):

        # Get Ethernet data
        eth_layer = pkt.getlayer(Ether)
        hwsrc = eth_layer.src
        
        # Get ARP data
        arp_layer = pkt.getlayer(ARP)
        psrc, pdst = arp_layer.psrc, arp_layer.pdst
        
        # Build and send ARP reply
        eth_reply = Ether(src=HW_ADDR, dst=hwsrc)
        arp_reply = ARP(op=2, psrc=pdst, pdst=psrc)
        scapy.sendp(eth_reply / arp_reply)


    # TODO
    # TODO • Implement ICMP ping for incoming echo requests
    # TODO   —> test with "ping wumpus.quest"

    if pkt.haslayer(IP) and pkt.getlayer(IP).version == 4:
        ip_layer = pkt.getlayer(IP)
        ipv4_src = ip_layer.src
         
        ## Reply to ICMP (v4) echo-request packets
        if is_icmp_echo_request(pkt):

            # Forge and send ICMP echo-reply
            echo_reply = IP(dst=ipv4_src) / ICMP(type=0, code=0)
            scapy.send(echo_reply)


    # TODO
    # TODO • Rewrite both routines to support ICMPv6
    # TODO   —> test with "ping6 wumpus.quest"
    # TODO   —> test with "traceroute6 wumpus.quest"
    if pkt.haslayer(IPv6):

        # Get MAC and IPv6 source addresses
        ipv6_layer = pkt.getlayer(IPv6)
        ipv6_src = ipv6_layer.src

        # Build IPv6 layer
        ipv6_reply = IPv6(dst=ipv6_src)

        ### ICMPv6 Router Sollicitation
        if pkt.haslayer(ICMPv6ND_NS):

            # Build ICMPv6 layer
            icmpv6_na = ICMPv6ND_NA(R=0, S=1, O=1, tgt=dst)
            tgt_ll_addr = ICMPv6NDOptDstLLAddr(lladdr=HW_ADDR)

            # Send packet
            pkt_reply = ipv6_reply / icmpv6_na / tgt_ll_addr
            scapy.send(pkt_reply)


        ### ICMPv6 echo request
        elif pkt.haslayer(ICMPv6EchoRequest):

            # Get data from ICMPv6 echo request
            icmpv6_echo_request = pkt.getlayer(ICMPv6EchoRequest)
            icmpv6_id = icmpv6_echo_request.id
            icmpv6_seq = icmpv6_echo_request.seq

            # Build ICMPv6 echo reply
            icmpv6_echo_reply = ICMPv6EchoReply(id=icmpv6_id, seq=icmpv6_seq)
            pkt_reply = ipv6_reply / icmpv6_echo_reply
            scapy.send(pkt_reply)


    # TODO
    # TODO • Implement ICMP traceroute for incoming TCP/UDP requests
    # TODO   —> generate response IP addresses with game.handle_input()
    # TODO   —> test with "traceroute wumpus.quest"
    if pkt.haslayer(UDP) or pkt.haslayer(TCP):
        ip_layer = pkt.getlayer(IPv6) if pkt.haslayer(IPv6) else pkt.getlayer(IP)
        ip_src = ip_layer.src
        ip_dst = ip_layer.dst
        ip_list = game.handle_input(ip_src, ip_dst)
        # TODO: handle IP list


    # TODO • Play the wumpus.quest and have fun :)


### TODO • Capture and print packets for given INTERFACE
filter = f"(net {FILTER_PREFIX_IPV4} or net {FILTER_PREFIX_IPV6}) and not ether src {HW_ADDR}"
capture = scapy.sniff(iface=INTERFACE, prn=callback, filter=filter)
