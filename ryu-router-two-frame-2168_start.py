# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
# import sys

"""
fill in the code here (optional)
"""
s2_s1a_ip = '192.168.1.1'#S1ETH1_IP
s3_s1b_ip = '192.168.2.1'#S1ETH2_IP
h1_ip = '192.168.1.2'
h3_ip = '192.168.2.2'
h4_ip = '192.168.2.3'
h5_ip = '200.0.0.2'
h5_s1a_ip = '200.0.0.1'
h5_s1a_mac = '00:00:00:00:04:01'
h4_mac = '00:00:00:00:02:03'
h5_mac = '00:00:00:00:04:02'
h2_ip = '192.168.1.3'
h2_mac = '00:00:00:00:01:03'
h1_mac= '00:00:00:00:01:02'
h3_mac= '00:00:00:00:02:02'
s2_s1a_mac= '00:00:00:00:01:01'#S1ETH1_MAC
s1a_s1b_mac='00:00:00:00:03:01'
s3_s1b_mac= '00:00:00:00:02:01'#S1ETH2_MAC
s1b_s1a_mac='00:00:00:00:03:02'


ETH1_IP = "192.168.1.1"
ETH2_IP = "192.168.2.1"

#LEFT ROUTER LEFT IP-MAC
LR_LEFT_MAC = "00:00:00:00:01:01"

#LEFT ROUTER RIGTH MAC
LR_RIGHT_MAC = "00:00:00:00:03:01"

RR_LEFT_MAC = "00:00:00:00:03:02"
RR_RIGHT_MAC= "00:00:00:00:02:01"

dpid_to_name = {
	'26':'LEFT_ROUTER',
	'27':'RIGHT_ROYTER',
	'3':'S3',
	'2':'S2'
}

mac_to_name = {
	'00:00:00:00:01:02':'H1',
	'00:00:00:00:01:03':'H2',
	'00:00:00:00:02:02':'H3',
	'00:00:00:00:02:03':'H4',
	'00:00:00:00:04:02':'H5',
	'00:00:00:00:01:01':'LR_LEFT_MAC',
	'00:00:00:00:03:01':'LR_RIGHT_MAC',
	'00:00:00:00:03:02':'RR_LEFT_MAC',
	'00:00:00:00:02:01':'RR_RIGHT_MAC',
	'00:00:00:00:04:01':'H5_S1a_MAC',
	'ff:ff:ff:ff:ff:ff':'Broadcast(ff.ff...)'
}

src_to_mac = {
	'192.168.1.2':'00:00:00:00:01:02',
	'192.168.1.3':'00:00:00:00:01:03',
	'192.168.2.2':'00:00:00:00:02:02',
	'192.168.2.3':'00:00:00:00:02:03',
	'200.0.0.2':'00:00:00:00:04:02',
}
NAT_SRC= 'None'


class SimpleSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch, self).__init__(*args, **kwargs)
		self.mac_to_port = {}

	def add_flow(self, datapath, match, actions):
		ofproto = datapath.ofproto

		mod = datapath.ofproto_parser.OFPFlowMod(
			datapath=datapath, match=match, cookie=0,
			command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
			priority=ofproto.OFP_DEFAULT_PRIORITY,
			flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		dpid = datapath.id
		ofproto = datapath.ofproto

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)

		dst = eth.dst
		src = eth.src

		self.mac_to_port.setdefault(dpid, {})
		self.loggerInfo_pretty("packet in %s %s -> %s %s", dpid, src, dst, msg.in_port)

#		self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[dpid][src] = msg.in_port

		if dpid == 0x1A:
			if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
				arp_pkt = pkt.get_protocol(arp.arp)		
				if arp_pkt.opcode == arp.ARP_REQUEST:#request
					if arp_pkt.dst_ip == ETH1_IP:
						print('packet from s2')
						self.send_arp_reply( datapath, 
									LR_LEFT_MAC,ETH1_IP,
								   arp_pkt.src_mac,arp_pkt.src_ip, 2)
					elif arp_pkt.dst_ip == h5_s1a_ip:
						print("Should i do anything?{}",arp_pkt.dst_ip)
						print(arp_pkt.src_ip)
						NAT_SRC = arp_pkt.src_ip
						self.send_arp_reply( datapath, 
									h5_mac,ETH1_IP,
								   arp_pkt.src_mac,arp_pkt.src_ip, 2)

				return
			elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
				ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
				icmp_pkt = pkt.get_protocol(icmp.icmp)
				eth_pkt = pkt.get_protocol(ethernet.ethernet)
				
				#Destined to Left LAN
				if ipv4_pkt.dst.startswith('192.168.1'):
					nw_dst = h1_ip
					if ipv4_pkt.dst == h2_ip:
						nw_dst = h2_ip
					match = datapath.ofproto_parser.OFPMatch(in_port=1,dl_type=0x0800,nw_dst=nw_dst)#,dl_src = RR_LEFT_MAC)
	                                        #nw_dst='192.168.1.0')
					actions = [datapath.ofproto_parser.OFPActionSetDlSrc(LR_RIGHT_MAC),
							datapath.ofproto_parser.OFPActionSetDlDst(LR_LEFT_MAC),
								datapath.ofproto_parser.OFPActionOutput(2)]
					self.add_flow(datapath,match,actions)

				#Destined to Right LAN
				if ipv4_pkt.dst.startswith('192.168.2'):
					nw_dst = h3_ip
					if ipv4_pkt.dst == h4_ip:
						nw_dst = h4_ip
					match = datapath.ofproto_parser.OFPMatch(in_port=2,dl_type=0x0800,nw_dst=nw_dst)#,dl_src = RR_LEFT_MAC)
	                                        #nw_dst='192.168.1.0')
					actions = [datapath.ofproto_parser.OFPActionSetDlSrc(LR_RIGHT_MAC),
							datapath.ofproto_parser.OFPActionSetDlDst(RR_LEFT_MAC),
								datapath.ofproto_parser.OFPActionOutput(1)]
					self.add_flow(datapath,match,actions)
				
				return
			return
		if dpid == 0x1B:
			if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
				arp_pkt = pkt.get_protocol(arp.arp)		
				if arp_pkt.opcode == arp.ARP_REQUEST:#request
					if arp_pkt.dst_ip == ETH2_IP:
						print('packet from s3')
						self.send_arp_reply( datapath, 
									RR_RIGHT_MAC,ETH2_IP,
								   arp_pkt.src_mac,arp_pkt.src_ip, 2)
				return
			elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
				ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
				icmp_pkt = pkt.get_protocol(icmp.icmp)
				eth_pkt = pkt.get_protocol(ethernet.ethernet)
				#Destined to Left LAN
				if ipv4_pkt.dst.startswith('192.168.1'):
					nw_dst = h1_ip
					if ipv4_pkt.dst == h2_ip:
						nw_dst = h2_ip
					match = datapath.ofproto_parser.OFPMatch(in_port=2,dl_type=0x0800,nw_dst=nw_dst)#,dl_src = RR_LEFT_MAC)
	                                        #nw_dst='192.168.1.0')
					actions = [datapath.ofproto_parser.OFPActionSetDlSrc(LR_RIGHT_MAC),
							datapath.ofproto_parser.OFPActionSetDlDst(LR_LEFT_MAC),
								datapath.ofproto_parser.OFPActionOutput(2)]
					self.add_flow(datapath,match,actions)

				#Destined to Right LAN
				if ipv4_pkt.dst.startswith('192.168.2'):
					nw_dst = h3_ip
					if ipv4_pkt.dst == h4_ip:
						nw_dst = h4_ip
					match = datapath.ofproto_parser.OFPMatch(in_port=2,dl_type=0x0800,nw_dst=nw_dst)#,dl_src = RR_LEFT_MAC)
	                                        #nw_dst='192.168.1.0')
					actions = [datapath.ofproto_parser.OFPActionSetDlSrc(LR_RIGHT_MAC),
							datapath.ofproto_parser.OFPActionSetDlDst(RR_LEFT_MAC),
								datapath.ofproto_parser.OFPActionOutput(1)]
					self.add_flow(datapath,match,actions)
				
				
				return
			return	 
		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofproto.OFPP_FLOOD

		match = datapath.ofproto_parser.OFPMatch(
			in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

		actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

		# install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:
			self.add_flow(datapath, match, actions)

		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = datapath.ofproto_parser.OFPPacketOut(
			datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
			actions=actions, data=data)
		datapath.send_msg(out)

	def send_arp_reply(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
		e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
		a = arp.arp(1, 0x0800, 6, 4, 2, srcMac, srcIp, dstMac, dstIp)
		p = packet.Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()

		actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
		out = datapath.ofproto_parser.OFPPacketOut(
			datapath=datapath,
			buffer_id=0xffffffff,
			in_port=datapath.ofproto.OFPP_CONTROLLER,
			actions=actions,
			data=p.data)
		datapath.send_msg(out)

	@set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
	def _port_status_handler(self, ev):
		msg = ev.msg
		reason = msg.reason
		port_no = msg.desc.port_no

		ofproto = msg.datapath.ofproto
		if reason == ofproto.OFPPR_ADD:
			self.logger.info("port added %s", port_no)
		elif reason == ofproto.OFPPR_DELETE:
			self.logger.info("port deleted %s", port_no)
		elif reason == ofproto.OFPPR_MODIFY:
			self.logger.info("port modified %s", port_no)
		else:
			self.logger.info("Illeagal port state %s %s", port_no, reason)
	def loggerInfo_pretty(self,text, dpid, src, dst, port):
		self.logger.info(text, dpid_to_name[str(dpid)],mac_to_name[src],mac_to_name[dst],port) 


