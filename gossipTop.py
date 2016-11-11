from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, icmp, udp, tcp
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import in_proto as ip_proto

#custom libraries
import presentation
import gossipTables

#python libraries
from sets import Set
from datetime import datetime

BROADCAST = 'ff:ff:ff:ff:ff:ff'
MAX_ARRAY_LENGTH = 10000
GOSSIP_ICMP_ID_DEFAULT = 10
GOSSIP_ICMP_ID_ALTERNATE = 11

#-------------------------------------------------------------------
	# CUSTOM EVENTS
#-------------------------------------------------------------------
class EventPacketIn(event.EventBase):
	"""Sending a packet_in event to listeners (GossipBase)"""

	def __init__(self, msg):
		"""initialization"""

		super(EventPacketIn, self).__init__()
		self.msg = msg

#-------------------------------------------------------------------
	# GOSSIP CLASS
#-------------------------------------------------------------------

class GossipTop(app_manager.RyuApp):
	"""Adjusting the forwarding path"""
	
	def __init__(self):
		"""initialization"""

		super(GossipTop, self).__init__()
		self.name = 'gossipTop'
		self._press = presentation.Presentation()
		self.tables = gossipTables.GossipTables()

		self.request_reply_delay = {}

		self.idle_timeout = 10
		self.debug = False
		self.icmp_codes_per_out_port = {1 : GOSSIP_ICMP_ID_DEFAULT, 
										2 : GOSSIP_ICMP_ID_ALTERNATE}

	#-------------------------------------------------------------------
	# PUBLIC METHODS ( EVENT HANDLERS )
	#-------------------------------------------------------------------
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		"""If ARP, sending an event to observers, otherwise it will be routed to 
		corresponding methods by self._event_router"""

		msg = ev.msg
		dpid = msg.datapath.id
		pkt = packet.Packet(msg.data)
		pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
		pkt_arp = pkt.get_protocol(arp.arp)
		pkt_icmp = pkt.get_protocol(icmp.icmp)

		if pkt_arp or pkt_eth.dst == BROADCAST:
			# notify observers of ARP requests or L2 broadcast frames
			self.send_event_to_observers(EventPacketIn(msg))
		else:
			if pkt_icmp:
				# catching the reply of GossipDelay in form of a ICMP reply message with predefined ICMP ID
				if pkt_icmp.type == icmp.ICMP_ECHO_REPLY and pkt_icmp.data.id in self.icmp_codes_per_out_port.values():
					self._handle_gossip_rtt_estimation(pkt_icmp.data.id, dpid)
					return
			self._event_router(msg)


	#-------------------------------------------------------------------
	# PRIVATE METHODS ( RELATED TO GOSSIP )
	#-------------------------------------------------------------------
	def _boot(self):
		"""Logging the initialization of the gossipTop class"""
		print "---> Started GossipTop class"

	def _event_router(self, msg):
		"""Decide what to do"""
		
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		dpid = datapath.id
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]
		ip = pkt.get_protocol(ipv4.ipv4)
		icmp_pkt = pkt.get_protocol(icmp.icmp)

		dst = eth.dst
		src = eth.src 

		self._press.showPkt(dpid, src, dst, in_port)

		if ip:
			if (dpid == self.tables.ovsk_dpid) and (ip.dst == self.tables.ovsk_server_ip):
				self._create_path(in_port, pkt, eth, ip, datapath, msg)
			elif dpid == self.tables.ovsk_server_dpid:
				self._bouncer(in_port, pkt, eth, ip, datapath, msg)
		else:
			self._press.ipFailure(dpid, src, dst, in_port)
			return

	def _create_path(self, in_port, pkt, eth, ip, datapath, msg):
		"""Creating the path towards server"""

		dpid = datapath.id
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		out_port = None
		dst_to = None
		hard_timeout = 0
		idle_timeout = self.idle_timeout 

		l4_seg = pkt.get_protocol(udp.udp)
		icmp_pkt = pkt.get_protocol(icmp.icmp)

		if self.tables.default_path == True:
			dst_to = self.tables.default_path_mac
			out_port = self.tables.default_path_port
		else:
			(dst_to, out_port) = self._find_suitable_path(datapath, pkt, l4_seg, icmp_pkt)
			print "--->[%s] GossipTop: suitable path through mac: %s, port: %s" % (dpid, dst_to, out_port)


		if l4_seg:
			# we determine destination based on GossipMonitor's info
			port = l4_seg.dst_port
			print "--->[%s] GossipTop: L4 segment captured: %s" % (dpid, port)
			if port not in self.tables.all_ports:
				print "--->[%s] GossipTop: L4 port %s not on any experiment set" % (dpid, port)
				return
			elif port in self.tables.badwidth_hungry_ports:
				print "--->[%s] GossipTop: L4 port %s requires bandwidth" % (dpid, port)
			else:
				print "--->[%s] GossipTop: L4 port %s is sensitive to delay" % (dpid, port)



		if dpid not in self.tables.mac_to_port:
			self.tables.mac_to_port[dpid] = {dst_to : out_port}
		else:
			self.tables.mac_to_port[dpid][dst_to] = out_port

		#actions to reach Server
		actions_to = [parser.OFPActionSetField(eth_dst=dst_to),
						parser.OFPActionOutput(port=self.tables.mac_to_port[dpid][dst_to])]

		#matching packets to Server
		if icmp_pkt:
			match_to = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
										ipv4_dst=ip.dst,
										ip_proto=ip_proto.IPPROTO_ICMP,
										icmpv4_type=icmp.ICMP_ECHO_REQUEST)
		elif l4_seg:
			match_to = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
										ipv4_dst=ip.dst,
										ip_proto=ip_proto.IPPROTO_UDP,
										udp_dst=port)
		else:
			match_to = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
										ipv4_dst=ip.dst)


		###############################################################################
		# now doing the reverse path
		###############################################################################
		dst_local = eth.src

		#writing the port towards the source
		self.tables.mac_to_port[dpid][dst_local] = in_port

		#actions to reach the source
		actions_local = [parser.OFPActionOutput(port=self.tables.mac_to_port[dpid][dst_local])]

		#matching packets to the source
		if icmp_pkt:
			match_local = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
											ipv4_dst=ip.src,
											ip_proto=ip_proto.IPPROTO_ICMP,
											icmpv4_type=icmp.ICMP_ECHO_REPLY)
		elif l4_seg:
			rev_port = l4_seg.src_port
			match_local = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
											ipv4_dst=ip.src,
											ip_proto=ip_proto.IPPROTO_UDP,
											udp_dst=rev_port)
		else:
			match_local = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
											ipv4_dst=ip.src)

		# flow_mod & packet_out
		self._add_flow(datapath, 1, match_to, actions_to, idle_timeout, hard_timeout)
		self._add_flow(datapath, 1, match_local, actions_local, idle_timeout, hard_timeout)

		data = None
		if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath,
									buffer_id=msg.buffer_id,
									in_port=ofproto.OFPP_IN_PORT,
									actions=actions_to,
									data=data)
		datapath.send_msg(out)

	def _find_suitable_path(self, datapath, pkt, l4_seg, icmp_pkt):
		"""if GossipMonitor is used, we check the packet protocol, and
		if the case, port, and cross it with the information we are gathering
		to determine the output port"""
		
		dpid = datapath.id
		dst_to = self.tables.default_path_mac
		out_port = self.tables.default_path_port

		""" 
		as all traffic depends on the condition of the port,
		we check it here: True: too busy, False: ok
		"""

		if self.tables.port_conditions[dpid][out_port] == True:
			for port, condition in self.tables.port_conditions[dpid].items():
				if port > 2:
					# ignoring OFPP_LOCAL
					continue

				if condition == False:
					out_port = port
					dst_to = self.tables.ovsk_out_port_and_dest_mac[out_port]
					return (dst_to, out_port)

			""" if there is no clear option, we pick the link with lower load """
			_ref_load = 1e9
			_ref_port = out_port
			for port, rate in self.tables.port_output_rate[dpid].items():
				if rate < _ref_load:
					_ref_load = rate
					_ref_port = port

			out_port = _ref_port
			dst_to = self.tables.ovsk_out_port_and_dest_mac[out_port]

			print "--->[%s] GossipTop: no better path was found. Using alternate port %s, dst_mac: %s" % (dpid, out_port, dst_to)
		else:
			print "--->[%s] GossipTop: using default port %s, dst_mac: %s" % (dpid, out_port, dst_to)
	
		return (dst_to, out_port)

	def _bouncer(self, in_port, pkt, eth, ip, datapath, msg):
		"""Bouncing back ACKs from the port they came in"""

		dpid = datapath.id
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		out_port = None
		dst_to = None
		hard_timeout = 0
		idle_timeout = 2

		dst_local = eth.src
		dst_to = eth.dst    

		l4_seg = pkt.get_protocol(udp.udp)
		icmp_pkt = pkt.get_protocol(icmp.icmp)

		#saving mac and port to our table
		if dpid not in self.tables.mac_to_port:
			self.tables.mac_to_port[dpid] = {dst_local : in_port}
		else:
			self.tables.mac_to_port[dpid][dst_local] = in_port

		if dst_to == self.tables.ovsk_server_mac:
			out_port = ofproto.OFPP_LOCAL
			self.tables.mac_to_port[dpid][dst_to] = out_port
		elif dst_to not in self.tables.mac_to_port[dpid]:
			print "--->[%s] GossipTop: unknown destination MAC address" % dpid
			return

		#actions to reach Server
		actions_to = [parser.OFPActionOutput(port=self.tables.mac_to_port[dpid][dst_to])]  

		#matching packets to Server
		if icmp_pkt:
			match_to = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
										ipv4_dst=ip.dst,
										ip_proto=ip_proto.IPPROTO_ICMP,
										icmpv4_type=icmp.ICMP_ECHO_REQUEST,
										icmpv4_code=icmp_pkt.code)
		elif l4_seg:
			l4_port = l4_seg.dst_port
			print "--->[%s] GossipTop: L4 segment, to IP: %s, dest_port: %s" % (dpid, ip.dst, l4_port)
			match_to = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
										ipv4_dst=ip.dst,
										ip_proto=ip_proto.IPPROTO_UDP,
										udp_dst=l4_port,
										in_port=in_port)
		else:
			match_to = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
										ipv4_dst=ip.dst)

		###############################################################################
		# now doing the bouncing part
		###############################################################################
		
		#actions to reach the source
		actions_local = [parser.OFPActionSetField(eth_dst=dst_local),
							parser.OFPActionOutput(port=self.tables.mac_to_port[dpid][dst_local])]

		#matching packets to the source
		if icmp_pkt:
			match_local = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
											ipv4_dst=ip.src,
											ip_proto=ip_proto.IPPROTO_ICMP,
											icmpv4_type=icmp.ICMP_ECHO_REPLY,
											icmpv4_code=icmp_pkt.code)
		elif l4_seg:
			rev_port = l4_seg.src_port
			print "--->[%s] GossipTop: L4 segment, to IP: %s, dest_port: %s" % (dpid, ip.src, rev_port)
			match_local = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
											ipv4_dst=ip.src,
											ip_proto=ip_proto.IPPROTO_UDP,
											udp_dst=rev_port)
		else:
			match_local = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
											ipv4_dst=ip.src)

		# flow_mod & packet_out
		self._add_flow(datapath, 1, match_to, actions_to, idle_timeout, hard_timeout)
		self._add_flow(datapath, 1, match_local, actions_local, idle_timeout, hard_timeout)


		data = None
		if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath,
									buffer_id=msg.buffer_id,
									in_port=ofproto.OFPP_IN_PORT,
									actions=actions_to,
									data=data)
		datapath.send_msg(out)

	def _add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, buffer_id=None):
		"""Adding a flow. As this is only intended for the Gossip experiment, 
		we write relevant flows in this library"""

		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		if 'in_port' in match:
			_in_port = match['in_port']
			_ip_dst = match['ipv4_dst']	
			self._press.flowAdded(datapath, _in_port, _ip_dst)

		self._press.generalFlowAdded(datapath.id, match)

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

		mod = parser.OFPFlowMod(datapath=datapath,
								idle_timeout=idle_timeout,
								priority=priority,
								match=match,
								instructions=inst,
								hard_timeout=hard_timeout)
		datapath.send_msg(mod)

	#-------------------------------------------------------------------
	# PRIVATE METHODS ( RELATED TO MONITOR )
	#-------------------------------------------------------------------

	def _send_gossip_message_now(self, dp):
		"""being called from GossipMonitor. Sending ICMP messages an measuring RTT.
		The response is then catched at packet_in_handler to derive the RTT"""

		if dp.id != self.tables.ovsk_dpid:
			# only sending gossip messages from ovsk to ovsk_server
			return

		dpid = dp.id
		parser = dp.ofproto_parser
		ofproto = dp.ofproto

		# creating the ICMP Request
		for port in self.tables.datapaths_ports[dpid]:
			if port == ofproto.OFPP_LOCAL:
				# omitting OFPP_LOCAL
				continue

			ping = packet.Packet()

			ping.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP,
												dst=self.tables.ovsk_out_port_and_dest_mac[port],
												src=self.tables.ovsk_mac))
			
			ping.add_protocol(ipv4.ipv4(dst=self.tables.ovsk_server_ip,
										src=self.tables.ovsk_ip,
										proto=ip_proto.IPPROTO_ICMP))

			ping.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REQUEST,
										code=self.icmp_codes_per_out_port[port],
										csum=0,
										data=icmp.echo(id_=self.icmp_codes_per_out_port[port], 
														seq=0, 
														data=None)))

			# sending the message

			ping.serialize()
			# print "--->[%s] Sending gossip ICMP packet:\n\t--->%s\n" % (dp.id, ping)
			data = ping.data

			actions = [parser.OFPActionOutput(port=port)]

			out = parser.OFPPacketOut(datapath=dp,
										actions=actions,
										in_port=ofproto.OFPP_CONTROLLER,
										buffer_id=ofproto.OFP_NO_BUFFER,
										data=data)

			self.request_reply_delay[self.icmp_codes_per_out_port[port]] = datetime.now().microsecond
			dp.send_msg(out)


	def _handle_gossip_rtt_estimation(self, icmp_id, dpid):
		"""updating the average rtt"""

		if self.request_reply_delay[icmp_id] < datetime.now().microsecond:
			dif = abs(datetime.now().microsecond - self.request_reply_delay[icmp_id])

			if icmp_id not in self.tables.gossip_average_delay[dpid].keys():
				self.tables.gossip_average_delay[dpid].setdefault(icmp_id, [])
		
			self.tables.gossip_average_delay[dpid][icmp_id].append(dif)
			self.request_reply_delay[icmp_id] = None

			if (self.debug):
				self._show_rtt_per_port()
		else:
			return

		# to avoid having a too big array
		self._check_length_of_gossip_average_delay_array()

	def _check_length_of_gossip_average_delay_array(self):
		""" 
		checking if the average delay array is bigger than the threshold,
		if so, then leave the average as the only value
		"""

		for dpid in self.tables.gossip_average_delay:
			if dpid != self.tables.ovsk_dpid:
				continue

			for icmp_code in self.tables.gossip_average_delay[dpid]:
				l = self.tables.gossip_average_delay[dpid][icmp_code]
				if len(l) >= MAX_ARRAY_LENGTH:
					_new = sum(l) / float(len(l))
					self._reset_average_delay()
					self.tables.gossip_average_delay[dpid][icmp_code].append(_new)
				else:
					continue


	#### Debugging functions
	def _show_rtt_per_port(self):
		""" it does just that when debug is on. Otherwise returns a {port:avgRTT} dict"""

		rtt = {}
		for path in self.tables.gossip_average_delay[self.tables.ovsk_dpid]:
			l = self.tables.gossip_average_delay[self.tables.ovsk_dpid][path]
			
			if len(l) <= 0:
				l.append(0)

			avg = sum(l) / float(len(l))
			rtt[path] = avg

		return rtt

		# just useful with debugging
		if self.debug:
			for path, delay in rtt.items():
				print "ALARM::::: path: %s, rtt: %s" % (path, delay)


	#### REST functions need to be modified for handling multiple RTT paths
	def _get_recent_delay(self):
		"""it returns a dictionary with {port:avgRTT}"""

		rtt = {}
		for path in self.tables.gossip_average_delay[self.tables.ovsk_dpid]:
			if len(self.tables.gossip_average_delay[self.tables.ovsk_dpid][path]) > 0:
				rtt[path] = self.tables.gossip_average_delay[self.tables.ovsk_dpid][path][-1]
			else:
				rtt[path] = 0

		return (rtt)

	def _reset_average_delay(self):
		"""Method for resetting self.gossip_average_delay"""

		for dpid in self.tables.gossip_average_delay:
			if dpid != self.tables.ovsk_dpid:
				continue

			for path in self.tables.gossip_average_delay[dpid]:
				self.tables.gossip_average_delay[dpid][path][:] = []