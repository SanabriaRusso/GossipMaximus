from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp

# REST related libraries
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import json
from webob import Response
from ryu.lib import dpid as dpid_lib

#custom libraries
import presentation
import gossipTop
import gossipMonitor

delay_url = '/gossipTop/delay/{dpid}'
reset_url = '/gossipTop/resetDelay/{dpid}'
gossip_instance_name = 'gossip_instance'

#-------------------------------------------------------------------
    # REST API CLASS AND METHODS
#-------------------------------------------------------------------
class GossipController(ControllerBase):
    """Getting REST messages by querying GossipTop"""

    def __init__(self, req, link,  data, **config):
        """getting an instance of GossipTop via wsig's 'data' constructor.
        The apropriate controlled class is stored in this array, defined at
        its __init__() methods"""

        super(GossipController, self).__init__(req, link, data, **config)
        self.gossip_instance = data[gossip_instance_name]

    @route('gossipTop', delay_url, methods=['GET'], requirements={})
    def get_average_delay(self, req, **kwargs):
        """getting the last value of the average delay array (microseconds)"""

        gossip = self.gossip_instance
        dpid = int(kwargs['dpid'])
        delay = {}

        if dpid != gossip._gossipTop.tables.ovsk_dpid:
            print "--->[FAIL] GossipController: dpid %s is not registered" % (dpid)
            return Response(status=404)
        else:
            delay = gossip._gossipTop._get_recent_delay()
            print "--->[%s] GossipController: last observed average delay:" % (dpid)
            for path, rtt in delay.items():
                print "\tPath: %s, RTT: %s" % (path, rtt)
            body = json.dumps(delay)
            return Response(content_type='application/json', body=body)

    @route('gossipTop', reset_url, methods=['PUT'], requirements={})
    def reset_delay_measures(self, req, **kwargs):
        """resets the contents of the average delay array in GossipTop"""

        gossip = self.gossip_instance
        dpid = int(kwargs['dpid'])
        delay = {}

        if dpid != gossip._gossipTop.tables.ovsk_dpid:
            print "--->[FAIL] GossipController: dpid %s is not registered" % (dpid)
            return Response(status=404)
        else:
            gossip._gossipTop._reset_average_delay()

            delay = gossip._gossipTop._get_recent_delay()
            print "--->[%s] GossipController: average delay array is cleared:" % (dpid)
            
            for path, rtt in delay.items():
                print "\tPath: %s, RTT: %s" % (path, rtt)
            body = json.dumps(delay)

            return Response(content_type='application/json', body=body)
#-------------------------------------------------------------------
    # GOSSIP CLASS
#-------------------------------------------------------------------

class GossipBase(app_manager.RyuApp):
    """The base of a Gossip Maximus instance, just a simple switch for Exp6"""
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'gossipTop' : gossipTop.GossipTop, 'gossipMonitor' : gossipMonitor.GossipMonitor, 
                'wsgi' : WSGIApplication}

    def __init__(self, *args, **kwargs):
        """Initialization"""
        
        super(GossipBase, self).__init__(*args, **kwargs)
        self._gossipTop = kwargs['gossipTop']
        self._gossipTop._boot()

        self._gossipMonitor = kwargs['gossipMonitor']
        self._gossipMonitor._boot(self._gossipTop)

        self._press = presentation.Presentation()
        self._press.boot()
    
        # firing wsgi, and passing it to GossipTop to write code there
        self._wsgi = kwargs['wsgi']
        self._wsgi.register(GossipController, {gossip_instance_name:self})


    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """First message from a switch"""
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        print "--->[%s] Switch features" % datapath.id

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        
        self.add_flow_default(datapath, 0, match, actions) 
        
        # initializing tables
        self._gossipTop.tables.mac_to_port.setdefault(datapath.id, {})
        self._gossipTop.tables.default_arp_table.setdefault(datapath.id, {})
        self._gossipTop.tables.port_conditions.setdefault(datapath.id, {})
        self._gossipTop.tables.port_output_rate.setdefault(datapath.id, {})
        self._gossipTop.tables.datapaths_ports.setdefault(datapath.id, [])
        self._gossipTop.tables.gossip_average_delay.setdefault(datapath.id, {})

        print "--->[%s] Loading default value to tables" % datapath.id
        
        self._prefill_arp_table(datapath)
            
    def add_flow_default(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, buffer_id=None):
        """Adding a flow. Trying to keep it as general as possible"""
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if 'in_port' in match:
            _in_port = match['in_port']
            _ip_dst = match['ipv4_dst']
            self._press.flowAdded(datapath, _in_port, _ip_dst)
        else:
            self._press.matchAll(datapath.id, match)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, 
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath,
                                idle_timeout=idle_timeout,
                                priority=priority,
                                match=match, 
                                instructions=inst,
                                hard_timeout=hard_timeout)
        datapath.send_msg(mod)
        
    def _prefill_arp_table(self, dp):
        """Changes the arp table according to the test"""
        
        dpid = dp.id
        if dpid not in self._gossipTop.tables.switches_dpid_to_mac:
            # ignoring other switches
            return
        
        print "--->[%s] Filling ARP table" % dpid
        if dpid == self._gossipTop.tables.ovsk_dpid:
            self._gossipTop.tables.default_arp_table[dpid] = {self._gossipTop.tables.ovsk_ip : self._gossipTop.tables.ovsk_mac, 
                                                            self._gossipTop.tables.default_path_ip : self._gossipTop.tables.default_path_mac, 
                                                            self._gossipTop.tables.alternate_path_ip : self._gossipTop.tables.alternate_path_mac}
        elif dpid == self._gossipTop.tables.ovsk_server_dpid:
            self._gossipTop.tables.default_arp_table[dpid] = {self._gossipTop.tables.ovsk_server_ip : self._gossipTop.tables.ovsk_server_mac,
                                                            self._gossipTop.tables.reverse_default_ip : self._gossipTop.tables.reverse_default_mac,
                                                            self._gossipTop.tables.reverse_alternate_ip : self._gossipTop.tables.reverse_alternate_mac}
        
        print "\t--->[%s] ARP table: %s" % (dpid, self._gossipTop.tables.default_arp_table[dpid],)
        
    @set_ev_cls(gossipTop.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):        
        """Handling the arrival of a packet to the controller"""
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        
        dst = eth.dst
        src = eth.src
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        elif src not in self._gossipTop.tables.mac_of_experiment:
            # ignore transmitters outside experiment
            return
        
        # registering the accepted frame and incomming port
        self._gossipTop.tables.mac_to_port[dpid][src] = in_port
        if ip4_pkt:
            self._gossipTop.tables.default_arp_table[dpid][ip4_pkt.src] = src
        
        # Catching ARP requests
        if dst not in self._gossipTop.tables.mac_of_experiment:
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                pkt_arp = pkt.get_protocol(arp.arp)
                if pkt_arp:
                    print "--->[%s] Going to handle ARP request, in_port: %s" % (dpid, in_port)
                    self._handle_arp(datapath, in_port, eth, pkt_arp)
                else:
                    print "--->[%s] Void ARP request from: %s" % (dpid, src)
        else:
            self._press.showPkt(dpid, src, dst, in_port)
            
    def _handle_arp(self, dp, in_port, eth_pkt, pkt_arp):
        """Handling ARP request and providing a reply based on our table"""
        
        if pkt_arp.opcode != arp.ARP_REQUEST:
            # ignore all except ARP requests
            return
        elif pkt_arp.dst_ip not in self._gossipTop.tables.default_arp_table[dp.id]:
            print "--->[%s] ARP not in default table, dst: %s" % (dp.id, pkt_arp.dst_ip)
            return
        
        req_dst = pkt_arp.dst_ip
        print ("--->[%s] Handling ARP message from %s, asking for: %s" % (dp.id, eth_pkt.src, req_dst))
        
        # Creating an arp reply message
        # Starting with a common ethernet frame to requester
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
                                            dst=eth_pkt.src,
                                            src=self._gossipTop.tables.switches_dpid_to_mac[dp.id]))
        
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=self._gossipTop.tables.default_arp_table[dp.id][req_dst],
                                src_ip=req_dst,
                                dst_mac=pkt_arp.src_mac,
                                dst_ip=pkt_arp.src_ip))
        
        # updating local tables
        self._gossipTop.tables.default_arp_table[dp.id][pkt_arp.src_ip] = pkt_arp.src_mac
        self._gossipTop.tables.mac_to_port[dp.id][pkt_arp.src_mac] = in_port        
        
        self._send_arp_reply(dp, pkt, in_port)

    def _send_arp_reply(self, dp, pkt, port):
        """Sending a packet comming from _handle_arp"""
        
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        pkt.serialize()
        print ("--->[%s] Sending ARP reply: %s" % (dp.id, pkt,))
        
        data = pkt.data
        
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_IN_PORT)]
        
        out = parser.OFPPacketOut(datapath=dp,
                                 buffer_id=ofproto.OFP_NO_BUFFER,
                                 in_port=port,
                                 actions=actions,
                                 data=data)
        dp.send_msg(out)
        
        print "--->[%s] Sending through port: %s\n" % (dp.id, port)