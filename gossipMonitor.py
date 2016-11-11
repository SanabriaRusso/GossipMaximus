from operator import attrgetter

import gossipTop
import gossipInterpreter

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.base import app_manager

from ryu.lib import hub

#python libraries
import re

SOURCE_DATAPATH = 258

class GossipMonitor(app_manager.RyuApp):
    """A class that starts a thread to generate queries to datapaths,
    but also generates ICMP packets to measure end-to-end delay from source
    to server"""

    def __init__(self, *args, **kwargs):
        """Initialization"""
        
        super(GossipMonitor, self).__init__()
        self.name = 'gossipMonitor'
        self.datapaths = {}
        self.start_measuring_rtt = False
        
        # this will hold the GossipTop instances being used from self._boot()
        self.gossip = None

        #thread for queriyng switches
        self.monitor_thread = hub.spawn(self._monitor)
        self.monitor_interpreter = gossipInterpreter.GossipInterpreter()

        #thread for generating ICMP packets and determine end-to-end delay
        self.delay_thread = hub.spawn(self._delayGossip)

        self.sleep_time = 1

        self.show_output = False

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """being aware of datapaths waking up or dying"""

        datapath = ev.datapath
        dpid = int(str(datapath.id))

        if ev.state == MAIN_DISPATCHER:
            if not dpid in self.datapaths:
                self.datapaths[dpid] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if dpid in self.datapaths:
                del self.datapaths[dpid]

    def _monitor(self):
        """thread querying datapaths for port and flow metrics"""

        _sleep = self.sleep_time
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(_sleep)

    def _delayGossip(self):
        """triggering ICMP packets every second to measure RTT"""

        _sleep = self.sleep_time * 2

        while True:
            if self.start_measuring_rtt == True:
                self._send_gossip_request()      

            hub.sleep(_sleep)

    def _send_gossip_request(self):
        """calling GossipTop so it can send ICMP packages"""

        if SOURCE_DATAPATH not in self.datapaths:
            return
        
        self.gossip._send_gossip_message_now(self.datapaths[SOURCE_DATAPATH])


    def _request_stats(self, datapath):
        """querying members of self.datapaths"""

        # send stats request
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """handling the response of the datapaths"""

        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        self.monitor_interpreter.update_port_output_rate(self.sleep_time, dpid, body)
        
        for datapath in self.monitor_interpreter.congestion_table:
            # filling GossipTables
            for port, condition in self.monitor_interpreter.congestion_table[datapath].items():
                self.gossip.tables.port_conditions[datapath][port] = condition
                if self.show_output:
                    print ("--->[%s] GossipMonitor: Port %s, condition: %s" % (datapath, port, condition))

            for port, rate in self.monitor_interpreter.rate_of_port[datapath].items():
                self.gossip.tables.port_output_rate[datapath][port] = rate

                # registering the ports of the datapath
                if port not in self.gossip.tables.datapaths_ports[datapath]:
                    self.gossip.tables.datapaths_ports[datapath].append(port)
                    self.start_measuring_rtt = True

    #-------------------------------------------------------------------
    # PRIVATE METHODS ( RELATED TO GOSSIP )
    #-------------------------------------------------------------------

    def _boot(self, gossipInstance):
        """Loggin initialization of class"""

        print "---> GossipMonitor started"
        self.gossip = gossipInstance
