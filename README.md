# GossipMaximus
A Comprehensible Ryu-based metrics collector SDN application
---------------------------------------------------------------

## Structure

GossipMaximus is the name given to a bundle of Python Classes using the Ryu API.

The kernel is called GossipBase, and it handles most of the basic Openflow switch events: ofp_event.EventOFPSwitchFeatures, handles ARP requests and replies, and writes the default flow entry on each Openflow switch. When the Ryu application is executed, you should run:

usr@pc:$ ryu-manager GossipBase.py

GossipBase fires other applications through Ryu's CONTEXTS dictionary, and holds instances of them. These are: GossipTop, GossipMonitor, and Ryu's WSGIApplication for providing a REST API through GossipBase. GossipMonitor is passed the active instance of GossipTop; this is because GossipMonitor's results often call GossipTop's methods (like writing values in some of the tables).

GossipTop is my particular application for a given experiment. It sits on top of GossipBase and uses a GossipTable Class, which basically defines and holds all the tables that are going to be used throughout the application (ARP, mac_to_port, port_congestion, port_rtt, and many others). As GossipTop is my application, all (appropriate) GossipMaximus Classes should be able to view or edit these tables.

GossipMonitor functions are to register changes in the number of datapaths (Openflow switches waking up or dying), and to query the network for desirable metrics. At this moment, GossipMonitor creates two threads:

Monitor: generates periodic parser.OFPPortStatsRequest. The responses (in form of ofp_event.EventOFPPortStatsReply) are catched and processed by a GossipInterpreter Class (which holds no special code, just for data interpretation. It may be useful for understanding the structure of ofp_event.EventOFPPortStatsReply, though).
DelayGossip: this thread periodically calls GossipTop._send_gossip_message_now(datapath). The aforementioned method builds ICMP messages for all of datapath's output ports with different ICMP codes to differentiate them. Then, registers the RTT between requests and replies to build an overall RTT estimation per path.

##Code

I think that with this basic description you may start looking at the code. More importantly, you must remember that I am assuming that all predefined values, like: datapath IDs, MAC addresses, IP addresses, port numbers, and others, are based on my specific topology that runs a specific experiment. Hopefully with this post you will now be able to understand what you see at the Github repository.
