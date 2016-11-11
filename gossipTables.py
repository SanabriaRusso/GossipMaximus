#python libraries
import re
from sets import Set

class GossipTables(object):
    """Holding tables for the experiment"""
    
    def __init__(self):
        """initialization."""
        super(GossipTables, self).__init__()
        self.name = 'gossipTables'
        self.mac_to_port = {}
        self.default_arp_table = {}
        self.datapaths_ports = {}

        # variables determining the path to follow, these are updated by gossipMonitor.py
        self.default_path = False
        self.port_conditions = {}
        self.port_output_rate = {}

        self.default_path_port = 1
        self.alternate_path_port = 2

        self.mac_of_experiment = ['00:00:00:00:01:02', 
                                  '00:00:00:00:01:03', 
                                  '00:00:00:00:21:03',
                                  '00:00:00:00:01:06', 
                                  '00:00:00:00:21:06', 
                                  '00:00:00:00:01:10', 
                                  '00:00:00:00:31:06',
                                  '00:00:00:00:21:10']
        
        # identifying the both ends of the communication for the experiment
        self.ovsk_ip = '10.1.14.102'
        self.ovsk_mac = self.mac_of_experiment[0]
        
        self.ovsk_server_ip = '12.1.14.106'
        self.ovsk_server_mac = self.mac_of_experiment[3]
                
        self.default_path_ip = '10.1.14.110'
        self.default_path_mac = self.mac_of_experiment[5]
        
        self.reverse_default_ip = '12.1.14.110'
        self.reverse_default_mac = self.mac_of_experiment[7]
        
        self.alternate_path_ip = '10.1.14.103'
        self.alternate_path_mac = self.mac_of_experiment[1]
        
        self.reverse_alternate_ip = '12.1.14.103'
        self.reverse_alternate_mac = self.mac_of_experiment[2] 
        
        self.ovsk_dpid = int(re.sub('[:]', '', self.ovsk_mac), 16)
        self.ovsk_server_dpid = int(re.sub('[:]', '', self.ovsk_server_mac), 16)
        self.switches_dpid_to_mac = {self.ovsk_dpid : self.ovsk_mac,
                                     self.ovsk_server_dpid : self.ovsk_server_mac}

        self.ovsk_out_port_and_dest_mac = {self.default_path_port : self.default_path_mac,
                                            self.alternate_path_port: self.alternate_path_mac}

        """ for the sake of the experiment, we keep a pool of UDP ports
        that are going to be used to point to iPerf servers in ovsk_server"""
        self.all_ports = Set([9990, 9991, 9992, 9993, 9994, 9995, 9996, 9997, 9998, 9999])
        self.badwidth_hungry_ports = Set([9990, 9991, 9992, 9993, 9994, 9995])
        self.delay_sensitive_ports = Set([9996, 9997, 9998, 9999])


        # Related to the GossipDelay
        self.gossip_average_delay = {}

    def boot(self):
        """Initialization"""

        print "---> GossipTables defined"
    