# -*- coding: utf-8 -*-

#    Copyright (C) 2014 AT&T Labs All Rights Reserved.
#    Copyright (C) 2014 University of Pennsylvania All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Inception utilities"""
import logging
import os
import sys
import time
import struct
import md5
from collections import defaultdict
from collections import deque

from SimpleXMLRPCServer import SimpleXMLRPCServer
from xmlrpclib import ServerProxy
import socket

from kazoo import client
from oslo.config import cfg
import bidict

from ryu import log
from ryu.lib.dpid import str_to_dpid
from ryu.app import inception_dhcp as i_dhcp
from ryu.app import inception_priority as i_priority
from ryu.lib import hub
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.dhcp import dhcp
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.udp import udp
from ryu.ofproto import ether
from ryu.ofproto import inet

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('ip_prefix', 'ryu.app.inception_conf')
CONF.import_opt('dhcp_ip', 'ryu.app.inception_conf')
CONF.import_opt('dhcp_port', 'ryu.app.inception_conf')
CONF.import_opt('arp_timeout', 'ryu.app.inception_conf')
CONF.import_opt('zookeeper_storage', 'ryu.app.inception_conf')
CONF.import_opt('interdcenter_port_prefix', 'ryu.app.inception_conf')
CONF.import_opt('intradcenter_port_prefix', 'ryu.app.inception_conf')


class Topology(object):
    """
    Build switch level topology of Inception network.
    Gateway is assumed to have no local VMs connected.
    Topology is maintained as two dictionaries:
    """
    def __init__(self, gateway_ips=()):
        # {dpid_gw -> {dcenter_id -> port_no}}
        self.gateway_to_dcenters = defaultdict(dict)
        self.gateway_ips = gateway_ips
        self.gateways = []
        self.dhcp_switch = None
        self.dhcp_port = None
        # {local dpid -> {remote ip -> local port}}
        self.dpid_ip_to_port = defaultdict(dict)
        # {local ip -> local dpid}
        self.ip_to_dpid = bidict.bidict()

    @classmethod
    def topology_from_gateways(cls, gateway_ips_str):
        gateway_ips = str_to_tuple(gateway_ips_str)
        topology = cls(gateway_ips)
        return topology

    def update_switch(self, dpid_new, ip_new, ports):
        """Update switch topology"""

        self.ip_to_dpid[ip_new] = dpid_new
        LOGGER.info("Add: (switch=%s) -> (ip=%s)", dpid_new, ip_new)
        self.parse_switch_ports(dpid_new, ip_new, ports)
        if ip_new == CONF.dhcp_ip:
            self.dhcp_switch = dpid_new
            LOGGER.info("DHCP server switch: (ip=%s), (dpid=%s)", ip_new,
                        dpid_new)
        if ip_new in self.gateway_ips:
            self.gateways.append(dpid_new)
            LOGGER.info("Gateway switch: (ip=%s), (dpid=%s)", ip_new, dpid_new)

    def parse_switch_ports(self, dpid, ip, switch_ports):
        """Parse port name to extract connection information"""

        local_port_prefix = CONF.intradcenter_port_prefix
        remote_port_prefix = CONF.interdcenter_port_prefix
        for port in switch_ports:
            port_no = str(port.port_no)

            # Port_name: e.g., "obr_<ip_prefix>"
            if port.name.startswith(local_port_prefix) and '_' in port.name:
                peer_ip = self.extract_ip_addr(CONF.ip_prefix, port.name)
                LOGGER.info("Add: (switch=%s, peer_ip=%s) -> (port=%s)",
                            dpid, peer_ip, port_no)
                self.dpid_ip_to_port[dpid][peer_ip] = port_no

            # Port_name: e.g., "gateway_<dcenter_id>"
            elif port.name.startswith(remote_port_prefix):
                peer_dcenter = self.extract_dcenter(port.name)
                self.gateway_to_dcenters[dpid][peer_dcenter] = port_no
                LOGGER.info("New inter-datacenter connection:"
                            "(gateway=%s) -> (datacenter=%s)",
                            dpid, peer_dcenter)

            # Port name matches DHCP port
            if port.name == CONF.dhcp_port:
                self.dhcp_port = port_no

    def extract_ip_addr(self, ip_prefix, port_name):
        """Extract IP address from port name"""

        _, ip_suffix1, ip_suffix2 = port_name.split('_')
        peer_ip = '.'.join((ip_prefix, ip_suffix1, ip_suffix2))

        return peer_ip

    def extract_dcenter(self, port_name):
        """Extract datacenter id from port name"""

        _, dcenter_id = port_name.split('_')
        return dcenter_id

    def gateway_connected(self):
        """Check if any gateway is connected or not"""

        return self.gateways

    def is_gateway(self, dpid):
        """Check if dpid is gateway"""

        return (dpid in self.gateways)

    def get_gateways(self):
        return self.gateways

    def is_dhcp(self, dpid):
        """Check if dpid is dhcp server"""

        return dpid == self.dhcp_switch

    def get_fwd_port(self, dpid1, dpid2):
        ip_2 = self.ip_to_dpid[:dpid2]  # bidict reverse query
        port = self.dpid_ip_to_port[dpid1][ip_2]
        return port

    def get_dcenter_port(self, dpid_gw, dcenter):
        return self.gateway_to_dcenters[dpid_gw][dcenter]

    def get_neighbors(self, dpid):
        """Get neighbors in the form of {dpid_1: port_1, dpid_2, port_2, ...}.
        Skip neighbor switches not connected yet (i.e., not in self.ip_to_dpid)
        """

        ip_to_port = self.dpid_ip_to_port[dpid]
        dpid_to_port = {}
        for ip, port in ip_to_port.items():
            dpid = self.ip_to_dpid.get(ip)
            if dpid is not None:
                dpid_to_port[dpid] = port

        return dpid_to_port


class SwitchManager(object):
    """Manage openflow-switches"""
    SWITCH_MAXID = 65535

    def __init__(self, self_dcenter='0'):
        # Zookeeper data
        # Record all switches id assignment, to detect switch id conflict
        # {dcenter => {dpid => id}}
        self.dcenter_to_swcids = defaultdict(dict)

        # Local cache
        self.self_dcenter = self_dcenter
        # Record available ids of each switch which can be assigned to VMs
        # {dpid => deque(available ids)}
        self.dpid_to_vmids = defaultdict(deque)

    def init_swc_vmids(self, dpid):
        self.dpid_to_vmids[dpid] = deque(xrange(self.SWITCH_MAXID))

    def create_vm_id(self, dpid):
        try:
            vm_id = self.dpid_to_vmids[dpid].pop()
            return str(vm_id)
        except IndexError:
            LOGGER.info("ERROR: Index Error")
            return None

    def recollect_vm_id(self, vm_id, dpid):
        self.dpid_to_vmids[dpid].appendleft(int(vm_id))

    def generate_swc_id(self, dpid):
        """Create switch id"""
        swc_id = str((hash(dpid) % self.SWITCH_MAXID) + 1)
        local_ids = self.dcenter_to_swcids[self.self_dcenter]
        if swc_id in local_ids.values():
            # TODO(chen): Hash conflict
            LOGGER.info("ERROR: switch id conflict: %s", swc_id)
        else:
            local_ids[dpid] = swc_id

        return swc_id

    def update_swc_id(self, dcenter, dpid, swc_id):
        self.dcenter_to_swcids[dcenter][dpid] = swc_id

    def get_swc_id(self, dcenter, dpid):
        return self.dcenter_to_swcids[dcenter].get(dpid)

    def invalidate_vm_id(self, dpid, vm_id):
        if dpid not in self.dpid_to_vmids:
            self.dpid_to_vmids[dpid] = deque(xrange(self.SWITCH_MAXID))
            return False

        try:
            self.dpid_to_vmids[dpid].remove(int(vm_id))
            return True
        except ValueError:
            return False


class VmManager(object):
    """Manage virtual machines in the network"""
    VM_MAXID = 65535

    def __init__(self):
        # Local cache
        # Record VM's vm_id, to facilitate vmac generation
        # {mac => {dpid => id}}
        self.mac_to_id = {}
        # Record VM's positions, to facilitate detecting live migration
        # {mac => (dcenter, dpid, port)}
        self.mac_to_position = {}
        # Record VM's local flow setup, to prevent redundant flow setup
        self.mac_to_dpid = {}

    def update_vm(self, dcenter, dpid, port, mac, vm_id):
        self.mac_to_position[mac] = (dcenter, dpid, port)
        LOGGER.info("Update: (mac=%s) => (dcenter=%s, switch=%s, port=%s)",
                    mac, dcenter, dpid, port)
        self.mac_to_id[mac] = (dpid, vm_id)

    def get_position(self, mac):
        return self.mac_to_position.get(mac)

    def get_vm_id(self, mac):
        id_tuple = self.mac_to_id.get(mac)
        if id_tuple is None:
            return None
        else:
            _, vm_id = id_tuple
        return vm_id

    def mac_exists(self, mac):
        return (mac in self.mac_to_position)

    def flow_setup(self, mac, dpid):
        self.mac_to_dpid[mac] = dpid

    def flow_exists(self, mac, dpid):
        return (self.mac_to_dpid[mac] == dpid)

    def position_shifts(self, mac, dcenter, dpid, port):
        if mac not in self.mac_to_position:
            return False
        else:
            pos_old = self.mac_to_position[mac]
            return (pos_old != (dcenter, dpid, port))


class VmacManager(object):
    """
    Create vmacs of VMs, switches and datacenters
    """
    DCENTER_MASK = "ff:ff:00:00:00:00"
    SWITCH_MASK = "ff:ff:ff:ff:00:00"
    TENANT_MASK = "00:00:00:00:00:ff"

    def __init__(self, self_dcenter='0'):
        # zookeeper data
        # Record guests which queried vmac,
        # to inform of VMs during live migration
        # {vmac => {mac => time}}
        self.vmac_to_queries = defaultdict(dict)

        # Local cache
        # All Switches' virtual MAC, to facilitate vmac generation
        # {dpid => vmac}
        self.dpid_to_vmac = {}

        # All VMs' virtual MAC, to facilitate ARP resolution
        # {mac => vmac}
        self.mac_to_vmac = {}

    def get_query_macs(self, vmac):
        if vmac not in self.vmac_to_queries:
            return []

        query_list = []
        for mac_query in self.vmac_to_queries[vmac].keys():
            time_now = time.time()
            query_time = self.vmac_to_queries[vmac][mac_query]
            if (time_now - float(query_time)) > CONF.arp_timeout:
                del self.vmac_to_queries[vmac][mac_query]
            else:
                query_list.append(mac_query)

        return query_list

    def del_vmac_query(self, vmac):
        self.vmac_to_queries.pop(vmac, None)

    def update_query(self, vmac, mac, query_time):
        self.vmac_to_queries[vmac][mac] = query_time

    def create_dc_vmac(self, dcenter_str):
        """Generate MAC address for datacenter based on datacenter id.

        Address form: xx:xx:00:00:00:00
        xx:xx is converted from data center id
        """
        dcenter = int(dcenter_str)

        if dcenter > 65535:
            return

        dcenter_high = (dcenter >> 8) & 0xff
        dcenter_low = dcenter & 0xff
        dcenter_vmac = "%02x:%02x:00:00:00:00" % (dcenter_high, dcenter_low)
        return dcenter_vmac

    def create_swc_vmac(self, dcenter, dpid, swc_id_str):
        """Generate MAC address prefix for switch based on
        datacenter id and switch id.

        Address form: xx:xx:yy:yy:00:00
        xx:xx is converted from data center id
        yy:yy is converted from switch id
        """
        dcenter_vmac = self.create_dc_vmac(dcenter)
        dcenter_prefix = self.get_dc_prefix(dcenter_vmac)

        swc_id = int(swc_id_str)
        switch_high = (swc_id >> 8) & 0xff
        switch_low = swc_id & 0xff
        switch_suffix = ("%02x:%02x:00:00" % (switch_high, switch_low))
        switch_vmac = ':'.join((dcenter_prefix, switch_suffix))
        self.dpid_to_vmac[dpid] = switch_vmac
        return switch_vmac

    def create_vm_vmac(self, mac, tenant_manager, vm_manager):
        """Generate virtual MAC address of a VM"""
        _, dpid, _ = vm_manager.get_position(mac)
        switch_vmac = self.dpid_to_vmac[dpid]
        switch_prefix = self.get_swc_prefix(switch_vmac)
        vm_id = int(vm_manager.get_vm_id(mac))
        vm_id_hex = vm_id & 0xff
        vm_id_suffix = "%02x" % vm_id_hex

        tenant_id = int(tenant_manager.get_tenant_id(mac))
        tenant_id_hex = tenant_id & 0xff
        tenant_id_suffix = "%02x" % tenant_id_hex
        vmac = ':'.join((switch_prefix, vm_id_suffix, tenant_id_suffix))
        self.mac_to_vmac[mac] = vmac
        LOGGER.info("Create: (mac=%s) => (vmac=%s)", mac, vmac)
        return vmac

    def construct_vmac(self, dcenter, dpid, vm_id_str, tenant_id_str):
        swc_vmac = self.dpid_to_vmac[dpid]
        switch_prefix = self.get_swc_prefix(swc_vmac)
        vm_id = int(vm_id_str)
        vm_id_hex = vm_id & 0xff
        vm_id_suffix = "%02x" % vm_id_hex
        tenant_id = int(tenant_id_str)
        tenant_id_hex = tenant_id & 0xff
        tenant_id_suffix = "%02x" % tenant_id_hex
        vmac = ':'.join((switch_prefix, vm_id_suffix, tenant_id_suffix))
        return vmac

    def get_swc_prefix(self, vmac):
        """Extract switch prefix from virtual MAC address"""
        return vmac[:11]

    def get_dc_prefix(self, vmac):
        """Extract switch prefix from virtual MAC address"""
        return vmac[:5]

    def get_vm_vmac(self, mac):
        return self.mac_to_vmac.get(mac)

    def get_swc_vmac(self, dpid):
        return self.dpid_to_vmac.get(dpid)


class FlowManager(object):
    """Handle flow installation/uninstallation"""

    # Table id
    PRIMARY_TABLE = 0
    SECONDARY_TABLE = 1

    def __init__(self, dpset=None, multi_tenancy=False):
        self.dpset = dpset
        # Switches on which interdatacenter flows are to be installed
        self.interdcenter_waitinglist = []
        self.multi_tenancy = multi_tenancy

    def set_new_switch_flows(self, dpid, topology, vmac_manager):
        """Set up flows when a new switch(dpid) is connected"""
        self.set_default_flows(dpid)
        self.set_interswitch_flows(dpid, topology, vmac_manager)
        if topology.gateway_connected():
            self.set_switch_dcenter_flows(dpid, topology, vmac_manager)
        else:
            # To be installed interdatacenter flows after gateway is connected
            self.interdcenter_waitinglist.append(dpid)

    def handle_waitinglist(self, dpid_gw, topology, vmac_manager):
        """Install interdatacenter flows on non-gateway switches
        in the waiting list"""
        for dpid in self.interdcenter_waitinglist:
            self.set_switch_dcenter_flows(dpid, topology, vmac_manager)
        self.interdcenter_waitinglist = []

    def set_new_gateway_flows(self, dpid_gw, topology, vmac_manager):
        """Set up flows when a new gateway(dpid) is connected"""
        self.set_default_flows(dpid_gw)
        self.set_interswitch_flows(dpid_gw, topology, vmac_manager)
        self.set_gateway_dcenter_flows(dpid_gw, topology, vmac_manager)
        self.handle_waitinglist(dpid_gw, topology, vmac_manager)

    def set_gateway_dcenter_flows(self, dpid_gw, topology, vmac_manager):
        """Set up flows on gateway switches to other datacenters"""
        dcenter_to_port = topology.gateway_to_dcenters[dpid_gw].items()
        for (dcenter, port_no) in dcenter_to_port:
            peer_dc_vmac = vmac_manager.create_dc_vmac(dcenter)
            self.set_topology_flow(dpid_gw, peer_dc_vmac,
                                   VmacManager.DCENTER_MASK, port_no)

    def set_switch_dcenter_flows(self, dpid, topology, vmac_manager):
        """Set up flows on non-gateway switches to other datacenters"""
        dpid_gws = topology.get_gateways()
        for dpid_gw in dpid_gws:
            gw_fwd_port = topology.get_fwd_port(dpid, dpid_gw)
            for dcenter in topology.gateway_to_dcenters[dpid_gw]:
                peer_dc_vmac = vmac_manager.create_dc_vmac(dcenter)
                self.set_topology_flow(dpid, peer_dc_vmac,
                                       VmacManager.DCENTER_MASK, gw_fwd_port)

    def set_interswitch_flows(self, dpid, topology, vmac_manager):
        """Set up flows connecting the new switch(dpid) and
        all existing switches"""
        for (peer_dpid, fwd_port) in topology.get_neighbors(dpid).items():
            peer_vmac = vmac_manager.get_swc_vmac(peer_dpid)
            self.set_topology_flow(dpid, peer_vmac,
                                   VmacManager.SWITCH_MASK, fwd_port)

            self_vmac = vmac_manager.get_swc_vmac(dpid)
            peer_port = topology.get_fwd_port(peer_dpid, dpid)
            self.set_topology_flow(peer_dpid, self_vmac,
                                   VmacManager.SWITCH_MASK, peer_port)

    def set_topology_flow(self, dpid, mac, mask, port):
        """Set up a microflow for unicast on switch DPID towards MAC"""
        datapath = self.dpset.get(str_to_dpid(dpid))
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
        priority = i_priority.DATA_FWD_DCENTER

        if self.multi_tenancy:
            table_id = FlowManager.SECONDARY_TABLE
        else:
            table_id = FlowManager.PRIMARY_TABLE

        actions = [ofproto_parser.OFPActionOutput(int(port))]
        instructions_src = [
            datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions)]
        match_src = ofproto_parser.OFPMatch(eth_dst=(mac, mask))
        self.set_flow(datapath=datapath,
                      match=match_src,
                      table_id=table_id,
                      priority=priority,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=ofproto.OFPFC_ADD,
                      instructions=instructions_src)

        LOGGER.info("New forward flow: (switch=%s) -> (mac=%s, mask=%s)",
                    dpid, mac, mask)

    def set_gateway_bounce_flow(self, dpid, vmac_new, vmac_old, topology):
        """Set up a flow at gateway towards local dpid_old
        during live migration to prevent
        unnecessary multi-datacenter traffic"""
        dpid_gws = topology.get_gateways()
        for dpid_gw in dpid_gws:
            gw_fwd_port = topology.get_fwd_port(dpid_gw, dpid)
            datapath_gw = self.dpset.get(str_to_dpid(dpid_gw))
            ofproto = datapath_gw.ofproto
            ofproto_parser = datapath_gw.ofproto_parser
            actions = [ofproto_parser.OFPActionSetField(eth_dst=vmac_new),
                       ofproto_parser.OFPActionOutput(int(gw_fwd_port))]
            instructions = [
                datapath_gw.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions)]
            match_gw = ofproto_parser.OFPMatch(eth_dst=vmac_old)
            self.set_flow(datapath=datapath_gw,
                          match=match_gw,
                          table_id=FlowManager.PRIMARY_TABLE,
                          priority=i_priority.DATA_FWD_LOCAL,
                          flags=ofproto.OFPFF_SEND_FLOW_REM,
                          hard_timeout=CONF.arp_timeout,
                          command=ofproto.OFPFC_ADD,
                          instructions=instructions)

    def set_drop_flow(self, dpid, table_id=0):
        """Set up a flow to drop all packets that do not match any flow"""
        datapath = self.dpset.get(str_to_dpid(dpid))
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        instruction_norm = [
            datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [])]
        match_norm = ofproto_parser.OFPMatch()
        self.set_flow(datapath=datapath,
                      match=match_norm,
                      table_id=table_id,
                      priority=i_priority.NORMAL,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=ofproto.OFPFC_ADD,
                      instructions=instruction_norm)

    def set_flow(self, datapath, match=None, table_id=0, command=None,
                 priority=0, flags=0, hard_timeout=0, instructions=[]):
        """Send OFPFlowMod instruction to datapath"""

        parser = datapath.ofproto_parser
        datapath.send_msg(
            parser.OFPFlowMod(
                datapath=datapath,
                match=match,
                table_id=table_id,
                command=command,
                priority=priority,
                flags=flags,
                hard_timeout=hard_timeout,
                instructions=instructions))

    def set_default_flows(self, dpid):
        """Set up default flows on a connected switch.
        Default flows are categarized into two tables:
        Table 1: tenant filter
        Table 2: destination-based forwarding
        """
        datapath = self.dpset.get(str_to_dpid(dpid))
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        # Table 1 setup
        # Set up one flow for ARP messages.
        # Intercepts all ARP packets and send them to the controller
        actions_arp = [ofproto_parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER)]
        instruction_arp = [datapath.ofproto_parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS,
            actions_arp)]
        match_arp = ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP)
        self.set_flow(datapath=datapath,
                      match=match_arp,
                      table_id=FlowManager.PRIMARY_TABLE,
                      priority=i_priority.ARP,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=ofproto.OFPFC_ADD,
                      instructions=instruction_arp)
        # Set up two flows for DHCP messages
        actions_dhcp = [ofproto_parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER)]
        instruction_dhcp = [datapath.ofproto_parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS,
            actions_dhcp)]
        match_client = ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                               ip_proto=inet.IPPROTO_UDP,
                                               udp_src=i_dhcp.CLIENT_PORT)
        match_server = ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                               ip_proto=inet.IPPROTO_UDP,
                                               udp_src=i_dhcp.SERVER_PORT)
        # (1) Intercept all DHCP request packets and send to the controller
        self.set_flow(datapath=datapath,
                      match=match_client,
                      table_id=FlowManager.PRIMARY_TABLE,
                      priority=i_priority.DHCP,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=ofproto.OFPFC_ADD,
                      instructions=instruction_dhcp)
        # (2) Intercept all DHCP reply packets and send to the controller
        self.set_flow(datapath=datapath,
                      match=match_server,
                      table_id=FlowManager.PRIMARY_TABLE,
                      priority=i_priority.DHCP,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=ofproto.OFPFC_ADD,
                      instructions=instruction_dhcp)

        # To prevent loop, all non-matching packets are dropped
        self.set_drop_flow(dpid)

        # Table 2 setup for multi-tenancy
        # To prevent loop, all non-matching packets are dropped
        if self.multi_tenancy:
            self.set_drop_flow(dpid, table_id=FlowManager.SECONDARY_TABLE)

    def del_tenant_filter(self, dpid, mac):
        """Delete a tenant filter microflow on a switch (dpid)"""
        if not self.multi_tenancy:
            return

        datapath = self.dpset.get(str_to_dpid(dpid))
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        match = ofproto_parser.OFPMatch(eth_src=mac)

        self.set_flow(datapath=datapath,
                      match=match,
                      table_id=FlowManager.PRIMARY_TABLE,
                      command=ofproto.OFPFC_DELETE_STRICT)

    def set_tenant_filter(self, dpid, vmac, mac):
        """Set up a microflow on a switch (dpid)
        to only allow intra-tenant unicast"""
        if not self.multi_tenancy:
            return

        datapath = self.dpset.get(str_to_dpid(dpid))
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        match = ofproto_parser.OFPMatch(eth_src=mac,
                                        eth_dst=(vmac,
                                                 VmacManager.TENANT_MASK))
        inst = [ofproto_parser.OFPInstructionGotoTable(
                    FlowManager.SECONDARY_TABLE)]
        self.set_flow(datapath=datapath,
                      match=match,
                      table_id=FlowManager.PRIMARY_TABLE,
                      priority=i_priority.DATA_FWD_TENANT,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      command=ofproto.OFPFC_ADD,
                      instructions=inst)

    def set_local_flow(self, dpid, vmac, mac, port, flow_add=True, timeout=0):
        """Set up a microflow on a switch (dpid) towards a guest (mac)
        The rule matches on dst vmac, rewrites it to mac and forwards to
        the appropriate port.
        mac can be another vmac.
        """
        datapath = self.dpset.get(str_to_dpid(dpid))
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        if flow_add:
            flow_cmd = ofproto.OFPFC_ADD
        else:
            flow_cmd = ofproto.OFPFC_MODIFY_STRICT

        actions = [ofproto_parser.OFPActionSetField(eth_dst=mac),
                   ofproto_parser.OFPActionOutput(int(port))]
        instructions = [
            datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions)]
        match = ofproto_parser.OFPMatch(eth_dst=vmac)
        self.set_flow(datapath=datapath,
                      match=match,
                      table_id=FlowManager.PRIMARY_TABLE,
                      priority=i_priority.DATA_FWD_LOCAL,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      hard_timeout=timeout,
                      command=flow_cmd,
                      instructions=instructions)
        if self.multi_tenancy:
            self.set_flow(datapath=datapath,
                          match=match,
                          table_id=FlowManager.SECONDARY_TABLE,
                          priority=i_priority.DATA_FWD_LOCAL,
                          hard_timeout=timeout,
                          flags=ofproto.OFPFF_SEND_FLOW_REM,
                          command=flow_cmd,
                          instructions=instructions)


class TenantManager(object):
    """Manage tenant information"""
    DEFAULT_TENANT_ID = "1"

    def __init__(self, mac_to_tenant={}):
        self.mac_to_tenant = mac_to_tenant

    @classmethod
    def tenant_from_string(cls, tenant_info):
        """Create an instance of TenantManager from argument of type string"""
        tenant_list = cls.parse_tenants(tenant_info)
        mac_to_tenant = {}
        if tenant_list:
            for tenant_id, mac_tuple in enumerate(tenant_list, 1):
                for mac in mac_tuple:
                    mac_to_tenant[mac] = str(tenant_id)
        tenant_manager = cls(mac_to_tenant)
        return tenant_manager

    def parse_tenants(self, tenant_info, out_sep=';', in_sep=','):
        """Convert string to list of tuples"""

        tenant_list = []
        if tenant_info == "":
            return tenant_list

        tenant_str_list = tenant_info.split(out_sep)
        for tenant_str in tenant_str_list:
            mac_list = tenant_str.split(in_sep)
            mac_tuple = tuple(mac_list)
            tenant_list.append(mac_tuple)

        return tenant_list

    def get_tenant_id(self, mac):
        if self.mac_to_tenant:
            return self.mac_to_tenant[mac]
        else:
            return TenantManager.DEFAULT_TENANT_ID


class RPCManager(object):
    """Manager RPC clients and Issue RPC calls"""

    MAX_ID = 65536

    def __init__(self, dcenter_to_info, self_dcenter='0'):
        # {peer_dc => peer_gateway}: Record neighbor datacenter connection info
        self.self_dcenter = self_dcenter
        self.dcenter_to_info = dcenter_to_info
        self.dcenter_to_rpc = {}
        self.rpc_id = 0

    @classmethod
    def rpc_from_config(cls, peer_dcenters, self_dcenter='0'):
        dcenter_to_info = cls.parse_peer_dcenters(peer_dcenters)
        rpc_manager = cls(dcenter_to_info, self_dcenter)
        return rpc_manager

    @staticmethod
    def parse_peer_dcenters(peer_dcenters, out_sep=';', in_sep=','):
        """Convert string to dictionary"""

        peer_dcs_dic = {}
        if not peer_dcenters:
            return peer_dcs_dic

        peer_dcs_list = peer_dcenters.split(out_sep)
        for peer_dc in peer_dcs_list:
            peer_list = peer_dc.split(in_sep)
            peer_dcs_dic[peer_list[0]] = (peer_list[1], peer_list[2])

        return peer_dcs_dic

    def _setup_rpc_server_clients(self, inception_rpc):
        """Set up RPC server and RPC client to other controllers"""
        # RPC server
        host_addr = socket.gethostbyname(socket.gethostname())
        rpc_server = SimpleXMLRPCServer((host_addr, CONF.rpc_port),
                                        allow_none=True)
        rpc_server.register_introspection_functions()
        rpc_server.register_instance(inception_rpc)
        hub.spawn(rpc_server.serve_forever)

        # Create RPC clients
        for dcenter in self.dcenter_to_info:
            controller_ip, _ = self.dcenter_to_info[dcenter]
            rpc_client = ServerProxy("http://%s:%s" %
                                          (controller_ip, CONF.rpc_port))
            self.dcenter_to_rpc[dcenter] = rpc_client

    def get_dcenters(self):
        peer_dcenters = self.dcenter_to_info.keys()
        peer_dcenters.append(self.self_dcenter)
        return peer_dcenters

    def do_rpc(self, func_name, arguments):
        rpc_id = str(self.rpc_id)
        self.rpc_id = (self.rpc_id + 1) % self.MAX_ID
        for rpc_client in self.dcenter_to_rpc.values():
            rpc_client.do_rpc(func_name, rpc_id, arguments)


class ArpManager(object):
    """Maintain IP <=> MAC mapping"""
    def __init__(self):
        # Data stored in zookeeper
        self.ip_to_mac = {}

        # Local cache
        self.mac_to_ip = {}

    def update_mapping(self, ip, mac):
        if ip in self.ip_to_mac:
            return

        self.ip_to_mac[ip] = mac
        self.mac_to_ip[mac] = ip
        LOGGER.info("Update: (ip=%s) => (mac=%s)", ip, mac)

    def learn_arp_mapping(self, ip, mac):
        if ip in self.ip_to_mac:
            return

        self.update_mapping(ip, mac)

    def del_mapping(self, ip, mac):
        del self.ip_to_mac[ip]
        del self.mac_to_ip[mac]

    def get_ip(self, mac):
        return self.mac_to_ip[mac]

    def get_mac(self, ip):
        return self.ip_to_mac[ip]

    def mapping_exist(self, ip):
        return (ip in self.ip_to_mac)


class ZkManager(object):
    """Manage data storage and fetch in zookeeper"""

    def __init__(self, inception, zk_storage=False):
        # zk_storage: Decide whether to use zookeeper (True) or not (False)
        self.zk_storage = zk_storage
        self.inception = inception
        if self.zk_storage:
            # Flag indicating master/slave role
            self.master_ctl = False
            self.exit_flag = False

            self.pos_path = "/pos"
            self.arp_path = "/arp"
            self.queue_path = "/queue"
            self.leader_path = "/election"
            self.pktin_path = "/log/packet_in"
            self.rpc_path = "/log/rpc"

            self.digest_to_pktin = {}

            zk_logger = logging.getLogger('kazoo')
            zk_log_level = log.LOG_LEVELS[CONF.zk_log_level]
            zk_logger.setLevel(zk_log_level)
            console_handler = logging.StreamHandler()
            console_handler.setLevel(zk_log_level)
            console_handler.setFormatter(logging.Formatter(CONF.log_formatter))
            zk_logger.addHandler(console_handler)
            self.zk = client.KazooClient(hosts=CONF.zk_servers,
                                         logger=zk_logger)
            self.zk.start()
            self.zk.ensure_path(self.pos_path)
            self.zk.ensure_path(self.arp_path)
            self.zk.ensure_path(self.pktin_path)
            self.zk.ensure_path(self.rpc_path)

            self.pkt_queue = self.zk.LockingQueue(self.queue_path)
            self.thread_pkt = hub.spawn(self.handle_pkt_queue)
            hub.spawn(self.run_for_leader)

    def run_for_leader(self):
        election = self.zk.Election(self.leader_path)
        LOGGER.info('Contending for leadership...')
        election.run(self.handle_role_upgrade)

    def handle_role_upgrade(self):
        LOGGER.info("Upgrade to master")
        hub.kill(self.thread_pkt)
        while self.pkt_queue.__len__() > 0:
            self.consume_pkt()

        dcenters = self.inception.rpc_manager.get_dcenters()
        self.init_dcenter(dcenters)
        self.load_data(arp_manager=self.inception.arp_manager,
                       switch_manager=self.inception.switch_manager,
                       vm_manager=self.inception.vm_manager,
                       vmac_manager=self.inception.vmac_manager,
                       tenant_manager=self.inception.tenant_manager)
        self.handle_failover_log()
        self.master_ctl = True
        # TODO: New leader election design
        # HACK: Hardcode the program lifetime for evaluation
        if CONF.eval_lifetime is None:
            while True:
                time.sleep(1)
        else:
            time.sleep(CONF.eval_lifetime)
            self.exit_flag = True
            sys.exit()

    def consume_pkt(self):
        """Consume packet_in in queue and local cache"""
        pkt_data = self.pkt_queue.get()
        self.pkt_queue.consume()
        pkt_digest = pkt_data.decode('Latin-1').encode('Latin-1')
        self.digest_to_pktin.pop(pkt_digest, None)
        LOGGER.info('Packet_in message consumed: %s', pkt_digest)

    def handle_pkt_queue(self):
        """For slave controller only. Consume whatever packets in the queue"""
        while True:
            if self.is_slave():
                self.consume_pkt()

    def queue_nonempty(self):
        return (self.pkt_queue.__len__() > 0)

    def enqueue(self, pkt_digest):
        LOGGER.info('Packet_in message enqueued: %s', pkt_digest)
        self.pkt_queue.put(pkt_digest)

    def add_pktin(self, pkt_digest, dpid, in_port, pkt_data):
        self.digest_to_pktin[pkt_digest] = (dpid, in_port, pkt_data)

    def is_master(self):
        return (self.master_ctl == True)

    def is_slave(self):
        return (self.master_ctl == False)

    def load_data(self, arp_manager, switch_manager, vm_manager, vmac_manager,
                  tenant_manager):
        """Initiate local caches"""
        if not self.zk_storage:
            return

        LOGGER.info("Load data from zookeeper")
        # arp_manager
        for ip_unicode in self.zk.get_children(self.arp_path):
            ip = ip_unicode.encode('Latin-1')
            ip_path = os.path.join(self.arp_path, ip)
            mac, _ = self.zk.get(ip_path)
            arp_manager.update_mapping(ip, mac)

        # switch_manager & vm_manager & vmac_manager
        # Load switch id, vm_id, vm_position and create vmac
        for dcenter_unicode in self.zk.get_children(self.pos_path):
            dcenter = dcenter_unicode.encode('Latin-1')
            dc_path = os.path.join(self.pos_path, dcenter)
            for dpid_unicode in self.zk.get_children(dc_path):
                dpid = dpid_unicode.encode('Latin-1')
                dpid_path = os.path.join(dc_path, dpid)
                id_str, _ = self.zk.get(dpid_path)
                switch_manager.update_swc_id(dcenter, dpid, id_str)
                vmac_manager.create_swc_vmac(dcenter, dpid, id_str)
                for port_unicode in self.zk.get_children(dpid_path):
                    port_str = port_unicode.encode('Latin-1')
                    port_path = os.path.join(dpid_path, port_str)
                    for mac_unicode in self.zk.get_children(port_path):
                        mac = mac_unicode.encode('Latin-1')
                        mac_path = os.path.join(port_path, mac)
                        mac_id, _ = self.zk.get(mac_path)
                        switch_manager.invalidate_vm_id(dpid, mac_id)
                        vm_manager.update_vm(dcenter, dpid, port_str, mac,
                                             mac_id)
                        vm_vmac = vmac_manager.create_vm_vmac(mac,
                                                              tenant_manager,
                                                              vm_manager)
                        for qmac_unicode in self.zk.get_children(mac_path):
                            qmac = qmac_unicode.encode('Latin-1')
                            qmac_path = os.path.join(mac_path, qmac)
                            query_time, _ = self.zk.get(qmac_path)
                            vmac_manager.update_query(vm_vmac, qmac,
                                                      query_time)

    def init_dcenter(self, dcenters):
        if self.zk_storage:
            for dcenter in dcenters:
                zk_path = os.path.join(self.pos_path, dcenter)
                self.zk.ensure_path(zk_path)

    def log_dpid_id(self, dcenter, dpid, swc_id, txn=None):
        if self.zk_storage:
            zk_path = os.path.join(self.pos_path, dcenter, dpid)
            if txn is None:
                self.zk.create(zk_path, swc_id)
            else:
                txn.create(zk_path, swc_id)

    def log_vm(self, dcenter, dpid, port, mac, vm_id, txn=None):
        if self.zk_storage:
            zk_port_path = os.path.join(self.pos_path, dcenter, dpid, port)
            zk_path = os.path.join(self.pos_path, dcenter, dpid, port, mac)
            if txn is None:
                self.zk.create(zk_path, vm_id, makepath=True)
            else:
                txn.create(zk_port_path)
                txn.create(zk_path, vm_id)

    def del_vm(self, dcenter, dpid, port, txn=None):
        # Delete the port znode, along with the mac being its sub-node
        if self.zk_storage:
            zk_path = os.path.join(self.pos_path, dcenter, dpid, port)
            if txn is None:
                self.zk.delete(zk_path, recursive=True)
            else:
                txn.delete(zk_path)

    def move_vm(self, mac, dcenter_old, dpid_old, port_old, dcenter_new,
                dpid_new, port_new, vm_id_new, txn):
        # Move a znode of MAC from one position to another
        if self.zk_storage:
            zk_path_old = os.path.join(self.pos_path, dcenter_old, dpid_old,
                                       port_old)
            zk_mac_old = os.path.join(self.pos_path, dcenter_old, dpid_old,
                                       port_old, mac)
            for query_mac_unicode in self.zk.get_children(zk_mac_old):
                query_mac = query_mac_unicode.encode('Latin-1')
                zk_query_old = os.path.join(zk_mac_old, query_mac)
                txn.delete(zk_query_old)
            txn.delete(zk_mac_old)
            txn.delete(zk_path_old)
            zk_mac_new = os.path.join(self.pos_path, dcenter_new, dpid_new,
                                       port_new, mac)
            zk_port_new = os.path.join(self.pos_path, dcenter_new, dpid_new,
                                       port_new)
            txn.create(zk_port_new)
            txn.create(zk_mac_new, vm_id_new)

    def log_arp_mapping(self, ip, mac, txn=None):
        if self.zk_storage:
            zk_path = os.path.join(self.arp_path, ip)
            if txn is None:
                self.zk.create(zk_path, mac)
            else:
                txn.create(zk_path, mac)

    def log_query_mac(self, dcenter, dpid, port, mac, query_mac, query_time,
                      txn=None):
        if self.zk_storage:
            zk_path = os.path.join(self.pos_path, dcenter, dpid, port, mac,
                                   query_mac)
            if txn is None:
                self.zk.create(zk_path, query_time)
            else:
                txn.create(zk_path, query_time)

    def create_transaction(self):
        if self.zk_storage:
            return self.zk.transaction()
        else:
            return None

    def txn_commit(self, txn=None):
        if txn is not None:
            txn.commit()

    def add_packetin_log(self, position, packet_data, txn=None):
        """Failover logging"""
        if self.zk_storage:
            LOGGER.info('Add packet_in log')
            log_path = os.path.join(self.pktin_path, position)
            self.zk.create(log_path, packet_data)

    def del_packetin_log(self, position, txn=None):
        """Delete failover logging"""
        if self.zk_storage:
            LOGGER.info('Delete packet_in log')
            log_path = os.path.join(self.pktin_path, position)
            if txn is None:
                self.zk.delete(log_path)
            else:
                txn.delete(log_path)

    def add_rpc_log(self, func_name, arguments_tuple):
        if self.zk_storage:
            log_path = os.path.join(self.rpc_path, func_name)
            arguments = tuple_to_str(arguments_tuple)
            self.zk.create(log_path, arguments)

    def del_rpc_log(self, func_name, txn=None):
        if self.zk_storage:
            log_path = os.path.join(self.rpc_path, func_name)
            if txn is None:
                self.zk.delete(log_path)
            else:
                txn.delete(log_path)
                self.txn_commit(txn)

    def handle_failover_log(self):
        """Check if any work is left by previous controller.
        If so, continue the unfinished work.
        """
        LOGGER.info('Handle failover...')
        # Do unfinished packet_in handling
        zk_pktins = self.zk.get_children(self.pktin_path)
        for znode_unicode in zk_pktins:
            LOGGER.info('Process failover log...')
            pktin_log = znode_unicode.encode('Latin-1')
            log_path = os.path.join(self.pktin_path, pktin_log)
            raw_data, _ = self.zk.get(log_path)
            dpid, in_port = str_to_tuple(pktin_log)
            pkt_data = raw_data.decode('Latin-1').encode('Latin-1')
            pkt_digest = md5.new(pkt_data).digest()
            pkt_in = self.digest_to_pktin.pop(pkt_digest, None)
            if pkt_in is not None:
                packet = InceptionPacket(pkt_data)
                self.inception.process_packet_in(dpid, in_port, packet)
                # Enqueue the log so that other controllers
                # can dump the corresponding packet
                self.enqueue(pkt_digest)
            # Delete log after task is finished
            self.del_packetin_log(pktin_log)

        # Do unfinished rpc
        zk_rpcs = self.zk.get_children(self.rpc_path)
        for znode_unicode in zk_rpcs:
            LOGGER.info('Process RPC log...')
            rpc_log = znode_unicode.encode('Latin-1')
            log_path = os.path.join(self.rpc_path, rpc_log)
            rpc_data, _ = self.zk.get(log_path)
            func_name, _ = str_to_tuple(rpc_log)
            rpc_tuple = str_to_tuple(rpc_data)
            try:
                txn = self.create_transaction()
                rpc_method = getattr(self.inception.inception_rpc, func_name)
                rpc_method(txn, *rpc_tuple)
                self.del_rpc_log(rpc_log, txn)
            except AttributeError:
                LOGGER.warning("Unexpected exception in finding rpc method")

        self.zk.delete(self.pktin_path, recursive=True)
        self.zk.delete(self.rpc_path, recursive=True)
        self.zk.create(self.pktin_path)
        self.zk.create(self.rpc_path)
        LOGGER.info('Failover done.')

    def process_pktin_cache(self):
        if self.digest_to_pktin:
            LOGGER.info('Process pkt_in cache...')
            for dpid, in_port, packet in self.digest_to_pktin.values():
                packet_data = packet.data.decode('Latin-1').encode('Latin-1')
                pktin_log = tuple_to_str((dpid, in_port))
                self.add_packetin_log(pktin_log, packet_data)
                self.inception.process_packet_in(dpid, in_port, packet)
                self.del_packetin_log(pktin_log)
            self.digest_to_pktin.clear()
            LOGGER.info('pkt_in cache cleared.')


class InceptionPacket(Packet):
    """Subclass of ryu Packet"""
    def __init__(self, data=None, protocols=None, parse_cls=ethernet):
        Packet.__init__(self, data, protocols, parse_cls)
        self.raw_data = data

    def _parser(self, cls):
        rest_data = self.data
        while cls:
            try:
                proto, cls, rest_data = cls.parser(rest_data)
            except struct.error:
                break
            if isinstance(proto, dhcp):
                self.protocols.append(proto)
                continue

            if proto:
                self.protocols.append(proto)
                if isinstance(proto, udp):
                    if proto.src_port in (i_dhcp.CLIENT_PORT,
                                          i_dhcp.SERVER_PORT):
                        # DHCP packet
                        cls = dhcp

        if rest_data:
            self.protocols.append(rest_data)


def tuple_to_str(data_tuple, sep=','):
    """Convert tuple to string."""

    data_string = sep.join(data_tuple)
    return data_string


def str_to_tuple(data_string, sep=','):
    """Convert string to tuple."""

    data_tuple = tuple(data_string.split(sep))
    return data_tuple
