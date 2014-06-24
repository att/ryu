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

from collections import defaultdict
import logging

from oslo.config import cfg

from ryu.lib.dpid import str_to_dpid
from ryu.app import inception_dhcp as i_dhcp
from ryu.app import inception_priority as i_priority
from ryu.ofproto import ether
from ryu.ofproto import inet

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('ip_prefix', 'ryu.app.inception_conf')
CONF.import_opt('gateway_ip', 'ryu.app.inception_conf')
CONF.import_opt('dhcp_ip', 'ryu.app.inception_conf')
CONF.import_opt('dhcp_port', 'ryu.app.inception_conf')
CONF.import_opt('arp_timeout', 'ryu.app.inception_conf')
CONF.import_opt('interdcenter_port_prefix', 'ryu.app.inception_conf')
CONF.import_opt('intradcenter_port_prefix', 'ryu.app.inception_conf')


class Topology(object):
    """
    Build switch level topology of Inception network.
    Gateway is assumed to have no local VMs connected.
    Topology is maintained as two dictionaries:

    dpid_to_dpid: {dpid1 -> {dpid2 -> port}}
    gateway_to_dcenters: {gateway_dpid -> {dcenter -> port}}
    """
    def __init__(self):
        # Connection between local pairs of switches
        self.dpid_to_dpid = defaultdict(dict)
        # {dpid_gw -> {dcenter_id -> port_no}}
        self.gateway_to_dcenters = defaultdict(dict)
        # TOOD(chen): multiple gateways
        self.gateway = None
        self.dhcp_switch = None
        self.dhcp_port = None
        # {local dpid -> {remote ip -> local port}}
        self.dpid_ip_to_port = defaultdict(dict)
        # {local ip -> local dpid}
        self.ip_to_dpid = {}

    def update_switch(self, dpid_new, ip_new, ports):
        """Update switch topology"""

        self.ip_to_dpid[ip_new] = dpid_new
        LOGGER.info("Add: (switch=%s) -> (ip=%s)", dpid_new, ip_new)
        self.parse_switch_ports(dpid_new, ip_new, ports)
        if ip_new == CONF.dhcp_ip:
            self.dhcp_switch = dpid_new
        if ip_new == CONF.gateway_ip:
            self.gateway = dpid_new
            LOGGER.info("Gateway switch: (ip=%s), (dpid=%s)", ip_new,
                        self.gateway)

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
                if peer_ip in self.ip_to_dpid:
                    # peer_ip has been connected to the controller
                    peer_dpid = self.ip_to_dpid[peer_ip]
                    self.dpid_to_dpid[dpid][peer_dpid] = port_no

                    peer_port = self.dpid_ip_to_port[peer_dpid][ip]
                    self.dpid_to_dpid[peer_dpid][dpid] = peer_port

                else:
                    # Store the port_no until peer_ip is connected
                    self.dpid_ip_to_port[dpid][peer_ip] = port_no

            # Port_name: e.g., "gateway_<dcenter_id>"
            elif port.name.startswith(remote_port_prefix):
                peer_dcenter = self.extract_dcenter(port.name)
                port_no = port.port_no
                self.gateway_to_dcenters[dpid][peer_dcenter] = port_no
                LOGGER.info("New inter-datacenter connection:"
                            "(gateway=%s) -> (datacenter=%s)",
                            dpid, peer_dcenter)

            # Port name matches DHCP port
            if port.name == CONF.dhcp_port:
                self.dhcp_port = port.port_no

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

        return self.gateway is not None

    def is_gateway(self, dpid):
        """Check if dpid is gateway"""

        return dpid == self.gateway

    def is_dhcp(self, dpid):
        """Check if dpid is dhcp server"""

        return dpid == self.dhcp_switch


class VmacManager(object):
    """
    Manage vmacs of VMs, switches and datacenters
    """
    DCENTER_MASK = "ff:00:00:00:00:00"
    SWITCH_MASK = "ff:ff:ff:00:00:00"
    TENANT_MASK = "00:00:00:00:00:ff"
    SWITCH_MAXID = 65535
    VM_MAXID = 65535
    DCENTER_MAXID = 127

    def __init__(self):
        # Record switch id assignment
        self.switch_id_slots = [False] * (self.SWITCH_MAXID + 1)
        # Record vm id assignment of each switch
        self.dpid_to_vmidlist = defaultdict(list)
        # Datacenter virtual MAC
        self.dcenter_to_vmac = {}
        # Switch virtual MAC
        self.dpid_to_vmac = {}
        # VM virtual MAC
        self.mac_to_vmac = {}
        # HACK: for vm_id conflict
        self.vm_counter = 1

    def update_switch(self, dcenter_id, dpid):
        """Handle switch connection"""
        if dpid not in self.dpid_to_vmidlist:
            self.dpid_to_vmidlist[dpid] = [False] * (self.VM_MAXID + 1)

        if dpid not in self.dpid_to_vmac:
            dcenter_vmac = self.dcenter_to_vmac[dcenter_id]
            switch_vmac = self.create_swc_vmac(dcenter_vmac, dpid)
            self.dpid_to_vmac[dpid] = switch_vmac
        else:
            switch_vmac = self.dpid_to_vmac[dpid]

        return switch_vmac

    def update_dcenter(self, dcenter_id):
        if dcenter_id not in self.dcenter_to_vmac:
            dcenter_vmac = self.create_dc_vmac(int(dcenter_id))
            self.dcenter_to_vmac[dcenter_id] = dcenter_vmac

    def generate_vm_id(self, vm_mac, dpid):
        """Generate a new vm_id, 00 is saved for switch"""
        #TODO(chen): Avoid hash conflict
        vm_id = self.vm_counter
        self.vm_counter += 1
        if self.dpid_to_vmidlist[dpid][vm_id]:
            LOGGER.info("WARNING: switch id conflict:"
                        "vm_id=%s has been created for dpid=%s", vm_id, dpid)
        else:
            self.dpid_to_vmidlist[dpid][vm_id] = True

        return vm_id

    def create_dc_vmac(self, dcenter):
        """Generate MAC address for datacenter based on datacenter id.

        Address form: xx:xx:00:00:00:00
        xx:xx is converted from data center id
        """
        if dcenter > self.DCENTER_MAXID:
            return

        dcenter_id = dcenter * 2
        dcenter_hex = dcenter_id & 0xff
        dcenter_vmac = "%02x:00:00:00:00:00" % (dcenter_hex)
        return dcenter_vmac

    def create_swc_vmac(self, dcenter_vmac, dpid):
        """Generate MAC address prefix for switch based on
        datacenter id and switch id.

        Address form: xx:yy:yy:00:00:00
        xx is converted from datacenter id
        yy:yy is converted from switch id
        """
        dcenter_prefix = self.get_dc_prefix(dcenter_vmac)

        switch_num = (hash(dpid) % self.SWITCH_MAXID) + 1
        if self.switch_id_slots[switch_num]:
            LOGGER.info("ERROR: switch id conflict: ", switch_num)
        else:
            self.switch_id_slots[switch_num] = True

        switch_high = (switch_num >> 8) & 0xff
        switch_low = switch_num & 0xff
        switch_suffix = ("%02x:%02x:00:00:00" % (switch_high, switch_low))
        return ':'.join((dcenter_prefix, switch_suffix))

    def create_vm_vmac(self, vm_mac, switch_vmac, vm_id, tenant_id):
        """Generate virtual MAC address of a VM"""

        switch_prefix = self.get_swc_prefix(switch_vmac)
        vm_id_high = (vm_id >> 8) & 0xff
        vm_id_low = vm_id & 0xff
        vm_id_suffix = "%02x:%02x" % (vm_id_high, vm_id_low)
        tenant_id_hex = tenant_id & 0xff
        tenant_id_suffix = "%02x" % tenant_id_hex
        vmac = ':'.join((switch_prefix, vm_id_suffix, tenant_id_suffix))
        self.mac_to_vmac[vm_mac] = vmac
        LOGGER.info("Update: (mac=%s) => (vmac=%s)", vm_mac, vmac)
        return vmac

    def update_vm_vmac(self, mac, vmac):
        self.mac_to_vmac[mac] = vmac
        LOGGER.info("Update: (mac=%s) => (vmac=%s)", mac, vmac)

    def get_swc_prefix(self, vmac):
        """Extract switch prefix from virtual MAC address"""
        return vmac[:8]

    def get_dc_prefix(self, vmac):
        """Extract switch prefix from virtual MAC address"""
        return vmac[:2]


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
            peer_dc_vmac = vmac_manager.dcenter_to_vmac[dcenter]
            self.set_topology_flow(dpid_gw, peer_dc_vmac,
                                   VmacManager.DCENTER_MASK, port_no)

    def set_switch_dcenter_flows(self, dpid, topology, vmac_manager):
        """Set up flows on non-gateway switches to other datacenters"""
        # TODO(chen): Multiple gateways
        dpid_gw = topology.gateway
        gw_fwd_port = topology.dpid_to_dpid[dpid][dpid_gw]
        for dcenter in topology.gateway_to_dcenters[dpid_gw]:
            peer_dc_vmac = vmac_manager.dcenter_to_vmac[dcenter]
            self.set_topology_flow(dpid, peer_dc_vmac,
                                   VmacManager.DCENTER_MASK, gw_fwd_port)

    def set_interswitch_flows(self, dpid, topology, vmac_manager):
        """Set up flows connecting the new switch(dpid) and
        all existing switches"""
        for (peer_dpid, fwd_port) in topology.dpid_to_dpid[dpid].items():
            peer_vmac = vmac_manager.dpid_to_vmac[peer_dpid]
            self.set_topology_flow(dpid, peer_vmac,
                                   VmacManager.SWITCH_MASK, fwd_port)

            self_vmac = vmac_manager.dpid_to_vmac[dpid]
            peer_port = topology.dpid_to_dpid[peer_dpid][dpid]
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
        dpid_gw = topology.gateway
        gw_fwd_port = topology.dpid_to_dpid[dpid_gw][dpid]
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

    def set_local_flow(self, dpid, vmac, mac, port, flow_add=True):
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
                      command=flow_cmd,
                      instructions=instructions)
        if self.multi_tenancy:
            self.set_flow(datapath=datapath,
                          match=match,
                          table_id=FlowManager.SECONDARY_TABLE,
                          priority=i_priority.DATA_FWD_LOCAL,
                          flags=ofproto.OFPFF_SEND_FLOW_REM,
                          command=flow_cmd,
                          instructions=instructions)


class TenantManager(object):
    """Manage tenant information"""
    DEFAULT_TENANT_ID = 1

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
                    mac_to_tenant[mac] = tenant_id
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


class ArpMapping(object):
    """Maintain IP <=> MAC mapping"""
    def __init__(self):
        self.ip_to_mac = {}
        self.mac_to_ip = {}

    def update_mapping(self, ip, mac):
        self.ip_to_mac[ip] = mac
        self.mac_to_ip[mac] = ip

    def del_mapping(self, ip, mac):
        del self.ip_to_mac[ip]
        del self.mac_to_ip[mac]

    def get_ip(self, mac):
        return self.mac_to_ip[mac]

    def get_mac(self, ip):
        return self.ip_to_mac[ip]

    def mapping_exist(self, ip):
        return (ip in self.ip_to_mac)


def tuple_to_str(data_tuple, sep=','):
    """Convert tuple to string."""

    data_string = sep.join(data_tuple)
    return data_string


def str_to_tuple(data_string, sep=','):
    """Convert string to tuple."""

    data_tuple = tuple(data_string.split(sep))
    return data_tuple


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



