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

import logging
import md5

from oslo.config import cfg
import traceback

from ryu.app import inception_arp as i_arp
from ryu.app import inception_dhcp as i_dhcp
from ryu.app import inception_rpc as i_rpc
from ryu.app import inception_util as i_util
from ryu.app.inception_util import Topology
from ryu.app.inception_util import InceptionPacket
from ryu.app.inception_util import RPCManager
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet.arp import arp
from ryu.lib.packet.dhcp import dhcp
from ryu.lib.packet.ethernet import ethernet

LOGGER = logging.getLogger('ryu.app.inception')

CONF = cfg.CONF
CONF.import_opt('zookeeper_storage', 'ryu.app.inception_conf')
CONF.import_opt('zk_servers', 'ryu.app.inception_conf')
CONF.import_opt('zk_log_level', 'ryu.app.inception_conf')
CONF.import_opt('ip_prefix', 'ryu.app.inception_conf')
CONF.import_opt('gateway_ips', 'ryu.app.inception_conf')
CONF.import_opt('dhcp_port', 'ryu.app.inception_conf')
CONF.import_opt('self_dcenter', 'ryu.app.inception_conf')
CONF.import_opt('rpc_port', 'ryu.app.inception_conf')
CONF.import_opt('arp_timeout', 'ryu.app.inception_conf')
CONF.import_opt('arp_readers', 'ryu.app.inception_conf')
CONF.import_opt('ofp_versions', 'ryu.app.inception_conf')
CONF.import_opt('peer_dcenters', 'ryu.app.inception_conf')
CONF.import_opt('tenant_info', 'ryu.app.inception_conf')
CONF.import_opt('num_switches', 'ryu.app.inception_conf')
CONF.import_opt('forwarding_bcast', 'ryu.app.inception_conf')
CONF.import_opt('multi_tenancy', 'ryu.app.inception_conf')


class Inception(app_manager.RyuApp):
    """Inception Cloud SDN controller."""

    # Built-in Ryu modules, manage all connected switches: {dpid => datapath}
    _CONTEXTS = {
        'dpset': dpset.DPSet
    }
    # Default OpenFlow versions
    OFP_VERSIONS = CONF.ofp_versions

    def __init__(self, *args, **kwargs):
        super(Inception, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.dcenter_id = CONF.self_dcenter

        self.vmac_manager = i_util.VmacManager(self.dcenter_id)
        self.topology = Topology.topology_from_gateways(CONF.gateway_ips)
        self.flow_manager = i_util.FlowManager(self.dpset, CONF.multi_tenancy)
        self.tenant_manager = i_util.TenantManager(CONF.tenant_info)
        self.arp_manager = i_util.ArpManager()
        self.switch_manager = i_util.SwitchManager(self.dcenter_id)
        self.vm_manager = i_util.VmManager()

        self.rpc_manager = RPCManager.rpc_from_config(CONF.peer_dcenters,
                                                      self.dcenter_id)
        self.rpc_manager.update_arp_readers(CONF.arp_readers)
        self.zk_manager = i_util.ZkManager(self, CONF.zookeeper_storage)

        ## Inception relevent modules
        # ARP
        self.inception_arp = i_arp.InceptionArp(self)
        # DHCP
        self.inception_dhcp = i_dhcp.InceptionDhcp(self)
        # RPC
        self.inception_rpc = i_rpc.InceptionRpc(self)
        self.rpc_manager._setup_rpc_server_clients(self.inception_rpc)

    @handler.set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def switch_connection_handler(self, event):
        """Handle when a switch event is received."""
        datapath = event.dp
        dpid = dpid_to_str(datapath.id)

        # A new switch connects
        if event.enter:
            LOGGER.info("New switch connects")
            socket = datapath.socket
            ip, _ = socket.getpeername()

            self.topology.update_switch(dpid, ip, event.ports)
            self.switch_manager.init_swc_vmids(dpid)

            if self.topology.is_dhcp(dpid):
                self.inception_dhcp.update_server(self.topology.dhcp_switch,
                                                  self.topology.dhcp_port)

            if not self.zk_manager.is_master():
                # Slave controller work done
                return

            switch_id = self.switch_manager.get_swc_id(self.dcenter_id, dpid)
            if switch_id is None:
                switch_id = self.switch_manager.generate_swc_id(dpid)
                rpc_func_name = self.inception_rpc.update_swc_id.__name__
                rpc_args = (self.dcenter_id, dpid, switch_id)
                self.rpc_manager.do_rpc(rpc_func_name, rpc_args)

                self.vmac_manager.create_swc_vmac(self.dcenter_id, dpid,
                                                  switch_id)
                self.zk_manager.log_dpid_id(self.dcenter_id, dpid, switch_id)

            if self.topology.is_gateway(dpid):
                self.flow_manager.set_new_gateway_flows(dpid, self.topology,
                                                        self.vmac_manager)
                self.flow_manager.handle_waitinglist(dpid, self.topology,
                                                     self.vmac_manager)
            else:
                self.flow_manager.set_new_switch_flows(dpid, self.topology,
                                                       self.vmac_manager)

        # TODO(chen): A switch disconnects

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        """Handle when a packet is received."""
        LOGGER.info('New packet_in received.')
        msg = event.msg
        datapath = msg.datapath
        dpid = dpid_to_str(datapath.id)
        in_port = str(msg.match['in_port'])
        packet = InceptionPacket(msg.data)
        packet.serialize()
        packet_data = packet.data.decode('Latin-1').encode('Latin-1')
        pkt_digest = md5.new(packet_data).digest()

        if self.zk_manager.is_master():
            # master role
            # First finish all unfinished packet_ins
            self.zk_manager.process_pktin_cache()
            try:
                # Logging in zookeeper
                pktin_log = i_util.tuple_to_str((dpid, in_port))
                self.zk_manager.add_packetin_log(pktin_log, packet_data)
                self.process_packet_in(dpid, in_port, packet)
                # Enqueue packet so that other controllers
                # can dump the corresponding packet
                self.zk_manager.enqueue(pkt_digest)
                # Delete log after task is finished
                self.zk_manager.del_packetin_log(pktin_log)
            except Exception:
                LOGGER.warning("Unexpected exception in packet handler %s",
                               traceback.format_exc())
        else:
            # slave role
            LOGGER.info('Cache packet_in message from (dpid=%s, in_port=%s)',
                        dpid, in_port)
            self.zk_manager.add_pktin(pkt_digest, dpid, in_port, packet)

    def process_packet_in(self, dpid, in_port, packet):
        """Process raw data received from dpid through in_port."""
        txn = self.zk_manager.create_transaction()
        # Process packet
        try:
            ether_header = packet.get_protocol(ethernet)
            # do source learning
            ether_src = ether_header.src
            pos_old = self.vm_manager.get_position(ether_src)
            if pos_old:
                if (self.dcenter_id, dpid, in_port) != pos_old:
                    dcenter_old, dpid_old, port_old = pos_old
                    self.handle_migration(ether_src, dcenter_old, dpid_old,
                                          port_old, dpid, in_port, txn)
            else:
                self.learn_new_vm(dpid, in_port, ether_src, txn)
            # Handle ARP packet
            arp_header = packet.get_protocol(arp)
            if arp_header:
                self.inception_arp.handle(dpid, in_port, arp_header, txn)
            # handle DHCP packet if it is
            dhcp_header = packet.get_protocol(dhcp)
            if isinstance(dhcp_header, dhcp):
                self.inception_dhcp.handle(dhcp_header, packet.raw_data, txn)

        except Exception:
            LOGGER.warning("Unexpected exception in packet processing: %s",
                           traceback.format_exc())

            LOGGER.warn("packet=%s", packet)
            LOGGER.warn("ether_header=%s", ether_header)
            LOGGER.warn("ether_src=%s", ether_src)

        self.zk_manager.txn_commit(txn)

    def learn_new_vm(self, dpid, port, mac, txn):
        """Create vmac for new vm; Store vm position info;
        and install local forwarding flow"""
        # Update position
        LOGGER.info("Update vm position: (mac=%s) => (datacenter=%s, "
                    "switch=%s, port=%s)",
                    mac, self.dcenter_id, dpid, port)
        pos = self.vm_manager.get_position(mac)
        if pos is None:
            # Create vm_id
            vm_id = self.switch_manager.create_vm_id(dpid)
            self.vm_manager.update_vm(self.dcenter_id, dpid, port, mac, vm_id)
            rpc_func_name = self.inception_rpc.update_vm.__name__
            rpc_args = (self.dcenter_id, dpid, port, mac, vm_id)
            self.rpc_manager.do_rpc(rpc_func_name, rpc_args)
            vmac = self.vmac_manager.create_vm_vmac(mac, self.tenant_manager,
                                                    self.vm_manager)
        # Set up local flow
        self.flow_manager.set_tenant_filter(dpid, vmac, mac)
        self.flow_manager.set_local_flow(dpid, vmac, mac, port)
        # Register position and vm_id
        self.zk_manager.log_vm(self.dcenter_id, dpid, port, mac, vm_id, txn)

    def handle_migration(self, mac, dcenter_old, dpid_old, port_old, dpid_new,
                         port_new, txn):
        """Set flows to handle VM migration properly"""
        LOGGER.info("Handle VM migration")
        # Update VM position
        vmac_old = self.vmac_manager.get_vm_vmac(mac)

        # Multi-datacenter migration
        if dcenter_old != self.dcenter_id:
            LOGGER.info("VM migration from (DC=%s) to (DC=%s)", dcenter_old,
                        self.dcenter_id)

            # A new vmac has not been created
            # Revoke old vm_id
            vm_id_old = self.vm_manager.get_vm_id(mac)
            self.switch_manager.recollect_vm_id(vm_id_old, dpid_old)
            # Generate new vm_id
            vm_id_new = self.switch_manager.create_vm_id(dpid_new)
            self.vm_manager.update_vm(self.dcenter_id, dpid_new, port_new, mac,
                                      vm_id_new)
            vmac_new = self.vmac_manager.create_vm_vmac(mac,
                                                        self.tenant_manager,
                                                        self.vm_manager)

            # Instruct other datacenter to operate accordingly
            rpc_func_name = self.inception_rpc.handle_dc_migration.__name__
            rpc_args = (mac, dcenter_old, dpid_old, port_old, vm_id_old,
                        self.dcenter_id, dpid_new, port_new, vm_id_new)
            self.rpc_manager.do_rpc(rpc_func_name, rpc_args)

            # Set up flows at gateway to redirect flows bound for
            # old vmac in dcenter_old to new vmac
            # The flow will expire after ARP cache expires
            self.flow_manager.set_gateway_bounce_flow(dpid_new, vmac_new,
                                                      vmac_old, self.topology)

            # Add flow at dpid_new towards vmac_new
            self.flow_manager.set_local_flow(dpid_new, vmac_new, mac, port_new)
            LOGGER.info("Live migration: Add local forward flow on (switch=%s)"
                        "towards (mac=%s)", dpid_new, mac)

            self.notify_vmac_update(mac, vmac_old, vmac_new)
            # send gratuitous ARP to all local sending guests
            for mac_query in self.vmac_manager.get_query_macs(vmac_old):
                ip = self.arp_manager.get_ip(mac)
                ip_query = self.arp_manager.get_ip(mac_query)
                self.inception_arp.send_arp_reply(ip, vmac_new, ip_query,
                                                  mac_query)
            self.vmac_manager.del_vmac_query(vmac_old)

        # Same datacenter, different switch migration
        elif dpid_old != dpid_new:
            LOGGER.info("VM migration from (DPID=%s) to (DPID=%s)",
                        dpid_old, dpid_new)

            # Install/Update a new flow at dpid_new towards mac
            # Revoke old vm_id
            vm_id_old = self.vm_manager.get_vm_id(mac)
            self.switch_manager.recollect_vm_id(vm_id_old, dpid_old)
            # Generate new vm_id
            vm_id_new = self.switch_manager.create_vm_id(dpid_new)
            self.vm_manager.update_vm(self.dcenter_id, dpid_new, port_new, mac,
                                      vm_id_new)
            rpc_func_name = self.inception_rpc.update_vm.__name__
            rpc_args = (self.dcenter_id, dpid_new, port_new, mac, vm_id_new)
            self.rpc_manager.do_rpc(rpc_func_name, rpc_args)
            vmac_new = self.vmac_manager.create_vm_vmac(mac,
                                                        self.tenant_manager,
                                                        self.vm_manager)

            # Instruct dpid_old to redirect traffic
            fwd_port = self.topology.get_fwd_port(dpid_old, dpid_new)
            self.flow_manager.set_local_flow(dpid_old, vmac_old, vmac_new,
                                             fwd_port, False, CONF.arp_timeout)
            LOGGER.info("Redirect forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_old, mac)
            # Add flow at dpid_new towards vmac_new
            self.flow_manager.set_local_flow(dpid_new, vmac_new, mac, port_new)
            # Add tenant flow of mac at dpid_new
            self.flow_manager.set_tenant_filter(dpid_new, vmac_new, mac)
            # Delete tenant flow of mac at dpid_old
            self.flow_manager.del_tenant_filter(dpid_old, mac)

            LOGGER.info("Add local forward flow on (switch=%s) towards "
                        "(mac=%s)", dpid_new, mac)
            self.notify_vmac_update(mac, vmac_old, vmac_new)

        # Same switch, different port migration (reboot)
        elif port_old != port_new:
            LOGGER.info("VM migration (reboot etc) from (dpid_old=%s)"
                        " to (dpid_new=%s)", dpid_old, dpid_new)

            # Redirect traffic
            self.flow_manager.set_local_flow(dpid_old, vmac_old, mac, port_new,
                                             False)
            LOGGER.info("Update forward flow on (switch=%s) towards (mac=%s)",
                        dpid_old, mac)

        self.zk_manager.move_vm(mac, dcenter_old, dpid_old, port_old,
                                self.dcenter_id, dpid_new, port_new, vm_id_new,
                                txn)

    def notify_vmac_update(self, mac, vmac_old, vmac_new):
        # Send gratuitous ARP to all local guests sending traffic to mac
        for mac_query in self.vmac_manager.get_query_macs(vmac_old):
            ip = self.arp_manager.get_ip(mac)
            ip_query = self.arp_manager.get_ip(mac_query)
            self.inception_arp.send_arp_reply(ip, vmac_new, ip_query,
                                              mac_query)
        self.vmac_manager.del_vmac_query(vmac_old)
