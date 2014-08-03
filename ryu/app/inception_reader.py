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

from SimpleXMLRPCServer import SimpleXMLRPCServer
import socket

from oslo.config import cfg

from ryu.app import inception_util as i_util
from ryu.app.inception_util import InceptionPacket
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.lib import hub
from ryu.lib.dpid import dpid_to_str
from ryu.lib.dpid import str_to_dpid
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.ofproto import ether

LOGGER = logging.getLogger('ryu.app.inception')

CONF = cfg.CONF


class InceptionReader(app_manager.RyuApp):
    """Inception Cloud SDN controller."""

    # Built-in Ryu modules, manage all connected switches: {dpid => datapath}
    _CONTEXTS = {
        'dpset': dpset.DPSet
    }
    # Default OpenFlow versions
    OFP_VERSIONS = CONF.ofp_versions

    def __init__(self, *args, **kwargs):
        super(InceptionReader, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.dcenter_id = CONF.self_dcenter

        # RPC server for ARP update
        self.arp_rpc = ArpRpc()
        host_addr = socket.gethostbyname(socket.gethostname())
        rpc_server = SimpleXMLRPCServer((host_addr, CONF.rpc_port),
                                        allow_none=True)
        rpc_server.register_introspection_functions()
        rpc_server.register_instance(self.arp_rpc)
        hub.spawn(rpc_server.serve_forever)

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        """Handle when a packet is received."""
        LOGGER.info('New packet_in received.')
        msg = event.msg
        datapath = msg.datapath
        dpid = dpid_to_str(datapath.id)
        in_port = str(msg.match['in_port'])
        packet = InceptionPacket(msg.data)
        self.process_packet_in(dpid, in_port, packet)

    def process_packet_in(self, dpid, in_port, packet):
        """Process raw data received from dpid through in_port."""
        # Handle ARP packet
        arp_header = packet.get_protocol(arp.arp)
        if arp_header:
            LOGGER.info("Handle ARP packet")
            # Process ARP request
            if arp_header.opcode == arp.ARP_REQUEST:
                # Process ARP request
                src_ip = arp_header.src_ip
                src_mac = arp_header.src_mac
                dst_ip = arp_header.dst_ip

                LOGGER.info("ARP request: (ip=%s) query (ip=%s)",
                            src_ip, dst_ip)

                dst_vmac = self.arp_rpc.ip_to_mac.get(dst_ip)
                if dst_vmac is not None:
                    LOGGER.info("Cache hit: (dst_ip=%s) <=> (vmac=%s)",
                                dst_ip, dst_vmac)
                    # Send arp reply
                    src_mac_reply = dst_vmac
                    vmac_reply = src_mac
                    src_ip_reply = dst_ip
                    dst_ip_reply = src_ip
                    self.send_arp_reply(dpid, in_port, src_ip_reply,
                                        src_mac_reply, dst_ip_reply,
                                        vmac_reply)

                else:
                    LOGGER.info("Query failure: MAC for (dst_ip=%s)"
                                "cannot be found", dst_ip)

    def send_arp_reply(self, dpid, port, src_ip, src_mac, dst_ip, dst_mac):
        """
        Construct an arp reply given the specific arguments
        and send it through switch connecting dst_mac
        """
        # Forward ARP reply
        packet_reply = self.create_arp_packet(src_mac, dst_mac, dst_ip,
                                              src_ip, arp.ARP_REPLY)
        dst_datapath = self.dpset.get(str_to_dpid(dpid))
        dst_ofproto_parser = dst_datapath.ofproto_parser
        dst_ofproto = dst_datapath.ofproto
        actions_out = [dst_ofproto_parser.OFPActionOutput(int(port))]
        dst_datapath.send_msg(
            dst_ofproto_parser.OFPPacketOut(
                datapath=dst_datapath,
                buffer_id=0xffffffff,
                in_port=dst_ofproto.OFPP_LOCAL,
                data=packet_reply.data,
                actions=actions_out))
        LOGGER.info("Send ARP reply of (ip=%s) to (ip=%s): ", src_ip, dst_ip)

    def create_arp_packet(self, src_mac, dst_mac, dst_ip, src_ip, opcode):
            """Create an Ethernet packet, with ARP packet inside"""

            arp_packet = arp.arp(opcode=opcode,
                                  dst_mac=dst_mac,
                                  src_mac=src_mac,
                                  dst_ip=dst_ip,
                                  src_ip=src_ip)
            eth_packet = ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                            src=src_mac,
                                            dst=dst_mac)
            packet_out = packet.Packet()
            packet_out.add_protocol(eth_packet)
            packet_out.add_protocol(arp_packet)
            packet_out.serialize()

            return packet_out


class ArpRpc(object):
    """Receives RPCs to update {IP => MAC} mapping"""
    def __init__(self):
        self.ip_to_mac = {}

    def update_local_arp(self, ip, vmac):
        """For ARP_reader: update remote ip_mac mapping"""
        self.ip_to_mac[ip] = vmac
