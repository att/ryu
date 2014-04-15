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

from ryu.lib.dpid import str_to_dpid

LOGGER = logging.getLogger(__name__)

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68


class InceptionDhcp(object):
    """Inception Cloud DHCP module for handling DHCP packets."""

    def __init__(self, inception):
        self.inception = inception

        self.switch_dpid = None
        self.switch_port = None

        # name shortcuts
        self.dpset = inception.dpset
        self.mac_to_position = inception.mac_to_position

    def update_server(self, dpid, port):
        if self.switch_dpid is not None and self.switch_port is not None:
            LOGGER.warning("DHCP-server-connected switch registered before!")

        self.switch_dpid = dpid
        self.switch_port = port

    def handle(self, udp_header, ethernet_header, raw_data):
        # Process DHCP packet
        LOGGER.info("Handle DHCP packet")

        if self.switch_dpid is None or self.switch_port is None:
            LOGGER.warning("No DHCP server has been found!")
            return

        # A packet received from client. Find out the switch connected
        # to dhcp server and forward the packet
        if udp_header.src_port == DHCP_CLIENT_PORT:
            LOGGER.info("Forward DHCP message to server at (switch=%s) "
                        "(port=%s)", self.switch_dpid, self.switch_port)
            datapath = self.dpset.get(str_to_dpid(self.switch_dpid))
            action_out = [
                datapath.ofproto_parser.OFPActionOutput(
                    int(self.switch_port))]
            datapath.send_msg(
                datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_LOCAL,
                    data=raw_data,
                    actions=action_out))

        # A packet received from server. Find out the mac address of
        # the client and forward the packet to it.
        elif udp_header.src_port == DHCP_SERVER_PORT:
            _, dpid, port = self.mac_to_position(ethernet_header.dst)
            LOGGER.info("Forward DHCP message to client (mac=%s) at "
                        "(switch=%s, port=%s)",
                        ethernet_header.dst, dpid, port)
            datapath = self.dpset.get(str_to_dpid(dpid))
            action_out = [datapath.ofproto_parser.OFPActionOutput(int(port))]
            datapath.send_msg(
                datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_LOCAL,
                    data=raw_data,
                    actions=action_out))