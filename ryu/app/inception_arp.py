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
import time

from oslo.config import cfg

from ryu.lib.packet import arp

LOGGER = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('zookeeper_storage', 'ryu.app.inception_conf')


class InceptionArp(object):
    """Inception Cloud ARP module for handling ARP packets."""

    def __init__(self, inception):
        self.inception = inception

        # name shortcuts
        self.dpset = inception.dpset
        self.dcenter_id = inception.dcenter_id
        self.arp_manager = inception.arp_manager
        self.vmac_manager = inception.vmac_manager
        self.vm_manager = inception.vm_manager
        self.zk_manager = inception.zk_manager
        self.rpc_manager = inception.rpc_manager

    def handle(self, dpid, in_port, arp_header, txn):
        LOGGER.info("Handle ARP packet")
        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac
        dst_ip = arp_header.dst_ip

        # Do {IP => MAC} learning
        if not self.arp_manager.mapping_exist(src_ip):
            self.arp_manager.learn_arp_mapping(src_ip, src_mac)
            icp_rpc = self.inception.inception_rpc
            rpc_func_name = icp_rpc.update_arp_mapping.__name__
            rpc_args = (src_ip, src_mac)
            self.rpc_manager.do_rpc(rpc_func_name, rpc_args)
            src_vmac = self.vmac_manager.get_vm_vmac(src_mac)
            self.rpc_manager.rpc_arp_learning(src_ip, src_vmac)
            self.zk_manager.log_arp_mapping(src_ip, src_mac, txn)
        # Process ARP request
        if arp_header.opcode == arp.ARP_REQUEST:
            if self.arp_manager.mapping_exist(dst_ip):
                dst_mac = self.arp_manager.get_mac(dst_ip)
                dst_vmac = self.vmac_manager.get_vm_vmac(dst_mac)
                dst_pos = self.vm_manager.get_position(dst_mac)
                (dst_dcenter, dst_dpid, dst_port) = dst_pos

                # Record the communicating guests and time
                query_time = str(time.time())
                self.vmac_manager.update_query(dst_vmac, src_mac, query_time)
                self.zk_manager.log_query_mac(dst_dcenter, dst_dpid, dst_port,
                                              dst_mac, src_mac, query_time,
                                              txn)
