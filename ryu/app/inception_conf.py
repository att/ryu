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

"""A global view of Inception configurations, to ease management"""
from oslo.config import cfg

from ryu.ofproto import ofproto_v1_2

CONF = cfg.CONF

CONF.register_opts([
    cfg.BoolOpt('zookeeper_storage',
                default=False,
                help='Enable/Disable zookeeper storage'),
    cfg.StrOpt('zk_servers',
               default='127.0.0.1:2181',
               help=("Addresses of ZooKeeper servers\n"
                     "Format: <server1_ip:port1>,<server2_ip:port2>,...\n"
                     "E.g., 192.168.0.1:2181,192.168.0.2:2181,192.168.0.3:2181"
                     )),
    cfg.StrOpt('zk_election',
               default='/election',
               help='Path of leader election in ZooKeeper'),
    cfg.StrOpt('zk_log_level',
               default='warning',
               help="Log level for Kazoo/ZooKeeper"),
    cfg.StrOpt('gateway_ips',
               default="127.0.0.1",
               help=("IP addresses of the physical machine hosting gateway"
                     "Format: <gateway_ip1>,<gateway_ip2>,...\n"
                     "E.g., 192.168.0.1,192.168.0.2")),
    cfg.StrOpt('dhcp_ip',
               default="127.0.0.1",
               help="IP address of the physical machine hosting dhcp server"),
    cfg.StrOpt('dhcp_port',
               default='eth_dhcpp',
               help="Port name of dhcp port"),
    cfg.StrOpt('intradcenter_port_prefix',
               default="obr",
               help="String prefix of port_name, meaning intradcenter port"),
    cfg.StrOpt('interdcenter_port_prefix',
               default="gateway",
               help="String prefix of port_name, meaning intradcenter port"),
    cfg.StrOpt('ip_prefix',
               default='192.168',
               help="X1.X2 in your network's IP address X1.X2.X3.X4"),
    cfg.StrOpt('self_dcenter',
               default='1',
               help="Datacenter ID"),
    cfg.IntOpt('rpc_port',
               default=8000,
               help="The port for XMLRPC call"),
    cfg.IntOpt('eval_lifetime',
               default=None,
               help="Program lifetime. Only for evaluation"),
    cfg.StrOpt('peer_dcenters',
               default="",
               help=("Neighbor datacenter information\n"
                     "Format: <dc2_id,dc2_controller_ip>;...\n"
                     "E.g., 2,8.8.8.1;3,8.8.8.5"
                     )),
    cfg.BoolOpt('forwarding_bcast',
                default=False,
                help='Enable/Disable all-to-all broadcast'),
    cfg.IntOpt('arp_timeout',
               default=60,
               help="Default ARP timeout"),
    cfg.BoolOpt('multi_tenancy',
                default=False,
                help='Enable/Disable multi-tenancy'),
    cfg.StrOpt('tenant_info',
               default="",
               help=("Tenant group information identified by MAC addr\n"
                     "Format: <tenant1_mac1,tenant1_mac2,...>;...\n"
                     "59:fc:1e:52:fb:1b,fd:06:03:4d:98:47;b5:36:85:b4:cb:76")),
    # TODO: remove hardcoding
    cfg.IntOpt('num_switches',
               default=4,
               help=("The number of switches in total for each datacenter,"
                     " for failure recovery")),
    # TODO: non-configurable
    cfg.ListOpt('ofp_versions',
                default=[ofproto_v1_2.OFP_VERSION],
                help="Default OpenFlow versions to use"),
])
