##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from netaddr.ip import IPAddress, IPNetwork, AddrFormatError

from litp.core.execution_manager import (
    ConfigTask
    )
from litp.core.litp_logging import LitpLogger
from litp.core.plugin import Plugin
from litp.core.validators import ValidationError

_LOG = LitpLogger()


def sort_route_destinations(left, right):
    left_net = IPNetwork('{0}/{1}'.format(left[0], left[1]))
    right_net = IPNetwork('{0}/{1}'.format(right[0], right[1]))
    return cmp(left_net, right_net)


def sort_route_params(left, right):
    if right.startswith('GATEWAY'):
        return -1
    elif right.startswith('ADDRESS'):
        return 1
    elif right.startswith('NETMASK'):
        if left.startswith('GATEWAY'):
            return 1
        else:
            return -1


def RouteTask(node, model_item, description, call_id, **kwargs):
    """
    Creates a ConfigTask with values to setup routing table.
    Default *call_type* used is 'litpnetwork::route'.
    Route table is flushed after configuration is applied.
    """

    node_routes = kwargs['routes']

    kwargs['address'] = []
    kwargs['netmask'] = []
    kwargs['gateway'] = []
    kwargs['family'] = []
    for address, netmask, gw in node_routes:
        if IPAddress(address.split('/')[0]).version == 6:
            kwargs['family'].append('inet6')
            if "/" in address:
                ip_addr = IPNetwork(address, version=6)
            else:
                ip_addr = IPNetwork(address + '/64', version=6)
            kwargs['address'].append(str(ip_addr.network))
            kwargs['netmask'].append(str(ip_addr.netmask))
        else:
            kwargs['family'].append('inet4')
            kwargs['address'].append(address)
            kwargs['netmask'].append(netmask)
        kwargs['gateway'].append(gw)

    del kwargs['routes']
    kwargs['ensure'] = 'present'
    kwargs['node_name'] = node.hostname
    kwargs['require'] = [{'type': 'Litpnetwork::Config',
                          'value': model_item.device_name}]
    return ConfigTask(node, model_item, description, 'litpnetwork::route',
                      call_id, **kwargs)


class NetworkPlugin(Plugin):
    """
    The LITP Network plugin enables the configuration of the LITP management
    server (MS), managed peer nodes (MNs), and other network elements.

    Use this plugin to configure network interfaces (``eth``, ``bridge``,
    ``bond``, ``vlan``), IPv4 and IPv6 network routes (``route``, ``route6``)
    and virtual IPs (``vip``).

    Update reconfiguration actions are supported for this plugin
    (with some exceptions).
    """

    ENFORCE_PRESENT = 'present'

    ENFORCE_NOT_PRESENT = 'absent'

    DEFAULT_SUBNET = '0.0.0.0/0'

    MAX_VLANS_PER_NODE = 4094

    ALLOWED_INTERFACES = ['eth', 'bridge', 'vlan', 'bond']

    def __init__(self):
        '''
        Constructor to instantiate Drivers
        '''

        super(NetworkPlugin, self).__init__()

    def create_configuration(self, context):
        """
        This plugin provides support for configuring base Ethernet interfaces,
        bridges, bonds, VLANs and routes on the MS and on the peer nodes.

        Layer-2 interfaces are defined in the Deployment Model as items of type
        ``eth``, ``bridge``, ``bond`` or ``vlan`` in the ``network-interfaces``
        collection of a node/MS.

        IPv4 networks are defined under
        ``/infrastructure/networking/networks/`` and must be referenced by name
        in items that model a layer-2 interface that will be connected to that
        network.

        Routes are defined under
        ``/infrastructure/networking/routes/`` and must be inherited
        to a nodes ``network_routes`` collection to be set up on
        that node.

        Use item type ``route`` to add an IPv4 route and item type ``route6``
        to add an IPv6 route.

        If you do not specify a subnet mask when defining an IPv6 address,
        LITP uses '/64' by default.

        When configuring a ``bond`` you may specify a ``miimon`` property
        or ARP properties. The ARP properties are ``arp_interval``,
        ``arp_ip_target``,``arp_validate`` and ``arp_all_targets``. When
        configuring ARP properties, ``arp_interval`` and ``arp_ip_target``
        must both be specified. In addition, both ``arp_validate`` and
        ``arp_all_targets`` may be specified.

        *Example CLI*

        .. code-block:: bash
           :linenos:

            litp create -t network -p /infrastructure/networking/networks/n0 \
-o name='mgmt' subnet='10.82.23.0/24' litp_management='true'
            litp create -t network -p /infrastructure/networking/networks/n1 \
-o name='heartbeat'
            litp create -t network -p /infrastructure/networking/networks/n2 \
-o name='storage' subnet='10.81.24.0/24'
            litp create -t network -p /infrastructure/networking/networks/n3 \
-o name='backup' subnet='10.80.25.0/24'
            litp create -t network -p /infrastructure/networking/networks/n4 \
-o name='traffic' subnet='10.80.26.0/24'
            litp create -t network -p /infrastructure/networking/networks/n5 \
-o name='datanet' subnet='10.80.27.0/24'
            litp create -t route -p /infrastructure/networking/routes/r1 \
-o subnet='0.0.0.0/0' gateway='10.82.23.1'
            litp create -t route6 -p /infrastructure/networking/routes/r2 \
-o subnet='::/0' gateway='2001:aa::1:1'

            litp create -t eth -p /ms/network_interfaces/if0 \
-o macaddress='08:00:27:5B:C2:AA' device_name='eth0' \
ipaddress='10.82.23.1' network_name='mgmt'
            litp create -t eth -p /ms/network_interfaces/if1 \
-o macaddress='08:00:27:5B:C2:BB' device_name='eth1' bridge='br0'
            litp create -t eth -p /ms/network_interfaces/if2 \
-o macaddress='08:00:27:5B:C2:CC' device_name='eth2' bridge='br0'
            litp create -t bridge -p /ms/network_interfaces/if3 \
-o device_name='br0' ipaddress='10.81.24.1' forwarding_delay='0' \
stp='false' network_name='storage' multicast_snooping='0' \
multicast_querier='1' multicast_router='2' hash_max='2048'
            litp inherit -p /ms/routes/r1 \
-s /infrastructure/networking/routes/r1

            litp create -t eth \
-p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/if0 \
-o macaddress='08:00:27:5B:C1:4F' device_name='eth0' \
network_name='mgmt' ipaddress='10.82.23.2'
            litp create -t eth \
-p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/if1 \
-o macaddress='08:00:27:5B:C1:5F' device_name='eth1' network_name='heartbeat'
            litp create -t eth \
-p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/if2 \
-o macaddress='08:00:27:5B:C2:6F' device_name='eth2' \
ipaddress='10.81.24.1' network_name='storage'
            litp create -t vlan \
-p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/if3 \
-o device_name='eth2.4034' network_name='backup' ipaddress='10.80.25.2'
            litp create -t eth \
-p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/if4 \
-o macaddress='08:00:27:5B:C2:7F' device_name='eth3' master='bond0' \
rx_ring_buffer=2048 tx_ring_buffer=1024 txqueuelen=10000
            litp create -t bond \
-p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/if5 \
-o device_name='bond0' miimon=200 mode=3 \
network_name='traffic' ipaddress='10.80.26.1'
            litp create -t eth \
-p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/if6 \
-o macaddress='08:00:27:5B:C3:7F' device_name='eth4' master='bond1' \
rx_ring_buffer=4096 tx_ring_buffer=4096 txqueuelen=10000
            litp create -t bond \
-p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/if7 \
-o device_name='bond1' miimon=200 mode=4 xmit_hash_policy=layer3+4 \
network_name='datanet' ipaddress='10.80.27.2'
            litp inherit -p /deployments/d1/clusters/c1/nodes/n1/routes/r1 \
-s /infrastructure/networking/routes/r1
            litp inherit -p /deployments/d1/clusters/c1/nodes/n1/routes/r2 \
-s /infrastructure/networking/routes/r2

        *Example XML*

        .. code-block:: xml

            <?xml version='1.0' encoding='utf-8'?>
            <litp:root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xmlns:litp="http://www.ericsson.com/litp" \
xsi:schemaLocation="http://www.ericsson.com/litp litp-xml-schema/litp.xsd" \
id="root">
              <litp:root-deployments-collection id="deployments">
                <litp:deployment id="d1">
                  <litp:deployment-clusters-collection id="clusters">
                    <litp:cluster id="c1">
                      <litp:cluster-configs-collection id="configs"/>
                      <litp:cluster-nodes-collection id="nodes">
                        <litp:node id="n1">
                          <hostname>mn1</hostname>
                          <litp:node-configs-collection id="configs"/>
                          <litp:node-file_systems-collection \
id="file_systems"/>
                          <litp:node-items-collection id="items"/>
                          <litp:node-network_interfaces-collection \
id="network_interfaces">
                            <litp:eth id="if0">
                              <ipaddress>10.82.23.2</ipaddress>
                              <network_name>mgmt</network_name>
                              <device_name>eth0</device_name>
                              <macaddress>08:00:27:5B:C1:4F</macaddress>
                            </litp:eth>
                            <litp:eth id="if1">
                              <network_name>heartbeat</network_name>
                              <device_name>eth1</device_name>
                              <macaddress>08:00:27:5B:C1:5F</macaddress>
                            </litp:eth>
                            <litp:eth id="if2">
                              <ipaddress>10.81.24.1</ipaddress>
                              <network_name>storage</network_name>
                              <device_name>eth2</device_name>
                              <macaddress>08:00:27:5B:C2:6F</macaddress>
                            </litp:eth>
                            <litp:vlan id="if3">
                              <ipaddress>10.80.25.2</ipaddress>
                              <network_name>backup</network_name>
                              <device_name>eth2.4034</device_name>
                            </litp:vlan>
                            <litp:eth id="if4">
                              <device_name>eth3</device_name>
                              <macaddress>08:00:27:5B:C2:7F</macaddress>
                              <rx_ring_buffer>2048</rx_ring_buffer>
                              <tx_ring_buffer>1023</tx_ring_buffer>
                              <master>bond0</master>
                              <txqueuelen>10000</txqueuelen>
                              </litp:eth>
                            <litp:bond id="if5">
                              <device_name>bond0</device_name>
                              <miimon>200<miimon>
                              <mode>1</mode>
                              <network_name>traffic</network_name>
                              <ipaddress>10.80.26.1</ipaddress>
                            </litp:bond>
                            <litp:eth id="if6">
                              <device_name>eth4</device_name>
                              <macaddress>08:00:27:5B:C3:7F</macaddress>
                              <rx_ring_buffer>4096</rx_ring_buffer>
                              <tx_ring_buffer>4096</tx_ring_buffer>
                              <master>bond1</master>
                              <txqueuelen>10000</txqueuelen>
                            </litp:eth>
                            <litp:bond id="if7">
                              <ipaddress>10.80.27.2</ipaddress>
                              <network_name>datanet</network_name>
                              <device_name>bond1</device_name>
                              <miimon>200<miimon>
                              <mode>4</mode>
                              <xmit_hash_policy>layer3+4</xmit_hash_policy>
                            </litp:bond>
                          </litp:node-network_interfaces-collection>
                          <litp:node-routes-collection id="routes">
                            <route id="r1"/>
                          </litp:node-routes-collection>
                        </litp:node>
                        <litp:node id="n2">
                          <hostname>mn2</hostname>
                          <litp:node-configs-collection id="configs"/>
                          <litp:node-file_systems-collection \
id="file_systems"/>
                          <litp:node-items-collection id="items"/>
                          <litp:node-network_interfaces-collection \
id="network_interfaces">
                            <litp:eth id="if0">
                              <ipaddress>10.82.23.3</ipaddress>
                              <network_name>mgmt</network_name>
                              <device_name>eth0</device_name>
                              <macaddress>08:00:27:24:8F:27</macaddress>
                            </litp:eth>
                          </litp:node-network_interfaces-collection>
                          <litp:node-routes-collection id="routes">
                            <route id="r1"/>
                          </litp:node-routes-collection>
                        </litp:node>
                      </litp:cluster-nodes-collection>
                      <litp:cluster-services-collection id="services"/>
                      <litp:cluster-software-collection id="software"/>
                    </litp:cluster>
                  </litp:deployment-clusters-collection>
                </litp:deployment>
              </litp:root-deployments-collection>
              <litp:infrastructure id="infrastructure">
                <litp:infrastructure-items-collection id="items"/>
                <litp:networking id="networking">
                  <litp:networking-networks-collection id="networks">
                    <litp:network id="n0">
                      <litp_management>true</litp_management>
                      <name>mgmt</name>
                      <subnet>10.82.23.0/24</subnet>
                    </litp:network>
                    <litp:network id="n1">
                      <litp_management>false</litp_management>
                      <name>heartbeat</name>
                    </litp:network>
                    <litp:network id="n2">
                      <litp_management>false</litp_management>
                      <name>storage</name>
                      <subnet>10.81.24.0/24</subnet>
                    </litp:network>
                    <litp:network id="n3">
                      <litp_management>false</litp_management>
                      <name>backup</name>
                      <subnet>10.80.25.0/24</subnet>
                    </litp:network>
                    <litp:network id="n4">
                      <litp_management>false</litp_management>
                      <name>traffic</name>
                      <subnet>10.80.26.0/24</subnet>
                    </litp:network>
                    <litp:network id="n5">
                      <litp_management>false</litp_management>
                      <name>datanet</name>
                      <subnet>10.80.27.0/24</subnet>
                    </litp:network>
                  </litp:networking-networks-collection>
                  <litp:networking-routes-collection id="routes">
                    <litp:route id="r1">
                      <gateway>10.82.23.1</gateway>
                      <subnet>0.0.0.0/0</subnet>
                    </litp:route>
                  </litp:networking-routes-collection>
                </litp:networking>
                <litp:infrastructure-service_providers-collection \
id="service_providers"/>
                <litp:storage id="storage">
                  <litp:storage-file_systems-collection id="file_systems"/>
                  <litp:storage-storage_profiles-collection \
id="storage_profiles"/>
                  <litp:storage-storage_providers-collection \
id="storage_providers"/>
                </litp:storage>
                <litp:infrastructure-system_providers-collection \
id="system_providers"/>
                <litp:infrastructure-systems-collection id="systems"/>
              </litp:infrastructure>
              <litp:ms id="ms">
                <hostname>ms1</hostname>
                <litp:ms-configs-collection id="configs"/>
                <litp:ms-items-collection id="items"/>
                <litp:ms-network_interfaces-collection id="network_interfaces">
                  <litp:eth id="if0">
                    <ipaddress>10.82.23.1</ipaddress>
                    <network_name>mgmt</network_name>
                    <device_name>eth0</device_name>
                    <macaddress>08:00:27:5B:C2:AA</macaddress>
                  </litp:eth>
                  <litp:eth id="if1">
                    <bridge>br0</bridge>
                    <device_name>eth1</device_name>
                    <macaddress>08:00:27:5B:C2:BB</macaddress>
                  </litp:eth>
                  <litp:eth id="if2">
                    <bridge>br0</bridge>
                    <device_name>eth2</device_name>
                    <macaddress>08:00:27:5B:C2:CC</macaddress>
                  </litp:eth>
                  <litp:bridge id="if3">
                    <ipaddress>10.81.24.1</ipaddress>
                    <network_name>storage</network_name>
                    <device_name>br0</device_name>
                    <forwarding_delay>0</forwarding_delay>
                    <hash_max>2048</hash_max>
                    <multicast_querier>1</multicast_querier>
                    <multicast_router>2</multicast_router>
                    <multicast_snooping>0</multicast_snooping>
                    <stp>false</stp>
                  </litp:bridge>
                </litp:ms-network_interfaces-collection>
                <litp:ms-routes-collection id="routes">
                  <route id="r1"/>
                </litp:ms-routes-collection>
                <litp:ms-services-collection id="services"/>
              </litp:ms>
              <litp:root-plans-collection id="plans"/>
              <litp:software id="software">
                <litp:software-deployables-collection id="deployables"/>
                <litp:software-items-collection id="items"/>
                <litp:software-profiles-collection id="profiles"/>
                <litp:software-runtimes-collection id="runtimes"/>
              </litp:software>
            </litp:root>

        For more information, see "Introduction to LITP Networking" \
from :ref:`LITP References <litp-references>`.

        """

        tasks = []

        new_or_updated_tasks = self._new_or_updated_tasks(context)
        tasks.extend(new_or_updated_tasks)

        initial_routes_tasks = self._new_routes_tasks(context)
        tasks.extend(initial_routes_tasks)

        return tasks

    @staticmethod
    def _is_disable_pxe_boot_only_task(task):
        """
        Returns whether a task is for an interface with
        pxe_boot_only property to true
        """
        interface = task.model_item
        return hasattr(interface, 'pxe_boot_only') and \
            'true' == interface.pxe_boot_only

    def _new_or_updated_tasks(self, context):
        """
        Generates required Tasks for newly added Model Items,
        updated items or if the network has been updated.
        """
        tasks = []

        # Only look at nodes not being removed...
        nodes = [node for node in context.query("node")
                 if not node.is_for_removal()]
        mses = [ms for ms in context.query("ms")
                if not ms.is_for_removal()]
        subnets_updated = dict((net.name, net)
                               for net in context.query("network")
                               if NetworkPlugin._subnet_updated(net))

        mgmt_net = NetworkPlugin._management_network(context)

        for node in nodes + mses:
            node_iface_tasks = []
            mgmt_iface = None
            for interface in node.network_interfaces:

                if (not interface.is_for_removal() and
                        mgmt_net and mgmt_net.name == interface.network_name):
                    mgmt_iface = interface

                if interface.is_initial():
                    iface_tasks = self._device_tasks(context, node,
                                                     interface, 'Configure')
                    tasks.extend(iface_tasks)
                    if not node.is_ms():
                        node_iface_tasks.extend(iface_tasks)
                elif interface.is_updated():
                    tasks.extend(self._device_tasks(context, node,
                                                    interface, 'Update'))
                elif hasattr(interface, "network_name") and \
                        interface.network_name in subnets_updated:
                    dev_tasks = self._device_tasks(context, node,
                                                   interface, 'Update')
                    updated_net = subnets_updated[interface.network_name]
                    for task in dev_tasks:
                        task.model_items.update([updated_net])
                    tasks.extend(dev_tasks)

            if node.is_ms():
                continue

            pxe_boot_only_task = None
            first_mgmt_task = None
            for task in node_iface_tasks:
                if not first_mgmt_task and task.model_item == mgmt_iface:
                    first_mgmt_task = task
                else:
                    if (not pxe_boot_only_task and
                            NetworkPlugin._is_disable_pxe_boot_only_task(
                                task)):
                        pxe_boot_only_task = task

            if pxe_boot_only_task and first_mgmt_task:
                first_mgmt_task.requires.add(pxe_boot_only_task)

        return tasks

    def _build_kwargs(self, context, interface):
        """
        Build appropriate dictionary of properties for ConfigTask depending
        on the defined properties of the interface.
        """
        kwargs = {}
        if interface.ipaddress:
            kwargs['ipaddr'] = interface.ipaddress
            kwargs['netmask'] = NetworkPlugin._netmask(context, interface)
            kwargs['broadcast'] = NetworkPlugin._broadcast(context, interface)

            mgmt_net = NetworkPlugin._management_network(context)
            if mgmt_net and mgmt_net.name == interface.network_name:
                kwargs['is_mgmt_if'] = 'true'

        # This isn't an elif, dual-stack configs are supported
        if interface.ipv6address:
            kwargs['ipv6init'] = 'yes'
            kwargs['ipv6addr'] = interface.ipv6address

        if hasattr(interface, "bridge") and interface.bridge:
            kwargs['bridge'] = interface.bridge
            kwargs['before_device'] = interface.bridge

        if hasattr(interface, 'ipv6_autoconf') and interface.ipv6_autoconf:
            kwargs['ipv6_autoconf'] = \
                    'no' if interface.ipv6_autoconf == 'false' else 'yes'

        return kwargs

    @staticmethod
    def _add_slave_eth_kwargs(slave, kwargs):
        kwargs['master'] = slave.master
        kwargs['slave'] = 'yes'

        if hasattr(slave, 'txqueuelen') and slave.txqueuelen:
            kwargs['txqueuelen'] = slave.txqueuelen

        ethtool_opts = NetworkPlugin._gen_ethtool_options_str(slave)
        if ethtool_opts:
            kwargs['ethtool_opts'] = ethtool_opts

    @staticmethod
    def _add_before_device_kwarg(kwargs, slaves, index):
        try:
            kwargs['before_device'] = slaves[index + 1].device_name
        except IndexError:
            pass

    @staticmethod
    def _requires_arp_ip_cleaning(bond):

        had_target = bond.applied_properties.get('arp_ip_target') is not None
        has_target = hasattr(bond, 'arp_ip_target') and bond.arp_ip_target

        target_changed = had_target and has_target and \
           (bond.applied_properties.get('arp_ip_target') != bond.arp_ip_target)

        return (had_target and not has_target)\
            or target_changed\
            or not bond.applied_properties_determinable

    @staticmethod
    def _requires_primary_cleaning(bond):

        had_primary = bond.applied_properties.get('primary') is not None
        has_primary = hasattr(bond, 'primary') and bond.primary

        return (had_primary and not has_primary) or \
               (not bond.applied_properties_determinable and \
                not bond.is_initial())

    @staticmethod
    def _gen_bonding_options_str(bond):
        preamble = '._gen_bonding_options_str: '

        if bond.arp_interval and bond.arp_ip_target:
            monitoring_str = "arp_interval={0} arp_ip_target={1} "
            monitoring_str = monitoring_str.format(bond.arp_interval,
                                                   bond.arp_ip_target)
            if bond.arp_validate and bond.arp_all_targets:
                monitoring_str += "arp_validate={0} arp_all_targets={1} "
                monitoring_str = monitoring_str.format(bond.arp_validate,
                                                       bond.arp_all_targets)
        elif hasattr(bond, 'miimon') and bond.miimon:
            monitoring_str = "miimon={0} ".format(bond.miimon)
        else:
            monitoring_str = ''

        if bond.primary and bond.primary_reselect:
            primary_str = ' primary={0} primary_reselect={1}'.format(
                                        bond.primary, bond.primary_reselect)
        else:
            primary_str = ''

        mode_str = "mode={0}".format(bond.mode)

        xmit_hash_policy_str = ''
        if hasattr(bond, 'xmit_hash_policy') and bond.xmit_hash_policy:
            xmit_hash_policy_str = ' {0}={1}'.format('xmit_hash_policy',
                                                     bond.xmit_hash_policy)

        options_str = monitoring_str + mode_str + primary_str
        options_str += xmit_hash_policy_str

        _LOG.trace.debug(preamble + options_str)
        return options_str

    def _gen_arp_ips_to_clean(self, bond):

        if not bond.applied_properties_determinable:
            return "ALL"

        def get_ips(ip_csl):
            ips = ip_csl.split(',') if ip_csl else []
            return set(ips)

        new_ips = get_ips(bond.arp_ip_target)

        old_ips_prop = bond.applied_properties.get('arp_ip_target')
        old_ips = get_ips(old_ips_prop)

        ips_to_clean = old_ips - new_ips

        ips_to_clean_list = ' '.join(ip for ip in ips_to_clean)

        return ips_to_clean_list

    @staticmethod
    def _gen_bridging_options_str(bridge):
        options_str = 'multicast_snooping=%s' % bridge.multicast_snooping

        if bridge.multicast_querier:
            options_str += ' multicast_querier=%s' % bridge.multicast_querier

        if bridge.multicast_router:
            options_str += ' multicast_router=%s' % bridge.multicast_router

        if bridge.hash_max:
            options_str += ' hash_max=%s' % bridge.hash_max

        if bridge.hash_elasticity:
            options_str += ' hash_elasticity=%s' % bridge.hash_elasticity

        return options_str

    @staticmethod
    def _gen_ethtool_options_str(interface):
        rx_ring_buffer = hasattr(interface, 'rx_ring_buffer') and \
            interface.rx_ring_buffer and \
            '-G %s rx %s' % \
            (interface.device_name, interface.rx_ring_buffer) \
            or None
        tx_ring_buffer = hasattr(interface, 'tx_ring_buffer') and \
            interface.tx_ring_buffer and \
            '-G %s tx %s' % \
            (interface.device_name, interface.tx_ring_buffer) \
            or None
        ethtool_opts = (rx_ring_buffer or tx_ring_buffer) and \
            '; '.join(part for part in [rx_ring_buffer,
                                        tx_ring_buffer] if part) or None
        return ethtool_opts

    def get_required_slave_for_bond(self, bond, slaves):
        return bond.primary if bond.primary else slaves[0].device_name

    def _device_tasks(self, context, node, interface, verb):
        """
        Construct ConfigTask for specified interface.
        Supports eth, bridge, vlan and bond interfaces.
        """
        tasks = []
        kwargs = self._build_kwargs(context, interface)

        if interface.item_type_id == 'eth':

            ethtool_opts = NetworkPlugin._gen_ethtool_options_str(interface)
            if ethtool_opts:
                kwargs['ethtool_opts'] = ethtool_opts

            all_bonds = NetworkPlugin._net_ifaces_by_type(node, 'bond')
            new_bond_names = [bond.device_name for bond in all_bonds
                              if bond.is_initial()]

            if hasattr(interface, 'txqueuelen') and interface.txqueuelen:
                kwargs['txqueuelen'] = interface.txqueuelen

            if hasattr(interface, 'master') and interface.master and \
               isinstance(interface.master, basestring):
                if interface.master in new_bond_names:
                    # The tasks for slaves devices will be created after bond,
                    # look at the block of code below regarding to
                    # interface.item_type_id == 'bond'
                    pass
                else:
                    # In this case, the slave device task will be created
                    # assuming that the bond already exists in the system.

                    bond_master = [bond for bond in all_bonds
                                   if bond.device_name == interface.master][0]

                    slaves = self._get_slaves_devices(node, bond_master)
                    for i, slave in enumerate(slaves):
                        if slave == interface:
                            NetworkPlugin._add_before_device_kwarg(kwargs,
                                                                   slaves, i)
                            break

                    NetworkPlugin._add_slave_eth_kwargs(interface, kwargs)
                    tasks.append(self._device_task_interface(
                        node, interface, kwargs, verb))

            else:
                kwargs['hwaddr'] = interface.macaddress
                tasks.append(self._device_task_interface(node, interface,
                                                         kwargs, verb))

        elif interface.item_type_id == 'bridge':
            kwargs['type'] = 'Bridge'
            kwargs['stp'] = 'off' if interface.stp == 'false' else 'on'
            kwargs['delay'] = interface.forwarding_delay
            kwargs['hotplug'] = 'no'
            kwargs['bridging_opts'] = \
                            NetworkPlugin._gen_bridging_options_str(interface)

            tasks.append(self._device_task_interface(node, interface,
                                                     kwargs, verb))

        elif interface.item_type_id == 'vlan':
            kwargs['vlan'] = 'yes'

            # Prevent udevd from interfering. By adding the parameter here it
            # won't take affect until a device is reconfigured by a plan.
            kwargs['hotplug'] = 'no'

            # If a bond is VLAN tagged, it will screw up if the underlying
            # bond was bought up without any slaves defined.
            tagged_device = NetworkPlugin._extract_nic(interface.device_name)
            kwargs['required_device'] = tagged_device

            tasks.append(self._device_task_interface(node, interface,
                                                     kwargs, verb))

        elif interface.item_type_id == 'bond':

            kwargs['type'] = 'Bonding'
            kwargs['hotplug'] = 'no'
            kwargs['bonding_opts'] = \
                             NetworkPlugin._gen_bonding_options_str(interface)
            vlans_on_bond = self._get_vlan_devices(node, interface)

            if interface.is_updated() and vlans_on_bond:
                kwargs['vlans_on_bond'] = ' '.join([v.device_name
                                                    for v in vlans_on_bond])

            slaves = self._get_slaves_devices(node, interface)
            kwargs['required_device'] = \
                           self.get_required_slave_for_bond(interface, slaves)

            if NetworkPlugin._requires_arp_ip_cleaning(interface):
                arp_ips_to_clean = self._gen_arp_ips_to_clean(interface)
                kwargs["arp_ip_targets_to_clean"] = arp_ips_to_clean

            if NetworkPlugin._requires_primary_cleaning(interface):
                kwargs["primary_cleaning"] = 'true'

            bond_task = self._device_task_interface(node, interface,
                                                    kwargs, verb)

            # TORF-323439: if the bond arp_ip_target property was updated
            self._mark_bond_update_arp_ip_target(node, interface, bond_task)

            if interface.is_initial():
                # The loop below will create a chaining
                # of required devices but using the "before"
                # puppet relationship metaparameter.
                for i, slave in enumerate(slaves):
                    slave_kwargs = self._build_kwargs(context, slave)

                    NetworkPlugin._add_slave_eth_kwargs(slave, slave_kwargs)
                    NetworkPlugin._add_before_device_kwarg(slave_kwargs,
                                                           slaves, i)
                    st = self._device_task_interface(node, slave,
                                                     slave_kwargs, verb)
                    tasks.append(st)

                    # Associate bond task with slave model item - LITPCDS-7426
                    msg = 'Adding slave {0} model item to bond {1} task'.\
                          format(slave, interface)
                    _LOG.trace.debug(msg)
                    bond_task.model_items.add(slave)

            tasks.append(bond_task)
        return tasks

    def _is_arp_ip_target_property_updated(self, bond_interface):
        if not bond_interface.is_updated():
            return False
        try:
            if bond_interface.arp_ip_target != \
                bond_interface.applied_properties['arp_ip_target']:
                return True
        except KeyError:
            pass
        return False

    def _mark_bond_update_arp_ip_target(self, node, interface, bond_task):
        if not node.is_ms() and \
            self._is_arp_ip_target_property_updated(interface):
            bond_task._pre_vxvm_bond = True

    def _get_vlan_devices(self, node, iface):
        vlans = NetworkPlugin._net_ifaces_by_type(node, 'vlan')
        vlans_on_bond = [v for v in vlans if \
                         iface.device_name == NetworkPlugin._extract_nic(\
                                                        v.device_name)]
        return vlans_on_bond

    def _get_slaves_devices(self, node, iface):
        eths = NetworkPlugin._net_ifaces_by_type(node, 'eth')
        slaves = [e for e in eths if hasattr(e, 'master') and
                  e.master == iface.device_name]
        slaves.sort(lambda a, b: cmp(a.device_name, b.device_name))
        return slaves

    def _device_task_interface(self, node, interface, kwargs, verb):

        message = '{0} {1} "{2}" on node "{3}"'.format(
                verb, interface.item_type_id,
                interface.device_name, node.hostname)

        task = ConfigTask(node, interface,
            message,
            'litpnetwork::config',
            interface.device_name,
            ensure='present',
            bootproto='static',
            onboot='yes',
            nozeroconf='yes',
            userctl='no',
            **kwargs)

        _LOG.trace.debug('Add %s task: "%s"' % (interface.item_type_id, task))
        return task

    @staticmethod
    def _find_ip_network(context, interface):
        networks = None
        if hasattr(interface, 'network_name'):
            networks = context.query("network", name=interface.network_name)

        _LOG.trace.debug('Network is: %s' % networks)

        if networks and hasattr(networks[0], 'subnet') and networks[0].subnet:
            _LOG.trace.debug('Interface "%s" bound to network "%s"' %
                             (interface.device_name, networks[0].name))
            return IPNetwork(networks[0].subnet)

        elif networks and not hasattr(networks[0], 'subnet'):
            _LOG.trace.debug('Interface "%s" is bound to non-IP network'
                             % (interface.device_name))
            return None
        else:
            _LOG.trace.debug('Interface "%s" is not bound to any '
                             'network' % (interface.device_name))
            return None

    @staticmethod
    def _ip_in_network(context, network_name, ip):
        networks = context.query('network', name=network_name)
        if networks and hasattr(networks[0], 'subnet') and networks[0].subnet:
            net = IPNetwork(networks[0].subnet)
            return IPAddress(ip) in net

    @staticmethod
    def _device_network_is_changed(device):
        return device.properties.get('network_name') != \
               device.applied_properties.get('network_name')

    @staticmethod
    def _device_ipv6address_is_changed(device):
        return device.properties.get('ipv6address') != \
               device.applied_properties.get('ipv6address')

    @staticmethod
    def _valid_real_devices(net_ifaces):
        return [iface for iface in net_ifaces \
                if iface.item_type_id != 'network-interface' \
                    and not iface.is_for_removal()]

    @staticmethod
    def _valid_ipv4_and_ipv6_routes(node):
        return [route for route in node.routes \
                if ('route' == route.item_type_id or
                    'route6' == route.item_type_id) and \
                    not route.is_for_removal()]

    @staticmethod
    def _valid_ipv4_routes(node_routes):
        return [route for route in node_routes \
                if 'route' == route.item_type_id and \
                  not route.is_for_removal()]

    @staticmethod
    def _valid_ipv6_routes(node_routes):
        return [route for route in node_routes \
                if 'route6' == route.item_type_id and \
                   not route.is_for_removal()]

    @staticmethod
    def _subnet_updated(network):
        if network and network.is_updated():
            if (network.applied_properties.get("subnet") !=
                network.subnet):
                return True
        return False

    @staticmethod
    def _netmask(context, interface):
        network = NetworkPlugin._find_ip_network(context, interface)
        if network:
            return str(network.netmask)

    @staticmethod
    def _network(context, interface):
        network = NetworkPlugin._find_ip_network(context, interface)
        if network:
            return str(network.network)

    @staticmethod
    def _broadcast(context, interface):
        network = NetworkPlugin._find_ip_network(context, interface)
        if network:
            return str(network.broadcast)

    def _new_routes_tasks(self, context):
        tasks = []
        for node in self._all_nodes(context):

            node_tasks = []
            node_devices_with_routes = set()

            for device in node.network_interfaces:
                if device.is_for_removal():
                    continue

                device_routes = []
                do_setup = False

                for route in self._valid_ipv4_routes(node.routes):
                    # for LITPCDS-7403, we need to clean old routes for device
                    # If route gateway was in old device network and
                    # device network changed, then device route must be updated
                    if device.is_updated() and \
                           device.applied_properties.get('network_name') and \
                           self._device_network_is_changed(device):
                        if self._ip_in_network(context,
                                device.applied_properties.get('network_name'),
                                route.gateway):
                            do_setup = True

                    if NetworkPlugin._reached_via(context,
                                                  route.gateway, device):
                        _LOG.trace.debug('Layer 2 interface used to reach '
                                         '{0} from {1}: {2}'. format(
                                             route.gateway, node.hostname,
                                             device.device_name))

                        route_props = NetworkPlugin._route_props(route)[:-1]
                        device_routes.append(route_props)

                        # If route is not yet applied
                        # or device network has been updated

                        do_setup = True if not route.is_applied() or \
                        self._device_network_is_changed(device) else do_setup

                        # We need to apply routes for this device
                        # *irrespective* of whether they are updated or already
                        # applied
                        node_devices_with_routes.add(device.device_name)

                    # If route is updated, note the previous device
                    old_gateway = NetworkPlugin._old_gateway(route)
                    if old_gateway:
                        route_moved = NetworkPlugin._reached_via(context,
                                                           old_gateway, device)
                        if route_moved:
                            curr_device = NetworkPlugin.\
                                    _device_name_for_IPv4_route(context, node,
                                            route.gateway)

                            _LOG.trace.debug(('The gateway for route "{0}" '
                                'was previously reached through "{1}" - now '
                                '"{2}"').format(route, device.device_name,
                                                curr_device.device_name))

                            _LOG.trace.debug('Add "%s" to cleanup list.' %
                                            (device.device_name))
                            do_setup = True
                            node_devices_with_routes.add(device.device_name)

                # In order to preserve consistent route order in the route-<if>
                # files, sort the IPv4 routes according to destination subnets
                device_routes.sort(cmp=sort_route_destinations)

                # Recap node's routes in the logs
                _LOG.trace.debug('Device "%s" IPv4 routes: %s' %
                                 (device.device_name, str(device_routes)))

                # Hang the route task on the node's interface that will be used
                # to reach the route's gateway

                for route in self._valid_ipv6_routes(node.routes):

                    # for LITPCDS-7403, we need to clean old routes for device
                    # If route gateway was in old device network and
                    # device network changed, then device route must be updated
                    if device.is_updated() and \
                           device.applied_properties.get('ipv6address') and \
                           self._device_ipv6address_is_changed(device):
                        net = NetworkPlugin._network_from_ipv6address(\
                              device.applied_properties.get('ipv6address'))
                        do_setup = IPAddress(route.gateway) in net

                    if NetworkPlugin._IPv6_reached_via(route.gateway, device):
                        _LOG.trace.debug('Layer 2 interface used to reach '
                                         '{0} from {1}: {2}'. format(
                                             route.gateway, node.hostname,
                                             device.device_name))

                        device_routes.append((route.subnet, False,
                                              route.gateway))

                        # Regardless route is applied or not, if new ip
                        # differs from old ip, route must be re-applied

                        do_setup = True if not route.is_applied() or\
                            self._device_ipv6address_is_changed(device) else \
                            do_setup

                        # We need to apply routes for this device
                        # *irrespective* of whether they are updated or already
                        # applied
                        node_devices_with_routes.add(device.device_name)

                    # If route is updated, note the previous device
                    old_gateway = NetworkPlugin._old_gateway(route)
                    if old_gateway:
                        route_moved = NetworkPlugin._IPv6_reached_via(
                                old_gateway, device)
                        if route_moved:
                            curr_device = NetworkPlugin.\
                                    _device_name_for_IPv6_route(node,
                                            route.gateway)

                            _LOG.trace.debug(('The gateway for route "{0}" '
                                'was previously reached through "{1}" - now '
                                '"{2}"').format(route, device.device_name,
                                                curr_device.device_name))

                            _LOG.trace.debug('Add "%s" to cleanup list.' %
                                            (device.device_name))
                            do_setup = True
                            node_devices_with_routes.add(device.device_name)

                _LOG.trace.debug('Device "%s" IPv6 routes: %s' %
                                 (device.device_name, str(device_routes)))

                if device_routes and do_setup:
                    # We only want one task per device for all non-local routes
                    description = ('Write route configuration for node '
                                   '"{node}" via interface "{iface}".').format(
                                       node=node.hostname,
                                       iface=device.device_name)
                    node_tasks.append(RouteTask(
                        node,
                        device,
                        description,
                        "{0}_routes".format(device.device_name),
                        device=device.device_name,
                        routes=device_routes,
                    ))

                elif do_setup:
                    # this is the old device that's left without routes
                    description = ('Clean up routes on interface'
                                    ' "{iface}" on node "{node}"').format(
                                        iface=device.device_name,
                                        node=node.hostname)
                    node_tasks.append(RouteTask(
                        node,
                        device,
                        description,
                        "{0}_routes".format(device.device_name),
                        device=device.device_name,
                        routes=list(),
                    ))

                else:
                    _LOG.trace.debug("Skip setup as all routes on this "
                        "node's {0} interface are applied.".format(
                            device.device_name)
                    )

            if node_tasks:
                # We need to add a ConfigTask that will actually apply the
                # routes
                # XXX(xigomil) Temporarily hanging this task
                # off the first interface to move it into the same phase
                # as all other routes-related tasks.
                if_path = sorted([i for i in node.network_interfaces],
                                 key=lambda nic: nic.device_name)[0]

                node_tasks.append(ConfigTask(
                        node,
                        if_path,
                        'Apply routes on node "{node}"'.format(
                            node=node.hostname
                            ),
                        'litpnetwork::route_reload',
                        "{0}_route_reload".format(node.hostname),
                        devices=list(node_devices_with_routes),
                        subscribe=[{
                            'type': 'Litpnetwork::Route',
                            'value': "{0}_routes".format(s)} for s in \
                                  node_devices_with_routes]
                    ))

            tasks.extend(node_tasks)

        _LOG.trace.debug(tasks)
        return tasks

    @staticmethod
    def _old_gateway(route):
        old_gateway = None
        if route.is_updated():
            # We need to act if the gateway has changed
            if route.gateway != route.applied_properties.get('gateway'):
                old_gateway = route.applied_properties.get('gateway')
        return old_gateway

    @staticmethod
    def _route_props(route):
        old_gateway = NetworkPlugin._old_gateway(route)
        route_dest = IPNetwork(route.subnet)
        route_props = (str(route_dest.network),
                       str(route_dest.netmask),
                       route.gateway,
                       old_gateway)
        return route_props

    @staticmethod
    def _network_from_ipv6address(ipv6address):
        """
        Returns a netaddr.IPNetwork object instantiated from a
        network-interface model item's ipv6address property. If the prefix is
        absent from the property value, it defaults to /64
        """
        if '/' in ipv6address:
            return IPNetwork(ipv6address)
        else:
            return IPNetwork(ipv6address + '/64')

    @staticmethod
    def _IPv6_reached_via(v6_route_gateway, device):
        if not hasattr(device, 'ipv6address') or not device.ipv6address:
            return False

        v6_device_net = NetworkPlugin._network_from_ipv6address(
                device.ipv6address
            )
        return IPAddress(v6_route_gateway) in v6_device_net

    @staticmethod
    def _reached_via(context, route_gateway, device):
        reached_via = False
        _LOG.trace.debug('is {0} reachable via {1}'.format(route_gateway,
            device))

        net = NetworkPlugin._find_ip_network(context, device)
        if net and IPAddress(route_gateway) in net:
            reached_via = True

        return reached_via

    @staticmethod
    def _device_name_for_IPv4_route(context, node, route_gateway):
        # Ignore interfaces with no network_names - eg bridged interfaces
        # Ignore interfaces with no ipaddresses - eg heartbeats
        device = None
        for l2_interface in node.network_interfaces:
            if (not hasattr(l2_interface, 'network_name') \
                or not l2_interface.network_name) \
                    or (not hasattr(l2_interface, 'ipaddress') \
                        or not l2_interface.ipaddress):
                continue

            # Get the network with matching name
            matching_net = context.query('network',
                                         name=l2_interface.network_name)[0]

            _LOG.trace.debug('Node {0}\'s interface {1} bound to network '
                             '{2}'.format(node.hostname,
                                          l2_interface.device_name,
                                          matching_net.name))

            if IPAddress(route_gateway) in \
                        IPNetwork(matching_net.subnet):
                device = l2_interface
                break

        if device:
            _LOG.trace.debug('Found device "{device_name}" on node "{node}" '
                             'to use for route with gateway "{route}"'.format(
                                 device_name=device.device_name,
                                 node=node.hostname,
                                 route=route_gateway))
        return device

    @staticmethod
    def _device_name_for_IPv6_route(node, route_gateway):
        # Ignore interfaces with no network_names - eg bridged interfaces
        # Ignore interfaces with no ipaddresses - eg heartbeats
        device = None
        for l2_interface in node.network_interfaces:
            if (not hasattr(l2_interface, 'network_name') \
                or not l2_interface.network_name) \
                    or (not hasattr(l2_interface, 'ipv6address') \
                        or not l2_interface.ipv6address):
                continue

            if IPAddress(route_gateway) in \
                    NetworkPlugin._network_from_ipv6address(
                            l2_interface.ipv6address):
                device = l2_interface
                break

        if device:
            _LOG.trace.debug('Found device "{device_name}" on node "{node}" '
                 'to use for route with gateway "{route}"'.format(
                     device_name=device.device_name,
                     node=node.hostname,
                     route=route_gateway))
        return device

    @staticmethod
    def _all_nodes(context):
        return [node for node in (context.query('node') + context.query('ms'))
                if not node.is_for_removal()]

    @staticmethod
    def _master_changed(eth):
        if 'master' not in eth.applied_properties:
            return False

        return eth.applied_properties['master'] != eth.master

    @staticmethod
    def _ipaddress_changed(interface):
        return ('ipaddress' not in interface.applied_properties or
                    interface.applied_properties['ipaddress'] !=
                        interface.ipaddress)

    @staticmethod
    def _networks(context):
        return [net for net in context.query('network')
                if not net.is_for_removal()]

    @staticmethod
    def _management_networks(context):
        return [net for net in context.query('network', litp_management='true')
                if not net.is_for_removal()]

    @staticmethod
    def _management_network(context):
        networks = NetworkPlugin._management_networks(context)
        return networks[0] if 1 == len(networks) else None

    @staticmethod
    def _removed_net_ifaces_by_type(node, net_iface_type):
        return [item for item in node.query(net_iface_type)
                if item.is_for_removal()]

    @staticmethod
    def _all_net_ifaces_by_type(node, net_iface_type):
        return [item for item in node.query(net_iface_type)]

    @staticmethod
    def _net_ifaces_by_type(node, net_iface_type):
        return [item for item in node.query(net_iface_type)
                if not item.is_for_removal()]

    @staticmethod
    def _net_iface_by_device_name(node, device_name):
        device = [item for item in node.query('network-interface',
                                              device_name=device_name)
                  if not item.is_for_removal()]
        if len(device) == 1:
            return device[0]
        else:
            return None

    @staticmethod
    def get_vlan_device_names(node):
        vlans = NetworkPlugin._net_ifaces_by_type(node, 'vlan')
        return [NetworkPlugin._extract_nic(vlan.device_name) for vlan in vlans]

    @staticmethod
    def _extract_nic(device_name):
        parts = device_name.split('.', 1)
        if parts and len(parts) == 2:
            return parts[0]
        return None

    @staticmethod
    def _get_subnet_for_net_name(net_name, networks):
        for net in networks:
            if net.name == net_name:
                return net.subnet

        return None

    # Validation methods below this line
    # -----------------------------------

    def validate_model(self, context):
        """
        Validates network model integrity. Validation rules enforced by this
        plugin are:

        - Rules exclusive to the MS:

          - The ``network-interface`` item bound to the LITP management \
            network on the MS must have an IPv4 address.

          - The property ``pxe_boot_only`` cannot be set on the MS.

        - Rules exclusive to the MNs:

          - The ``network-interface`` item bound to the LITP management \
            network on the MNs cannot be VLAN tagged.

          - The ``pxe_boot_only`` property of a ``eth`` item only can be \
            set to true in one interface of the node.

          - The ``pxe_boot_only`` property of a ``eth`` item is only allowed \
            in nodes in ``Initial`` state.

          - The ``eth`` item cannot be tagged when the property \
            ``pxe_boot_only`` is set to true.

        - Rules common to the MS and MNs:

          - The ``network_name`` property of interfaces in the node's \
            ``network_interfaces`` Collection do not reference the same \
            network more than once.

          - The network tagged with ``litp_management=true`` is the \
            ``network_name`` of one interface for every node.

          - The ``device_name`` properties of items of type \
            ``network-interface`` do not overlap within a given node's \
            ``network_interfaces`` Collection.

          - The ``device_name`` property of a ``bridge`` cannot be changed \
            once the bridge has been set up.

          - The ``bridge`` property of an interface item matches the \
            ``device_name`` property of one ``bridge`` item under its \
            parent node's ``network_interfaces`` Collection.

          - A ``network-interface`` cannot be a member of a ``bridge`` \
            and have a ``network_name`` property

          - A ``network-interface`` cannot be a member of a ``bridge`` \
            and have an ``ipaddress`` property

          - The ``ipaddress`` property of each item of type \
            ``network-interface`` in a node's ``network_interfaces`` \
            Collection fits within the subnet defined on the network \
            item with a matching name.

          - The ``ipaddress`` property of each item of type \
            ``network-interface`` in a node's ``network_interfaces`` \
            Collection is neither the network nor the broadcast \
            address of the network item with a matching name.

          - IP addresses, where present on a node's ``network-interface``
            items, are unique within that node.

          - IP addresses are unique within a network.

          - MAC addresses, where present on a node's ``network-interface``
            items, are unique within that node.

          - A ``network-interface`` item must have its ``ipaddress`` property \
            set if the network it references through its ``network_name`` \
            property has a ``subnet`` property.

          - A ``network-interface`` item that references a non-IP network \
            through its ``network_name`` property must not have its \
            ``ipaddress`` property set.

          - The maximum number of ``VLANs`` per node is 4094.

          - A ``VLAN`` device-name must be formatted as: \
            ``<valid eth device-name><dot><VLAN ID>``

          - A ``VLAN`` ID must be unique per Node.

          - A ``Bond`` must have slave ``eth`` items.

          - The ``master`` of an ``eth`` must be a valid ``Bond``

          - The ``master`` of an ``eth`` cannot be changed or deleted \
            but may be added.

          - An ``eth`` should not be both Bonded and VLAN tagged.

          - The swapping of ``ipaddress`` or ``ipv6address`` property values \
            between nodes on the same ``network`` is not supported.

          - The actual applied values of ``rx_ring_buffer`` and \
            ``tx_ring_buffer`` will depend on the specific \
            ``network-interface`` driver implementation and may not match \
            the values stored in the model.

          - The actual applied value of ``txqueuelen`` will depend on the \
            specific ``network-interface`` driver implementation and may \
            not match the values stored in the model.

          - The ``xmit_hash_policy`` property for a ``bond`` can only be \
            set if the bonding ``mode`` is one of 2, balance-xor, 4, \
            802.3ad.

          - Once set, the ``txqueuelen`` property can not be deleted.

        - Networks

          - All ``network`` items defined in \
            ``/infrastructure/networking/networks`` must have have a unique
            ``name`` property.

          - Only one ``network`` is tagged with ``litp_management=true``.

          - The subnets of IPv4 networks associated with IPv4 addresses \
            on a node must not overlap.

          - The subnets of IPv6 addresses on a node must not overlap.

          - The value of the ``subnet`` property must be a valid IPv4 network.

          - Base item types ``network-interface`` are not allowed in the model.

        - Routes:

          - All ``route`` items referenced from a node or MS must \
            have distinct destination subnets.

          - All ``route`` items referenced from a node or MS must \
            have a gateway address directly reachable from that system.

          - Prevent removal of ``route`` item from the node.

          - IPv6 local addresses cannot be used as gateway.

          - Base item types ``route-base`` are not allowed in the model.
        """

        preamble = '.validate_model: '

        errors = []

        errors += self._validate_network_names_unique(context)
        errors += self._validate_only_one_mgmt_network(context)
        errors += self._validate_macs_unique(context)
        errors += self._validate_consistent_network_v6_subnets(context)

        mgmt_net = NetworkPlugin._management_network(context)
        networks = NetworkPlugin._networks(context)

        all_nodes = self._all_nodes(context)
        errors += self._validate_no_base_route_items(all_nodes)
        errors += self._validate_ips_unique_in_network(all_nodes)
        errors += self._validate_no_ip_swapping(all_nodes)

        for node in all_nodes:

            if node.is_ms():
                errors += self._validate_pxe_boot_only_ms(node)
            else:
                errors += self._validate_pxe_boot_only_node(node)

            if mgmt_net:
                if node.is_ms():
                    errors += self._validate_ms_mgmt_ip_not_removed(node,
                                                                    mgmt_net)
                else:
                    errors += self._validate_vlan_on_nodes_not_mgmt(node,
                                                                    mgmt_net)

                errors += self._validate_mgmt_network_usage(node, mgmt_net)
                errors += self._validate_ipv6_mgmt_is_dual_stack(node,
                                                                 mgmt_net)
            else:
                _LOG.trace.debug(preamble +
                                 "No management network to validate against.")

            errors += self._validate_only_supported_types_present(node)
            errors += self._validate_device_names_unique(node)
            errors += self._validate_ips_unique_in_node(node)
            errors += self._validate_vlan_ids_unique(node)

            errors += self._validate_network_subnets_overlap(node, networks)
            errors += self._validate_network_name_usage(node, networks)
            errors += self._validate_ips_valid_for_network(node, networks)
            errors += self._validate_interface_l3_config(node, networks)
            errors += self._validate_node_routes(node, networks)

            errors += \
                self._validate_bridged_interface_bridge_valid_device_name(node)

            errors += self._validate_bridge_is_used(node)

            errors += self._validate_vlan_count(node)
            errors += self._validate_format_vlan_device_names(node)

            errors += self._validate_bond_used_by_eth(node)
            errors += self._validate_eth_master_is_bond(node)
            errors += self._validate_eth_not_bonded_and_tagged(node)
            errors += self._validate_bond_and_all_slaves_removed(node)
            errors += self._validate_bond_primary_is_slave(node)
            errors += self._validate_txqueuelen_not_deleted(node)
        return errors

    def _validate_txqueuelen_not_deleted(self, node):
        """
        Validate that txqueuelen is not being deleted once it has been
        set/applied, this it currently not supported.

        :param node: Node containing eth devices
        :returns: List of validation errors. Empty list means no errors found.
        :rtype: list
        """
        errors = []
        interfaces = NetworkPlugin._net_ifaces_by_type(node, 'eth')
        for iface in interfaces:
            if iface.is_updated():
                not_currently_set = getattr(iface, 'txqueuelen', None) is None
                was_set = 'txqueuelen' in iface.applied_properties
                if was_set and not_currently_set:
                    msg = 'The txqueuelen property can not be ' \
                          'removed once set.'
                    errors.append(ValidationError(
                            item_path=iface.get_vpath(),
                            error_message=msg
                    ))
        return errors

    def _validate_pxe_boot_only_ms(self, ms):
        """
        Validate that only one eth device has pxe_boot_only=true set
        :param all_nodes: List of nodes to check
        :returns: List of validation errors. Empty list means no errors found.
        :rtype: list
        """
        errors = []
        pxe_boot_only_nics = [nic for nic in ms.network_interfaces
                if getattr(nic, 'pxe_boot_only', None)]

        msg = 'Property "pxe_boot_only" cannot be set on the "ms"'

        for nic in pxe_boot_only_nics:
            vpath = nic.get_vpath()
            errors.append(ValidationError(error_message=msg, item_path=vpath))

        return errors

    def _validate_pxe_boot_only_node(self, node):
        """
        Validate that only one eth device has pxe_boot_only=true set
        :param all_nodes: List of nodes to check
        :returns: List of validation errors. Empty list means no errors found.
        :rtype: list
        """
        errors_info = []
        vlan_nic_devs = NetworkPlugin.get_vlan_device_names(node)

        pxe_boot_only_nics = [nic for nic in node.network_interfaces
                if getattr(nic, 'pxe_boot_only', 'false') == 'true'
                and not nic.is_for_removal()]
        multiple_nics_error = len(pxe_boot_only_nics) > 1

        for nic in pxe_boot_only_nics:
            if nic.device_name in vlan_nic_devs:
                msg = ('Item "eth" cannot be tagged when '
                       '"pxe_boot_only" property is set to "true"')
                errors_info.append((msg, nic.get_vpath()))

            if not node.is_initial() and not nic.is_applied():

                msg = ('Property "pxe_boot_only" can be set to '
                       '"true" only on nodes in "Initial" state')
                errors_info.append((msg, nic.get_vpath()))

            if multiple_nics_error:
                msg = ('Property "pxe_boot_only" can be set to "true" on only '
                       'one interface on node "{0}"'.format(node.hostname))

                errors_info.append((msg, nic.get_vpath()))

        errors = []
        for msg, vpath in errors_info:
            errors.append(ValidationError(error_message=msg, item_path=vpath))

        return errors

    def _validate_no_ip_swapping(self, all_nodes):

        errors = []

        for node in all_nodes:
            for nic in node.network_interfaces:
                if nic.is_for_removal():
                    continue

                if hasattr(nic, 'ipaddress') and \
                   nic.ipaddress and \
                   (nic.is_initial() or \
                    (nic.is_updated() and \
                     NetworkPlugin._ipaddress_changed(nic))):
                    errors += self._veto_swap_ip_address('IPv4', node,
                                                         nic, all_nodes)

                if hasattr(nic, 'ipv6address') and \
                   nic.ipv6address and \
                   (nic.is_initial() or \
                    (nic.is_updated() and \
                     NetworkPlugin._device_ipv6address_is_changed(nic))):
                    errors += self._veto_swap_ip_address('IPv6', node,
                                                         nic, all_nodes)

        return errors

    def _veto_swap_ip_address(self, version, current_node, nic, all_nodes):

        preamble = '._veto_swap_ip_address: '
        errors = []

        for node in all_nodes:
            if node == current_node:
                continue

            for iface in node.network_interfaces:
                if iface.is_for_removal():
                    continue

                create_error = False

                if version == 'IPv4':
                    if self._ipaddress_changed(iface) and \
                       nic.ipaddress == \
                                    iface.applied_properties.get('ipaddress'):
                        create_error = True

                elif version == 'IPv6':
                    if self._device_ipv6address_is_changed(iface) and \
                       nic.ipv6address == \
                                   iface.applied_properties.get('ipv6address'):
                        create_error = True

                if create_error:
                    old_iface_net = \
                                  iface.applied_properties.get('network_name')
                    new_iface_net = iface.network_name
                    iface_net = old_iface_net if old_iface_net \
                                    else new_iface_net

                    if not nic.network_name == iface_net:
                        continue

                    msg = ('Swapping %s address on network "%s" with Applied '
                           '%s address on node "%s" is not supported') % \
                           (version, nic.network_name, version, node.hostname)
                    _LOG.trace.debug(preamble + msg)
                    error = ValidationError(error_message=msg,
                                            item_path=nic.get_vpath())
                    errors.append(error)
                    break

        return errors

    def _validate_no_base_route_items(self, nodes):
        '''
        Veto the use of base item network-interface or route-base in the model
        '''
        errors = []
        for node in nodes:
            for rte in node.routes:
                if rte.item_type_id == 'route-base':
                    msg = 'Base item type "route-base" is not allowed'
                    errors.append(ValidationError(error_message=msg,
                                            item_path=rte.get_vpath()))
        return errors

    def _validate_network_subnets_overlap(self, node, networks):
        '''
        Veto the overlap of network subnets on a per node basis.
        '''

        errors = []

        ipv4_subnets = dict()
        ipv6_subnets = list()

        for net_iface in node.network_interfaces:
            if net_iface.is_for_removal():
                continue

            if hasattr(net_iface, 'network_name') and \
                        net_iface.network_name:
                subnet = self._get_subnet_for_net_name(\
                                net_iface.network_name, networks)
                if subnet:
                    local_net = IPNetwork(subnet)
                    #No op if duplicate network name found
                    #as this case is handled in 'validate_network_name_usage'
                    if net_iface.network_name in ipv4_subnets:
                        pass
                    else:
                        ipv4_subnets[net_iface.network_name] = (local_net, \
                                                        net_iface.get_vpath())

            if hasattr(net_iface, 'ipv6address') and net_iface.ipv6address:
                local_net = NetworkPlugin._network_from_ipv6address(\
                                            net_iface.ipv6address)
                ipv6_subnets.append((local_net, net_iface.get_vpath()))

        unique_ipv4subnets = list(ipv4_subnets.values())

        errors += self._compare_subnets_on_node(unique_ipv4subnets, node)
        errors += self._compare_subnets_on_node(ipv6_subnets, node)

        return errors

    def _compare_subnets_on_node(self, subnets, node):

        preamble = '._compare_subnets_on_node: ' + \
                   node.hostname + ': '

        msg = 'Overlapping network subnet ' + \
                          'defined on network interface '
        errors = []

        unique_error_subnet_vpaths = set()

        for i, left_sub in enumerate(subnets):
            for right_sub in subnets[i + 1:len(subnets)]:
                if left_sub[0].first <= right_sub[0].last \
                        and right_sub[0].first <= left_sub[0].last:

                    _LOG.trace.debug(preamble + msg)

                    unique_error_subnet_vpaths.add(left_sub[1])

                    unique_error_subnet_vpaths.add(right_sub[1])

        for path in unique_error_subnet_vpaths:
            errors.append(ValidationError(item_path=path,
                                  error_message=msg))
            _LOG.trace.debug(preamble + msg + path)

        return errors

    @staticmethod
    def _validate_bond_primary_is_slave(node):
        '''
        Veto bond primary names that are not
        slaves of the bond
        '''

        errors = []

        bonds = NetworkPlugin._net_ifaces_by_type(node, 'bond')
        eths = NetworkPlugin._net_ifaces_by_type(node, 'eth')

        for bond in bonds:
            if hasattr(bond, 'primary') and bond.primary:
                slaves = [eth.device_name for eth in eths
                          if hasattr(eth, 'master') and eth.master and
                          eth.master == bond.device_name]
                if bond.primary not in slaves:
                    msg = ('Primary value "%s" is not a valid '
                           'slave of this bond' % bond.primary)
                    err = ValidationError(item_path=bond.get_vpath(),
                                          error_message=msg)
                    errors.append(err)

        return errors

    @staticmethod
    def _validate_bond_and_all_slaves_removed(node):
        '''
        Veto removal of some slaves.
        The Bond & all slaves must be removed together
        '''

        preamble = '._validate_bond_and_all_slaves_removed: ' + \
                   node.hostname + ': '

        errors = []

        removed_slaves = [eth for eth in node.query('eth')
                          if hasattr(eth, 'master') and eth.master and
                             eth.is_for_removal()]

        for eth in removed_slaves:
            peers = [e for e in node.query('eth')
                     if hasattr(e, 'master') and e.master and
                        e.master == eth.master and e != eth]

            if any((not peer.is_for_removal()) for peer in peers):
                msg = ('All eth peers of "%s" and slaves of Bond "%s" ' + \
                       'must be removed in the same plan.') % \
                       (eth.device_name, eth.master)

                _LOG.trace.debug(preamble + msg)

                err = ValidationError(item_path=eth.get_vpath(),
                                      error_message=msg)
                errors.append(err)

            bonds = [b for b in node.query('bond')
                     if b.device_name == eth.master]

            if bonds:
                removed_bonds = [b for b in bonds if b.is_for_removal()]

                if not removed_bonds:
                    msg = 'Bond "{0}" does not have state \'ForRemoval\' ' \
                          'while slave eths do. A Bond and all slave eths ' \
                          'must be removed in the ' \
                          'same plan.'.format(eth.master)
                    _LOG.trace.debug(preamble + msg)

                    err = ValidationError(item_path=eth.get_vpath(),
                                          error_message=msg)
                    errors.append(err)

        if len(removed_slaves) == 0:
            removed_bonds = \
                NetworkPlugin._removed_net_ifaces_by_type(node, 'bond')
            if removed_bonds:
                for rem_bond in removed_bonds:
                    msg = 'bond "{0}" has state \'ForRemoval\' while '\
                    'its slave eths do not. A Bond and all slave eths must '\
                    'be removed in the same plan.'.format(rem_bond.device_name)
                    _LOG.trace.debug(preamble + msg)

                    err = ValidationError(item_path=rem_bond.get_vpath(),
                                          error_message=msg)
                    errors.append(err)

        return errors

    @staticmethod
    def _validate_eth_not_bonded_and_tagged(node):
        """
        An eth should not be Bonded and VLAN tagged
        """

        preamble = '._validate_eth_not_bonded_and_tagged: ' + \
                   node.hostname + ': '

        errors = []

        eths = NetworkPlugin._net_ifaces_by_type(node, 'eth')
        vlans = NetworkPlugin._net_ifaces_by_type(node, 'vlan')

        bond_eth_devs = [eth.device_name for eth in eths
                           if hasattr(eth, 'master') and eth.master]

        vlan_nic_devs = [NetworkPlugin._extract_nic(vlan.device_name)
                         for vlan in vlans]

        if bond_eth_devs and vlan_nic_devs:

            intersection = set(bond_eth_devs).intersection(set(vlan_nic_devs))

            if intersection:
                msg = 'The following network interfaces are Bonded and ' + \
                      'VLAN tagged; this is not currently supported: ' + \
                      ', '.join(intersection)

                _LOG.trace.debug(preamble + msg)

                err = ValidationError(
                                item_path=node.network_interfaces.get_vpath(),
                                error_message=msg)
                errors.append(err)

        return errors

    @staticmethod
    def _validate_ms_mgmt_ip_not_removed(ms_node, mgmt_net):
        """
        Validates that none of the net_interface items on the MS (or
        specialisations of that base type) have had their ipaddress property
        removed if they are bound to the LITP management network.
        """

        _LOG.trace.debug('validate_ms_ip_not_removed')

        errors = list()
        for ms_interface in ms_node.network_interfaces:
            if not ms_interface.is_updated():
                continue

            if ms_interface.network_name != mgmt_net.name:
                continue

            _LOG.trace.debug('Mgmt interface {0} on MS is updated'.format(
                    ms_interface.get_vpath()
                ))

            # Do we have an IP address now?
            if not ms_interface.ipaddress:
                # We don't have an ipaddress
                # We should raise a ValidationError only if that MS interface
                # *did* have an ipaddress previously
                if 'ipaddress' in ms_interface.applied_properties and \
                        ms_interface.applied_properties['ipaddress']:
                    err = ValidationError(item_path=ms_interface.get_vpath(),
                            error_message='Removal of the IPv4 address from '
                            'the MS management interface is not currently '
                            'supported'
                            )
                    errors.append(err)
        return errors

    @staticmethod
    def _validate_only_one_mgmt_network(context):
        """
        Validates that one ``network`` item has the
        ``litp_management`` property set to true
        """

        preamble = '._validate_only_one_mgmt_network: '
        errors = []

        current_networks = NetworkPlugin._networks(context)

        if len(current_networks) > 0:
            mgmt_networks = NetworkPlugin._management_networks(context)

            msg = 'There must be exactly one network assigned ' \
                  'litp_management="true"'
            if len(mgmt_networks) == 0:
                _LOG.trace.debug((preamble + "{count} mgmt networks; " +
                                  msg).format(count=len(mgmt_networks)))

                parent_path = '/'.join(current_networks[0].get_vpath().
                                       split('/')[:-1])
                errors.append(ValidationError(parent_path, error_message=msg))

            elif len(mgmt_networks) > 1:
                _LOG.trace.debug((preamble + "{count} mgmt networks; " +
                                  msg).format(count=len(mgmt_networks)))
                error = ValidationError(mgmt_networks[0].get_vpath(),
                                        error_message=msg)
                errors.append(error)

        return errors

    @staticmethod
    def _validate_network_names_unique(context):
        """
        Validates that all ``network`` name properties are unique
        """
        preamble = '._validate_network_names_unique: '
        errors = []

        networks = context.query('network')
        for network in networks:
            if network.is_for_removal():
                continue

            net_names = [net.name for net in networks
                         if net != network and
                         net.name == network.name and
                         not net.is_for_removal()]
            if len(net_names) > 0:
                msg = ('Network name "{net}" '
                       'is not unique.').format(net=network.name)
                error = ValidationError(network.get_vpath(),
                                        error_message=msg)
                errors.append(error)
                _LOG.trace.debug(preamble + msg)

        return errors

    @staticmethod
    def _extract_vlan_ids(vlans):
        '''
        Extract just the 2nd part of each VLAN device name
        '''
        vlan_ids = []
        for vlan in vlans:
            (_, vid) = vlan.device_name.split('.', 2)
            vlan_ids.append((vlan, vid))
        return vlan_ids

    def _validate_vlan_ids_unique(self, node):
        """
        Validate that the ``VLAN`` IDs are all unique
        """

        preamble = '._validate_vlan_ids_unique: ' + \
                   node.hostname + ': '
        errors = []

        vlans = NetworkPlugin._net_ifaces_by_type(node, 'vlan')
        vlan_ids = self._extract_vlan_ids(vlans)

        id_interfaces = dict()

        for (vlan, vlan_id) in vlan_ids:
            if vlan_id not in id_interfaces:
                id_interfaces[vlan_id] = [vlan]
            else:
                id_interfaces[vlan_id].append(vlan)

        for vlan_id in id_interfaces.keys():
            if len(id_interfaces[vlan_id]) > 1:
                for vlan in id_interfaces[vlan_id]:
                    emsg = ('VLAN ID "%s" is used for more than one ' + \
                            'interface, it must be unique.') % \
                            vlan_id
                    _LOG.trace.debug(preamble + emsg)
                    errors.append(ValidationError(vlan.get_vpath(),
                                                  error_message=emsg))

        return errors

    @staticmethod
    def _validate_network_name_usage(node, networks):
        """
        Validate per node that a ``network`` is only assigned
        once to a network-interface.
        """

        preamble = '._validate_network_name_usage: ' + node.hostname + ': '
        errors = []

        for net_interface in node.network_interfaces:
            if not hasattr(net_interface, 'network_name') or \
               net_interface.network_name is None:
                continue

            if net_interface.is_for_removal():
                continue

            net_name_uses = [iface.network_name
                             for iface in node.network_interfaces
                             if hasattr(iface, 'network_name') and
                             iface.network_name and
                             iface != net_interface and
                             iface.network_name == net_interface.network_name
                             and not iface.is_for_removal()]
            if net_name_uses:
                for unused_name in net_name_uses:
                    msg = 'Network name "{0}" must be used '\
                    'by one network-interface.'.format(unused_name)
                    error = ValidationError(net_interface.get_vpath(),
                                            error_message=msg)
                    _LOG.trace.debug(preamble + msg)
                    errors.append(error)

            # but does it really exists
            used_networks = [net for net in networks
                             if net.name == net_interface.network_name and
                             not net.is_for_removal()]

            if len(used_networks) != 1:
                msg = 'Property network_name "{name}" '\
                    'does not match a defined network.'.format(
                    name=net_interface.network_name
                )
                error = ValidationError(net_interface.get_vpath(),
                                        error_message=msg)
                _LOG.trace.debug(preamble + msg)
                errors.append(error)

        return errors

    @staticmethod
    def _validate_mgmt_network_usage(node, mgmt_network):
        """
        Validate per node that the designated management network is
        assigned once among the network-interfaces.
        """

        preamble = '._validate_mgmt_network_usage: ' + node.hostname + ': '

        errors = []

        mgmt_ifaces = [iface for iface in node.network_interfaces
                       if hasattr(iface, 'network_name')
                       and iface.network_name is not None
                       and iface.network_name
                       and iface.network_name == mgmt_network.name
                       and not iface.is_for_removal()]

        if len(mgmt_ifaces) != 1:
            msg = "The management network must be used " + \
                  "for one network interface."
            if len(mgmt_ifaces) == 0:
                resource_path = node.get_vpath()
            else:
                resource_path = mgmt_ifaces[0].get_vpath()

            _LOG.trace.debug(preamble + msg)
            errors.append(ValidationError(resource_path, error_message=msg))

        return errors

    @staticmethod
    def _validate_device_names_unique(node):
        """
        Validate all network-interface device names are unique
        """

        preamble = '._validate_device_names_unique: ' + node.hostname + ': '
        errors = []

        unique_device_names = []
        for net_iface in NetworkPlugin._valid_real_devices(
                                        node.network_interfaces):

            device_name = net_iface.device_name
            if device_name not in unique_device_names:
                unique_device_names.append(device_name)
            else:
                msg = ('Interface with device_name "{device_name}" '
                    'is not unique.'.format(device_name=device_name))
                errors.append(ValidationError(net_iface.get_vpath(),
                                              error_message=msg))
                _LOG.trace.debug(preamble + msg)

        return errors

    @staticmethod
    def _validate_bridged_interface_bridge_valid_device_name(node):
        """
        Validate that the ``bridge`` property on an ``network_device`` item is
        the name of a bridge on the node.
        """

        preamble = '._validate_eth_bridge_valid_device_name: ' + \
                   node.hostname + ': '
        errors = []
        rem_bridges = []

        list_devices = []
        for nic in ['eth', 'bond', 'vlan']:
            list_devices += NetworkPlugin._net_ifaces_by_type(node, nic)

        for device in list_devices:
            if hasattr(device, 'bridge') and device.bridge:

                bridge = node.query('bridge', device_name=device.bridge)

                list_bridges = [bridge for bridge in
                        node.query('bridge', device_name=device.bridge)]
                rem_bridges = [rbridge for rbridge in
                        node.query('bridge', device_name=device.bridge) if
                        rbridge.is_for_removal()]

                if list_bridges and not rem_bridges:
                    continue
                # Assume duplicate bridge names checked for elsewhere
                if not list_bridges \
                    and not rem_bridges:
                    msg = ('Property bridge "{bridge}" does not '
                    'correspond to a valid bridge.'.\
                    format(bridge=device.bridge))
                    _LOG.trace.debug(preamble + msg)
                    errors.append(ValidationError(device.get_vpath(),
                                                  error_message=msg))

                elif rem_bridges:
                    msg = ('Property bridge "{0}" is not a valid bridge '
                   'as it has state \'ForRemoval\''.format(device.bridge))
                    _LOG.trace.debug(preamble + msg)
                    errors.append(ValidationError(device.get_vpath(),
                                                  error_message=msg))
        return errors

    @staticmethod
    def _validate_ips_valid_for_network(node, networks):
        """
        Validate that IP assigned to network-interfaces by network name
        are valid within the constraints of the Network.
        """

        preamble = '._validate_ips_valid_for_network: ' + node.hostname + ': '
        errors = []
        dict_ip_networks = dict()
        list_nonip_networks = []

        for network in networks:
            if  not network.is_for_removal():
                if network.subnet:
                    dict_ip_networks[network.name] = IPNetwork(network.subnet)
                else:
                    list_nonip_networks.append(network.name)

        for iface in NetworkPlugin._valid_real_devices(
                                    node.network_interfaces):
            if not hasattr(iface, 'network_name') \
                or iface.network_name is None:
                continue

            if hasattr(iface, 'network_name') and \
               hasattr(iface, 'ipaddress') and \
               iface.network_name and iface.ipaddress:
                if iface.network_name in list_nonip_networks:
                    # Eth in non-ip network has ipaddress. Caught elsewhere.
                    continue

                elif not iface.network_name in dict_ip_networks:
                    # Invalid names reported by _validate_network_name_usage()
                    pass
                else:
                    network_prefix = dict_ip_networks[iface.network_name]

                    try:
                        ip_addr = IPAddress(iface.ipaddress)
                    except AddrFormatError:
                        msg = "Invalid IP address."
                        errors.append(ValidationError(iface.get_vpath(),
                                                      error_message=msg))
                    else:
                        if ip_addr not in network_prefix:
                            msg = 'IP address "{ip}" not within subnet ' \
                                  '"{sub}" of network "{name}".'.format(
                                                      ip=iface.ipaddress,
                                                      sub=network_prefix,
                                                      name=iface.network_name)
                            _LOG.trace.debug(preamble + msg)
                            errors.append(ValidationError(iface.get_vpath(),
                                                          error_message=msg))
                        if ip_addr == network_prefix.network:
                            msg = 'Cannot assign IPv4 address "{0}" to this '\
                                    'interface as it is the network address '\
                                    'for its network "{1}".'.format(
                                            ip_addr,
                                            iface.network_name
                                        )
                            errors.append(ValidationError(
                                    item_path=iface.get_vpath(),
                                    error_message=msg
                                ))
                        if ip_addr == network_prefix.broadcast:
                            msg = 'Cannot assign IPv4 address "{0}" to this '\
                                    'interface as it is the broadcast address'\
                                    ' for its network "{1}".'.format(
                                            ip_addr,
                                            iface.network_name
                                        )
                            errors.append(ValidationError(
                                    item_path=iface.get_vpath(),
                                    error_message=msg
                                ))
        return errors

    def _validate_ips_unique_in_network(self, all_nodes):
        """
        Validate that an IP is unique per network.
        """

        ips_on_networks = dict()

        preamble = '._validate_ips_unique_in_network:'
        errors = []

        for node in all_nodes:
            for net_iface in node.network_interfaces:

                if net_iface.is_for_removal():
                    continue

                if hasattr(net_iface, 'network_name')\
                   and net_iface.network_name:
                    ips_on_networks.setdefault(net_iface.network_name, {})
                    network = ips_on_networks[net_iface.network_name]
                else:
                    continue

                if hasattr(net_iface, 'ipaddress') and net_iface.ipaddress:
                    network.setdefault(net_iface.ipaddress, [4, []])
                    network[net_iface.ipaddress][1].append(net_iface)

                if hasattr(net_iface, 'ipv6address') and net_iface.ipv6address:
                    network.setdefault(net_iface.ipv6address, [6, []])
                    network[net_iface.ipv6address][1].append(net_iface)

        for network in ips_on_networks.values():
            for ifaces in network.values():
                if len(ifaces[1]) > 1:
                    version = 'IP' if 4 == ifaces[0] else 'IPv6'
                    for iface in ifaces[1]:
                        msg = "{0} addresses must be unique per network.".\
                            format(version)
                        _LOG.trace.debug(preamble + msg)
                        errors.append(ValidationError(
                                      item_path=iface.get_vpath(),
                                      error_message=msg))

        return errors

    def _validate_ips_unique_in_node(self, node):
        """
        Validate that an IP is unique per node.
        """

        preamble = '._validate_ips_unique_in_node: ' + node.hostname + ': '
        errors = []

        for net_iface in node.network_interfaces:

            if net_iface.is_for_removal():
                continue

            if hasattr(net_iface, 'ipaddress') and net_iface.ipaddress:

                other_ips = [iface.ipaddress
                             for iface in node.network_interfaces
                             if hasattr(iface, 'ipaddress') and
                                iface.ipaddress and
                                iface != net_iface and
                                iface.ipaddress == net_iface.ipaddress and
                                not iface.is_for_removal()]
                if len(other_ips) > 0:
                    msg = "IP addresses must be unique per node."
                    _LOG.trace.debug(preamble + msg)
                    errors.append(ValidationError(
                             item_path=net_iface.get_vpath(),
                             error_message=msg))

            if hasattr(net_iface, 'ipv6address') and net_iface.ipv6address:

                net_iface_addr = \
                      IPAddress(self._strip_ipv6_prefix(net_iface.ipv6address))

                other_ips = [iface.ipv6address
                             for iface in node.network_interfaces
                             if hasattr(iface, 'ipv6address') and
                                iface.ipv6address and
                                iface != net_iface and
                                net_iface_addr == IPAddress( \
                              self._strip_ipv6_prefix(iface.ipv6address)) and
                                not iface.is_for_removal()]

                if len(other_ips) > 0:
                    msg = "IPv6 addresses must be unique per node."
                    _LOG.trace.debug(preamble + msg)
                    errors.append(ValidationError(
                                  item_path=net_iface.get_vpath(),
                                  error_message=msg))
        return errors

    @staticmethod
    def _strip_ipv6_prefix(address_as_string):
        if not '/' in address_as_string:
            return address_as_string
        return address_as_string.split('/')[0]

    def _validate_macs_unique(self, context):
        """
        Validate that a MAC is unique on a Node
        """
        preamble = '._validate_mac_unique: '
        errors = []

        present_nics = [nic for nic in context.query("network-interface")
                        if not nic.is_for_removal()]

        for net_iface in present_nics:
            if hasattr(net_iface, 'macaddress') and \
               net_iface.macaddress and \
               not net_iface.is_for_removal():

                other_macs = [iface.macaddress
                             for iface in context.query("network-interface")
                             if hasattr(iface, 'macaddress') and
                                iface.macaddress and
                                iface != net_iface and
                                iface.macaddress == net_iface.macaddress and
                                not iface.is_for_removal()]

                if len(other_macs) > 0:
                    msg = ("MAC addresses must be unique in the deployment "
                    "model.")
                    _LOG.trace.debug(preamble + msg)
                    errors.append(ValidationError(net_iface.get_vpath(),
                                                  error_message=msg))

        return errors

    @staticmethod
    def _validate_only_supported_types_present(node):
        """
        Validate only supported types are present in
        the node.network_interfaces Collection.
        """

        preamble = '._validate_only_supported_types_present: ' + \
                   node.hostname + ': '
        errors = []
        for interface in node.network_interfaces:
            _LOG.trace.debug("interface is %s " % interface)
            if interface.item_type_id not in NetworkPlugin.ALLOWED_INTERFACES:
                msg = ('The interface type "{0}" is not allowed. Allowed '
                       'interface types are {1}'.format(interface.item_type_id,
                                " or ".join(NetworkPlugin.ALLOWED_INTERFACES)))
                _LOG.trace.debug(preamble + msg)
                errors.append(ValidationError(interface.get_vpath(),
                              error_message=msg))

        return errors

    @staticmethod
    def _interface_has_IPv4_address(interface):
        has_ipv4 = (hasattr(interface, 'ipaddress') and interface.ipaddress)
        return has_ipv4

    def _validate_interface_l3_config(self, node, networks):
        errors = []

        for interface in node.network_interfaces:
            if interface.is_for_removal():
                continue

            if not (hasattr(interface, 'network_name') and
                    interface.network_name):
                continue

            matching_networks = [network for network in networks if
                    interface.network_name == network.name]
            if len(matching_networks) == 0:
                continue
            else:
                matching_network = matching_networks[0]

            if (hasattr(matching_network, 'subnet') and
                    matching_network.subnet):

                #LITPCDS-9074: Allow bridges to go without ip addresses

                allow_not_ip = interface.item_type_id == 'bridge' and \
                    matching_network.litp_management == 'false'

                if not self._interface_has_IPv4_address(interface) and \
                    not allow_not_ip:

                    if matching_network.litp_management == 'true':
                        err = 'This interface is tied to management '\
                        'network ({0}) and it requires an IPv4 address.'.\
                        format(matching_network.name)
                    else:
                        err = 'This interface does not define an IPv4 '\
                        'address. It is tied to a network ({0}) with a '\
                        'subnet defined.'.format(
                                    matching_network.name
                                )
                    errors.append(
                            ValidationError(
                                item_path=interface.get_vpath(),
                                error_message=err
                            )
                        )
            else:
                if self._interface_has_IPv4_address(interface):
                    err = 'This interface defines an IPv4 address. '\
                    'It is not tied to a network ({0}) with a valid '\
                    'subnet defined.'.format(
                                matching_network.name
                            )
                    errors.append(
                            ValidationError(
                                item_path=interface.get_vpath(),
                                error_message=err
                            )
                        )

        return errors

    def _validate_node_routes(self, node, networks):
        """
        Dispatches per-node route validation to specialised methods
        """

        errors = []

        errors += self._validate_subnets_unique(node)
        errors += self._validate_gateways_local(node, networks)
        errors += self._validate_route_not_removed(node)
        errors += self._validate_routes_not_reachable(node, networks)
        return errors

    @staticmethod
    def _validate_subnets_unique(node):
        errors = []

        node_route_destinations = dict()
        node_duplicates = set()
        for route in NetworkPlugin._valid_ipv4_and_ipv6_routes(node):

            route_dest = route.subnet
            if route_dest not in node_route_destinations:
                node_route_destinations[route_dest] = [route.get_vpath()]
            else:
                node_route_destinations[route_dest] += [route.get_vpath()]
                node_duplicates.add(route_dest)

        if node_duplicates:
            for duplicate_destination in node_duplicates:
                error_message = ('Destination subnet "{subnet}" is duplicated '
                                 'across several routes: {routes}').format(
                                     subnet=duplicate_destination,
                                     routes=' '.join(sorted(
                                         node_route_destinations[
                                            duplicate_destination
                                            ])))

                error = ValidationError(node.routes.get_vpath(),
                        error_message=error_message)
                errors.append(error)

        return errors

    def _validate_gateways_local(self, node, networks):
        errors = []

        node_subnets = list()
        ipv6_subnets = list()

        # For LITPCDS-7210, we track all node Ipv6 addresses
        # to disallow their use as gateway.
        ipv6_ips = list()

        for net_iface in node.network_interfaces:
            # IPv4 ifaces
            if hasattr(net_iface, 'ipaddress') and \
               hasattr(net_iface, 'network_name') and \
               net_iface.ipaddress and net_iface.network_name and \
               not net_iface.is_for_removal():
                subnet = self._get_subnet_for_net_name(net_iface.network_name,
                                                       networks)
                if subnet:
                    local_net = IPNetwork(subnet)
                    node_subnets.append(local_net)

            # We need to gather all IPv6 addresses bound to the node's
            # interfaces to determine which routes' gateways will be reachable
            if hasattr(net_iface, 'ipv6address') and \
               hasattr(net_iface, 'network_name') and \
               net_iface.ipv6address and net_iface.network_name and \
               not net_iface.is_for_removal():
                ipv6_ips.append(self._strip_ipv6_prefix(net_iface.ipv6address))
                local_net = NetworkPlugin._network_from_ipv6address(
                        net_iface.ipv6address
                    )
                ipv6_subnets.append(local_net)

        # IPv4 routes
        for route in self._valid_ipv4_routes(node.routes):

            # Each route's gateway address should fit within one and exactly 1
            # directly-attached subnet
            matching_subnets = list()
            for node_subnet in node_subnets:
                if IPAddress(route.gateway) in node_subnet:
                    matching_subnets.append(node_subnet)

            if 1 > len(matching_subnets):
                errors.append(ValidationError(route.get_vpath(),
                    error_message='Route gateway is not reachable from any '
                    'of the interfaces on node "{0}"'.format(node.hostname)))
            if 1 < len(matching_subnets):
                errors.append(ValidationError(route.get_vpath(),
                    error_message='Route gateway is reachable from more ' \
                    'than one interface on node "{0}"'.format(node.hostname)))

        # IPv6 routes
        for route in self._valid_ipv6_routes(node.routes):

            if route.gateway in ipv6_ips:
                errors.append(ValidationError(route.get_vpath(),
                    error_message='Local IPv6 address "{0}" ' \
                        'can not be used as gateway.'.format(route.gateway)))

            matching_subnets = list()
            for ipv6_subnet in ipv6_subnets:
                if IPAddress(route.gateway) in ipv6_subnet:
                    matching_subnets.append(ipv6_subnet)

            if 1 > len(matching_subnets):
                errors.append(ValidationError(route.get_vpath(),
                    error_message='Route gateway is not reachable from any '
                    'of the interfaces on node "{0}"'.format(node.hostname)))
            if 1 < len(matching_subnets):
                errors.append(ValidationError(route.get_vpath(),
                    error_message='Route gateway is reachable from more ' \
                    'than one interface on node "{0}"'.format(node.hostname)))
        return errors

    @staticmethod
    def _validate_route_not_removed(node):
        errors = []
        routes_removed = [route for route in node.routes
                          if route.is_for_removal()]
        for route in routes_removed:
            msg = 'Route item cannot be removed. Removal is not supported.'
            errors.append(ValidationError(item_path=route.get_vpath(),
                                          error_message=msg))
        return errors

    @staticmethod
    def _validate_routes_V4_not_reachable(node, networks):
        # since LITPCDS-7422, a redundant route to local networks
        # is not allowed.

        errors = []

        node_net_names = [nic.network_name for nic in node.network_interfaces
                          if hasattr(nic, 'network_name')]

        node_nets = [net for net in networks if net.name in node_net_names]

        for network in node_nets:
            if not hasattr(network, 'subnet') or not network.subnet:
                continue

            subnet = IPNetwork(network.subnet)

            # remove routes is not yet supported but eventually it will.
            for route in NetworkPlugin._valid_ipv4_routes(node.routes):

                routed_subnet = IPNetwork(route.subnet)

                if subnet.__contains__(routed_subnet):

                    device_name = [nic.device_name for nic in \
                                   node.network_interfaces if \
                                   nic.network_name == network.name][0]

                    msg = 'A route with value "{0}" for property "subnet" ' \
                          'is invalid as it is accessible via interface ' \
                          'named "{1}"'.format(route.subnet, device_name)
                    errors.append(ValidationError(item_path=route.get_vpath(),
                                                  error_message=msg))

        return errors

    @staticmethod
    def _validate_routes_V6_not_reachable(node):
        # since LITPCDS-7422, a redundant route to local networks
        # is not allowed.

        errors = []

        v6networks = []
        for net_iface in node.network_interfaces:
            if not hasattr(net_iface, 'ipv6address') or \
               not net_iface.ipv6address:
                continue
            subnet = NetworkPlugin._network_from_ipv6address(\
                                        net_iface.ipv6address)
            v6networks.append([subnet, net_iface.device_name])

        for route in NetworkPlugin._valid_ipv6_routes(node.routes):
            # remove routes is not yet supported but eventually it will.

            routed_subnet = IPNetwork(route.subnet)
            for subnet, device_name in v6networks:
                if subnet.__contains__(routed_subnet):

                    msg = 'A route with value "{0}" for '\
                          'property "subnet" is invalid as it is ' \
                          'accessible via interface named "{1}"'.format( \
                          route.subnet, device_name)

                    errors.append(ValidationError(item_path=route.get_vpath(),
                                                  error_message=msg))

        return errors

    @staticmethod
    def _validate_routes_not_reachable(node, networks):
        if not node.routes:
            return []

        errors = []

        errors += NetworkPlugin._validate_routes_V4_not_reachable(node,
                                                                  networks)
        errors += NetworkPlugin._validate_routes_V6_not_reachable(node)

        return errors

    @staticmethod
    def _interfaces_for_bridge(node, bridge):
        """
        Return a list with interfaces of required type that
        are bridged to "bridge"
        """

        interfaces_using_bridge = list()
        types = ['eth', 'bond', 'vlan']

        for interface_type in types:

            interfaces_using_bridge.extend([
                interface for interface in node.query(interface_type,
                                           bridge=bridge.device_name)
                if not interface.is_for_removal()])

        return interfaces_using_bridge

    def _validate_bridge_is_used(self, node):
        """
        Validate that a bridge is bound to a network device
        """

        preamble = '._validate_bridge_is_used: ' + node.hostname + ': '

        errors = []
        bridges = NetworkPlugin._net_ifaces_by_type(node, 'bridge')

        for bridge in bridges:
            devices_using_bridge = self._interfaces_for_bridge(node, bridge)
            if not devices_using_bridge:
                message = 'Bridge "{name}" is not used.'.format(
                    name=bridge.device_name
                    )
                _LOG.trace.debug(preamble + message)
                errors.append(
                    ValidationError(
                        item_path=bridge.get_vpath(),
                        error_message=message
                        )
                    )
        return errors

    def _validate_vlan_count(self, node):
        """
        Validate the number of VLANs per Node
        """

        preamble = '._validate_vlan_count: ' + node.hostname + ': '

        errors = []

        vlans = NetworkPlugin._net_ifaces_by_type(node, 'vlan')
        num_vlans = len(vlans)

        if num_vlans > self.MAX_VLANS_PER_NODE:
            msg = 'Too many VLANs on node "%s". %d allowed, %d found' % \
                   (node.hostname, self.MAX_VLANS_PER_NODE, num_vlans)
            _LOG.trace.debug(preamble + msg)
            errors.append(ValidationError(node.network_interfaces.get_vpath(),
                                          error_message=msg))

        return errors

    @staticmethod
    def _nics_supporting_vlan(node):
        '''
        Coalesce the Node network-interfaces that can be VLAN tagged
        '''

        nics = []
        for nic_type in ['eth', 'bond']:
            nics += NetworkPlugin._net_ifaces_by_type(node, nic_type)
        return nics

    @staticmethod
    def _all_nics_supporting_vlan(node):
        '''
        Coalesce the Node network-interfaces that can be VLAN tagged
        but include deleted items
        '''

        nics = []
        for nic_type in ['eth', 'bond']:
            nics += NetworkPlugin._all_net_ifaces_by_type(node, nic_type)
        return nics

    @staticmethod
    def _validate_format_vlan_device_names(node):
        """
        A VLAN device-name must be formatted as:
        <valid nic device-name><dot><VLAN ID>
        where the nic is an eth or Bond.
        """
        errors = []

        nic_device_names = [nic.device_name for nic in
                            NetworkPlugin._nics_supporting_vlan(node)]

        for vlan in NetworkPlugin._net_ifaces_by_type(node, 'vlan'):
            errors += NetworkPlugin._validate_format_vlan_device_name(vlan,
                                                    nic_device_names, node)

        return errors

    @staticmethod
    def _validate_format_vlan_device_name(vlan, nic_device_names, node):

        preamble = '._validate_format_vlan_device_name: '
        errors = []
        msg = None

        all_nics = [nic.device_name for nic in
                            NetworkPlugin._all_nics_supporting_vlan(node)]

        nic_name = NetworkPlugin._extract_nic(vlan.device_name)

        if not nic_name or nic_name in nic_device_names:
            return errors

        if nic_name and not \
            (nic_name in nic_device_names or nic_name in all_nics):
            msg = ('Invalid VLAN device_name: unknown ' + \
                   'network interface item "%s"') % nic_name
        else:
            msg = ('Invalid VLAN device_name: network interface ' + \
                       'item "%s" has state \'ForRemoval\'') % nic_name

        _LOG.trace.debug(preamble + msg)
        errors.append(ValidationError(vlan.get_vpath(),
                                      error_message=msg))
        return errors

    @staticmethod
    def _validate_ipv6_mgmt_is_dual_stack(node, mgmt_net):
        """
        Validate that the mgmt network is not IPv6-only.
        """

        preamble = '._validate_ipv6_mgmt_is_dual_stack ' + node.hostname + ': '
        errors = []

        for net_iface in node.network_interfaces:
            if net_iface.is_for_removal() or \
                net_iface.network_name != mgmt_net.name:
                continue

            if net_iface.ipv6address and not net_iface.ipaddress:
                msg = "The management network cannot be IPv6 only."
                _LOG.trace.debug(preamble + msg)
                errors.append(ValidationError(net_iface.get_vpath(),
                                              error_message=msg))
        return errors

    @staticmethod
    def _validate_bond_used_by_eth(node):
        '''
        Validate that a Bond is the master for at least one eth
        '''

        preamble = '._validate_bond_used_by_eth: ' + node.hostname + ': '
        errors = []

        for bond in NetworkPlugin._net_ifaces_by_type(node, 'bond'):
            slaves = [eth for eth in
                      NetworkPlugin._net_ifaces_by_type(node, 'eth')
                      if hasattr(eth, 'master') and eth.master and \
                         eth.master == bond.device_name]
            if not slaves:
                msg = 'Bond "%s" is not a master for any "eth" devices' % \
                      bond.device_name
                _LOG.trace.debug(preamble + msg)
                errors.append(ValidationError(bond.get_vpath(),
                                              error_message=msg))

        return errors

    @staticmethod
    def _validate_eth_master_is_bond(node):
        '''
        Validate that an eth "master" value is a valid Bond
        '''

        preamble = '._validate_eth_master_is_bond: ' + node.hostname + ': '
        errors = []

        all_bonds = [item.device_name for item in node.query('bond')]

        bond_devices = [bond.device_name for bond in
                        NetworkPlugin._net_ifaces_by_type(node, 'bond')]

        for eth in NetworkPlugin._net_ifaces_by_type(node, 'eth'):
            if hasattr(eth, 'master') and eth.master and \
                eth.master not in bond_devices:
                if eth.master in all_bonds:
                    msg = ('eth "master" "{0}" is not a valid Bond '
                           '"device_name" as it has state \'ForRemoval\''). \
                           format(eth.master)
                else:
                    msg = ('eth "master" "{0}" is not a valid '
                           'Bond "device_name"').format(eth.master)
                    _LOG.trace.debug(preamble + msg)
                errors.append(ValidationError(eth.get_vpath(),
                                          error_message=msg))
        return errors

    @staticmethod
    def _validate_vlan_on_nodes_not_mgmt(node, management_network):
        """
        Validate that the ``network`` assigned to a ``vlan``
        item is not the Management network in case of a managed node.
        """

        errors = []

        vlans = NetworkPlugin._net_ifaces_by_type(node, 'vlan')

        for vlan in vlans:
            if hasattr(vlan, 'network_name') and \
               vlan.network_name == management_network.name:
                emsg = ('Device "{vlan}" is not valid. '
                        'VLAN tagging of the management '
                        'interface on a peer node is not supported').\
                       format(vlan=vlan.device_name)
                errors.append(ValidationError(vlan.get_vpath(),
                                              error_message=emsg))
        return errors

    def _validate_consistent_network_v6_subnets(self, context):
        """
        Validate that all ``nodes`` on a given ``network`` that have an
        ``ipv6address`` are on the same subnet.
        """
        preamble = '._validate_consistent_network_v6_subnets: '
        errors = []
        subnets = {}
        networks_with_clashes = set()

        for node in self._all_nodes(context):
            for nic in NetworkPlugin._valid_real_devices(
                node.network_interfaces):
                if hasattr(nic, 'ipv6address') and nic.ipv6address and \
                    hasattr(nic, 'network_name'):
                    # For some reason if a netmask is not specified, IPNetwork
                    # uses /128 as the default rather than /64 (RHEL quirk?)
                    if '/' in nic.ipv6address:
                        ip_addr = IPNetwork(nic.ipv6address, version=6)
                    else:
                        ip_addr = IPNetwork(nic.ipv6address + '/64', version=6)
                    ip_netbits = ip_addr.network
                    ip_netmask = ip_addr.netmask
                    ip_subnet = (ip_netbits, ip_netmask)
                    try:
                        if subnets[nic.network_name] != ip_subnet:
                            networks_with_clashes.add(nic.network_name)
                    except KeyError:
                        subnets[nic.network_name] = ip_subnet

        # 2nd pass to generate all required error messages (one per interface
        # on affected networks, which might be a lot..)
        for node in self._all_nodes(context):
            for nic in NetworkPlugin._valid_real_devices(
                node.network_interfaces):
                if hasattr(nic, 'ipv6address') and nic.ipv6address and \
                    hasattr(nic, 'network_name') and \
                    nic.network_name in networks_with_clashes:
                    msg = 'Device "{eth}" on node "{node}" attached'\
                    ' to network "{net}" is using a different IPv6'\
                    ' subnet to other nodes on the network.'.format(
                        node=node.hostname,
                        net=nic.network_name,
                        eth=nic.device_name
                    )
                    errors.append(
                        ValidationError(
                            item_path=nic.get_vpath(),
                            error_message=msg
                            )
                        )
                    _LOG.trace.debug(
                        preamble + nic.get_vpath() + ": " + msg
                        )
        return errors
