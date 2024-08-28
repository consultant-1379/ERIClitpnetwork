##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import unittest

from mock import Mock

from litp.core.execution_manager import ConfigTask
from litp.core.validators import ValidationError
from mock_network_items import (
    NetworkMock,
    NetworkMockContext,
    NetworkMockNode,
    NetworkMockEth,
    NetworkMockBridge,
    NetworkMockBond
)
from network_plugin.network_plugin import NetworkPlugin


class TestNetworkPlugin(unittest.TestCase):
    mock_node_counter = int()

    def mock_slave_interface(self, bond_name, device_name):
        return Mock(
                item_type_id='eth',
                master=bond_name,
                device_name=device_name,
                ipaddress=None,
                ipv6address=None,
                ipv6_autoconf=None,
                bridge=None,
                rx_ring_buffer=None,
                tx_ring_buffer=None,
                txqueuelen=None,
                is_initial=lambda: True,
                is_for_removal=lambda: False,
                macaddress="00:11:22:33:44:55",
                get_vpath=lambda: '/' + device_name
        )

    def mock_bond_interface(self, bond_name):
        return Mock(item_type_id='bond',
                    miimon='100',
                    arp_all_targets=None,
                    arp_validate=None,
                    arp_interval=None,
                    arp_ip_target=None,
                    primary=None,
                    primary_reselect=None,
                    mode='5',
                    device_name=bond_name,
                    ipaddress=None,
                    ipv6address=None,
                    ipv6_autoconf=None,
                    rx_ring_buffer=None,
                    tx_ring_buffer=None,
                    bridge='br1',
                    is_initial=lambda: False,
                    is_for_removal=lambda: False,
                    xmit_hash_policy=None,
                    applied_properties={},
                    get_vpath=lambda: '/' + bond_name)

    def setUp(self):
        self.plugin = NetworkPlugin()

    def test__netmask(self):
        network = Mock(subnet="1.2.3.0/24",
                       name="foo",
                       get_vpath=lambda:"/i/networks/foonet")

        interface = Mock(device_name="eth1",
                         ipaddress="1.2.3.4",
                         network_name="foo",
                         get_vpath=lambda:"/d/nodes/network_interfaces/eth1")

        context = Mock(query=lambda b, **kwargs: [network])
        netmask = NetworkPlugin._netmask(context, interface)
        self.assertEqual("255.255.255.0", netmask)

        # when either interface.network_name or network.name is not matched
        context2 = Mock(query=lambda b, **kwards: [])
        netmask2 = NetworkPlugin._netmask(context2, interface)
        self.assertEqual(None, netmask2)

    def test__network(self):
        network = Mock(subnet="1.2.3.0/24",
                       name="foo",
                       get_vpath=lambda:"/i/networks/foonet")

        interface = Mock(device_name="eth1",
                         ipaddress="1.2.3.4",
                         network_name="foo",
                         get_vpath=lambda:"/d/nodes/network_interfaces/eth1")

        context = Mock(query=lambda b, **kwargs: [network])
        net = NetworkPlugin._network(context, interface)
        self.assertEqual("1.2.3.0", net)

        # when either interface.network_name or network.name is not matched
        context2 = Mock(query=lambda b, **kwards: [])
        net2 = NetworkPlugin._netmask(context2, interface)
        self.assertEqual(None, net2)

    def test__find_ip_network_nonip_net_item(self):
        nonipnetitem = Mock(spec=['name'])
        nonipnetitem.name='foo'

        context = Mock(query=lambda item, name: [nonipnetitem])
        interface = Mock(network_name='foo', device_name='eth11')

        net = NetworkPlugin._find_ip_network(context, interface)
        self.assertEqual(None, net)

    def test__broadcast(self):
        network = Mock(subnet="1.2.3.0/24",
                       name="foo",
                       get_vpath=lambda:"/i/networks/foonet")

        interface = Mock(device_name="eth1",
                         ipaddress="1.2.3.4",
                         network_name="foo",
                         get_vpath=lambda:"/d/nodes/network_interfaces/eth1")

        context = Mock(query=lambda b, **kwargs: [network])
        broadcast = NetworkPlugin._broadcast(context, interface)
        self.assertEqual("1.2.3.255", broadcast)

        # when either interface.network_name or network.name is not matched
        context2 = Mock(query=lambda b, **kwards: [])
        broadcast2 = NetworkPlugin._netmask(context2, interface)
        self.assertEqual(None, broadcast2)

    @staticmethod
    def _mock_node_factory(for_removal=False):
        TestNetworkPlugin.mock_node_counter += 1
        node_name='node{0}'.format(TestNetworkPlugin.mock_node_counter)

        def node_query(*args, **kwargs):
            return []
        return Mock(
                is_for_removal=lambda: for_removal,
                get_vpath=lambda: '/' + node_name,
                query=Mock(side_effect=node_query),
                network_interfaces=[
                        # One interface is new
                        Mock(
                            get_vpath=lambda: '/{0}/if0'.format(node_name),
                            is_initial=lambda: True,
                            is_updated=lambda: False,
                            is_applied=lambda: False,
                            network_name='mock_net',
                            ipaddress='11.11.11.11',
                            item_type_id='eth',
                            bridge='br0',
                            macaddress='00:11:22:33:44:55',
                            device_name='eth0',
                            rx_ring_buffer=None,
                            tx_ring_buffer=None,
                        ),
                        # ...another is updated
                        Mock(
                            get_vpath=lambda: '/{0}/if1'.format(node_name),
                            is_initial=lambda: False,
                            is_updated=lambda: True,
                            is_applied=lambda: False,
                            network_name='mock_net',
                            ipaddress='11.11.11.12',
                            item_type_id='bridge',
                            macaddress='00:11:22:33:44:56',
                            device_name='br0',
                            rx_ring_buffer=None,
                            tx_ring_buffer=None,
                        ),
                        # yet another is applied
                        Mock(
                            get_vpath=lambda: '/{0}/if2'.format(node_name),
                            is_initial=lambda: False,
                            is_updated=lambda: False,
                            is_applied=lambda: True,
                            network_name='mock_net',
                            ipaddress='11.11.11.13',
                            item_type_id='eth',
                            macaddress='00:11:22:33:44:57',
                            device_name='eth2',
                            rx_ring_buffer=None,
                            tx_ring_buffer=None,
                        )
                    ],
            )

    def test_removed_nodes_are_skipped(self):
        TestNetworkPlugin.mock_node_counter = 0

        mock_nodes = [
                TestNetworkPlugin._mock_node_factory(for_removal=True),
                TestNetworkPlugin._mock_node_factory(for_removal=False),
            ]

        mock_nets = [
                Mock(name='mock_net', subnet='11.11.11.0/24'),
            ]

        def _mock_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return mock_nodes
            elif 'ms' == query_item_type:
                return []
            elif 'network' == query_item_type:
                return mock_nets

        mock_model = Mock()
        mock_model.query = _mock_query

        # Only the second node is applied, check no tasks are generated for new
        # interfaces on the other nodes
        new_interface_tasks = self.plugin._new_or_updated_tasks(mock_model)
        nodes_with_tasks = set([task.node.get_vpath() for task in new_interface_tasks])
        self.assertEquals(1, len(nodes_with_tasks))
        self.assertEquals(set(['/node2']), nodes_with_tasks)

        # Only the second node is applied, check no tasks are generated for updated
        # interfaces on the other nodes
        updated_interface_tasks = self.plugin._new_or_updated_tasks(mock_model)
        nodes_with_tasks = set([task.node.get_vpath() for task in updated_interface_tasks])
        self.assertEquals(1, len(nodes_with_tasks))
        self.assertEquals(set(['/node2']), nodes_with_tasks)

    def test_ms_and_nodes_same_tasks(self):
        TestNetworkPlugin.mock_node_counter = 0

        mock_nodes = [
                TestNetworkPlugin._mock_node_factory(),
            ]

        mock_nets = [
                Mock(name='mock_net', subnet='11.11.11.0/24'),
            ]

        mock_mses = [
                TestNetworkPlugin._mock_node_factory(),
            ]

        def _mock_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return mock_nodes
            elif 'ms' == query_item_type:
                return mock_mses
            elif 'network' == query_item_type:
                return mock_nets

        mock_model = Mock()
        mock_model.query = _mock_query

        # A node and a MS with the same set of network interfaces should get
        # the same tasks generated for new interfaces
        new_interface_tasks = self.plugin._new_or_updated_tasks(mock_model)
        nodes_with_tasks = set([task.node.get_vpath() for task in new_interface_tasks])
        self.assertEquals(2, len(nodes_with_tasks))
        self.assertEquals(set(['/node1', '/node2']), nodes_with_tasks)

        # ...and for updated interfaces
        updated_interface_tasks = self.plugin._new_or_updated_tasks(mock_model)
        nodes_with_tasks = set([task.node.get_vpath() for task in updated_interface_tasks])
        self.assertEquals(2, len(nodes_with_tasks))
        self.assertEquals(set(['/node1', '/node2']), nodes_with_tasks)

    def test_interface_selection_for_new_and_updated_interface_tasks(self):
        TestNetworkPlugin.mock_node_counter = 0

        mock_nodes = [
                TestNetworkPlugin._mock_node_factory(),
            ]

        mock_nets = [
                Mock(name='mock_net', subnet='11.11.11.0/24',
                     is_updated=lambda: False),
            ]

        def _mock_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return mock_nodes
            elif 'ms' == query_item_type:
                return []
            elif 'network' == query_item_type:
                return mock_nets

        mock_model = Mock()
        mock_model.query = _mock_query
        new_interface_tasks = self.plugin._new_or_updated_tasks(mock_model)
        items_with_tasks = set([task.model_item.get_vpath() for task in new_interface_tasks])

        # Only if0 is in initial state, yet the plugin also returns a
        # ConfigTask for the loopback interface when >=1 interface is found in
        # the initial state
        expected_items_with_tasks = set(['/node1/if0', '/node1/if1'])
        self.assertEquals(expected_items_with_tasks, items_with_tasks)

    def test_create_config(self):
        TestNetworkPlugin.mock_node_counter = 0

        mock_nodes = [
                TestNetworkPlugin._mock_node_factory(),
            ]

        mock_nets = [
                Mock(name='mock_net', subnet='11.11.11.0/24',
                     applied_properties={"subnet": '11.11.11.0/24'},),
            ]

        def _mock_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return mock_nodes
            elif 'ms' == query_item_type:
                return []
            elif 'network' == query_item_type:
                return mock_nets
            elif 'route' == query_item_type:
                return []

        mock_model = Mock()
        mock_model.query = _mock_query
        expected_tasks = self.plugin._new_or_updated_tasks(mock_model)

        self.assertEquals(expected_tasks, self.plugin.create_configuration(mock_model))

        items_with_tasks = set([task.model_item.get_vpath() for task in
                self.plugin.create_configuration(mock_model)])

        expected_items_with_tasks = set(['/node1/if0', '/node1/if1'])
        self.assertEquals(expected_items_with_tasks, items_with_tasks)

    def test_heartbeat_nets(self):
        TestNetworkPlugin.mock_node_counter = 0
        networks = []
        interfaces = []
        networks.append(Mock(subnet="1.2.3.0/24",
                       name="mgmt",
                       get_vpath=lambda:"/ms/networks/mgmt"))

        networks.append(Mock(name="hb1",
                       get_vpath=lambda:"/ms/networks/hb1"))

        iface1 = Mock(device_name="eth0",
                 ipaddress="1.2.3.4",
                 network_name="mgmt",
                 get_vpath=lambda:\
                 "/deployments/d1/clusters/c1/nodes/n1/network_interfaces/eth0")

        iface2 = Mock(device_name="eth1",
                 network_name="hb1",
                 get_vpath=lambda:\
                 "/deployments/d1/clusters/c1/nodes/n1/network_interfaces/eth1")

        node_url = '/deployments/d1/clusters/c1/nodes/n1'
        node1 = Mock(network_interfaces=[iface1, iface2],
                hostname='mn1',
                get_vpath=lambda: node_url)

        context = Mock(query=lambda b, **kwargs: [networks[0]])
        device = self.plugin._device_name_for_IPv4_route(context, node1, '1.2.3.1')
        self.assertEqual("eth0", device.device_name)
        context = Mock(query=lambda b, **kwargs: [networks[1]])
        device = self.plugin._device_name_for_IPv4_route(context, node1, '1.2.3.1')
        self.assertEqual(None, device)

    def test_vlan_config(self):
        mock_eth0 = Mock(is_for_removal=lambda: False,
                         device_name='eth0')

        mock_vlan = Mock(is_initial=lambda: True,
                         item_type_id='vlan',
                         device_name='eth0.1234',
                         ipaddress=None
                         )

        mock_node = Mock(hostname="sc1",
                         is_for_removal=lambda: False,
                         network_interfaces=[mock_vlan],
                         query=lambda a,device_name: [mock_eth0])

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node]
            elif 'ms' == query_item_type:
                return []
            elif 'network' == query_item_type:
                return []

        context = Mock(query=_mock_context_query)

        tasks = self.plugin.create_configuration(context)
        self.assertTrue(1, len(tasks))

    def test_create_mgmt_if(self):
        mock_if = Mock(is_initial=lambda: True,
                is_updated=lambda: False,
                get_vpath=lambda: '/node/if1',
                item_type_id='eth',
                device_name='eth1',
                macaddress='00:11:22:33:44:55',
                network_name='mgmt',
                ipaddress='10.10.10.89',
                ipv6address='',
                bridge='',
                rx_ring_buffer=None,
                tx_ring_buffer=None,
            )

        def _mock_node_query (query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [mock_if]
            return []

        mock_node = Mock(hostname="sc1",
                is_for_removal=lambda: False,
                network_interfaces = [mock_if],
                get_vpath=lambda: '/node',
                query=_mock_node_query
            )

        mock_net = Mock(
                is_for_removal=lambda: False,
                item_type_id='network',
                litp_management='true',
                subnet='10.10.10.0/24',
                applied_properties={"subnet": '10.10.10.0/24'},
            )

        mock_net.name = 'mgmt'

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node]
            elif 'network' == query_item_type:
                return [mock_net]
            elif 'ms' == query_item_type:
                return []

        context = Mock(query=_mock_context_query)

        tasks = self.plugin.create_configuration(context)
        self.assertEquals(1, len(tasks), tasks)
        task = tasks[0]
        self.assertTrue('is_mgmt_if' in task.kwargs)

    def test_create_non_mgmt_if(self):
        mock_if = Mock(is_initial=lambda: True,
                is_updated=lambda: False,
                get_vpath=lambda: '/node/if1',
                item_type_id='eth',
                device_name='eth1',
                macaddress='00:11:22:33:44:55',
                network_name='not_mgmt',
                ipaddress='10.10.10.89',
                ipv6address='',
                bridge='',
                rx_ring_buffer=None,
                tx_ring_buffer=None,
            )

        def _mock_node_query (query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [mock_if]
            return []

        mock_node = Mock(hostname="sc1",
                is_for_removal=lambda: False,
                network_interfaces = [mock_if],
                get_vpath=lambda: '/node',
                query=_mock_node_query
            )

        mock_net = Mock(
                item_type_id='network',
                litp_management='false',
                subnet='10.10.10.0/24',
                applied_properties={"subnet": '10.10.10.0/24'},
            )

        mock_net.name = 'not_mgmt'

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node]
            elif 'network' == query_item_type:
                return [mock_net]
            elif 'ms' == query_item_type:
                return []

        context = Mock(query=_mock_context_query)

        tasks = self.plugin.create_configuration(context)
        self.assertEquals(1, len(tasks), tasks)
        task = tasks[0]
        self.assertFalse('is_mgmt_if' in task.kwargs)

    def test_update_mgmt_if(self):
        mock_if = Mock(is_initial=lambda: False,
                is_updated=lambda: True,
                get_vpath=lambda: '/node/if1',
                item_type_id='eth',
                device_name='eth1',
                macaddress='00:11:22:33:44:55',
                network_name='mgmt',
                ipaddress='10.10.10.89',
                ipv6address='',
                bridge='',
                rx_ring_buffer=None,
                tx_ring_buffer=None,
            )

        def _mock_node_query (query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [mock_if]
            return []

        mock_node = Mock(hostname="sc1",
                is_for_removal=lambda: False,
                network_interfaces = [mock_if],
                get_vpath=lambda: '/node',
                query=_mock_node_query
            )

        mock_net = Mock(
                is_for_removal=lambda: False,
                item_type_id='network',
                litp_management='true',
                subnet='10.10.10.0/24',
            )

        mock_net.name = 'mgmt'

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node]
            elif 'network' == query_item_type:
                return [mock_net]
            elif 'ms' == query_item_type:
                return []

        context = Mock(query=_mock_context_query)

        tasks = self.plugin.create_configuration(context)
        self.assertEquals(1, len(tasks), tasks)
        task = tasks[0]
        self.assertTrue('is_mgmt_if' in task.kwargs)

    def test_update_non_mgmt_if(self):
        mock_if = Mock(is_initial=lambda: False,
                is_updated=lambda: True,
                get_vpath=lambda: '/node/if1',
                item_type_id='eth',
                device_name='eth1',
                macaddress='00:11:22:33:44:55',
                network_name='not_mgmt',
                ipaddress='10.10.10.89',
                ipv6address='',
                bridge='',
                rx_ring_buffer=None,
                tx_ring_buffer=None,
            )

        def _mock_node_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [mock_if]
            return []

        mock_node = Mock(hostname="sc1",
                is_for_removal=lambda: False,
                network_interfaces = [mock_if],
                get_vpath=lambda: '/node',
                query=_mock_node_query
            )

        mock_net = Mock(
                item_type_id='network',
                litp_management='false',
                subnet='10.10.10.0/24',
            )

        mock_net.name = 'not_mgmt'

        def _mock_context_query (query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node]
            elif 'network' == query_item_type:
                return [mock_net]
            elif 'ms' == query_item_type:
                return []

        context = Mock(query=_mock_context_query)

        tasks = self.plugin.create_configuration(context)
        self.assertEquals(1, len(tasks), tasks)
        task = tasks[0]
        self.assertFalse('is_mgmt_if' in task.kwargs)

    def test_bond_device_task(self):
        bond = self.mock_bond_interface('bond0')
        eth0 = self.mock_slave_interface('bond0', 'eth0')
        eth1 = self.mock_slave_interface('bond0', 'eth1')

        def _mock_node_query (query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [eth0, eth1]
            elif 'bond' == query_item_type:
                return [bond]
            return []

        node = Mock(hostname="sc1")
        node.network_interfaces = [eth0, eth1]
        node.query = _mock_node_query

        tasks = self.plugin._device_tasks(None, node, eth0, 'Configure')
        expected = ConfigTask(node, eth0,
                              'Configure eth "eth0" on node "sc1"',
                              'litpnetwork::config',
                              'eth0',
                              ensure='present',
                              bootproto='static',
                              onboot='yes',
                              nozeroconf='yes',
                              master='bond0',
                              slave='yes',
                              userctl='no',
                              before_device=eth1.device_name)

        self.assertEquals([expected], tasks)

        # ----

        eth0.master = None
        eth0.macaddress = '00:11:22:33:44:55'
        tasks = self.plugin._device_tasks(None, node, eth0, 'Configure')
        expected = ConfigTask(node, eth0,
                              'Configure eth "eth0" on node "sc1"',
                              'litpnetwork::config',
                              'eth0',
                              ensure='present',
                              bootproto='static',
                              onboot='yes',
                              nozeroconf='yes',
                              userctl='no',
                              hwaddr='00:11:22:33:44:55')

        self.assertEquals([expected], tasks)


        eth0.master = "bond0"

        current_devices = [eth0, eth1]

        def _mock_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return current_devices
            return []

        node.query = _mock_query

        bond.is_initial=lambda: True

        node.network_interfaces.append(bond)

        tasks = self.plugin._device_tasks(None, node, bond, 'Configure')
        expected = [
            ConfigTask(node, eth0,
                       'Configure eth "eth0" on node "sc1"',
                       'litpnetwork::config',
                       'eth0',
                       ensure='present',
                       bootproto='static',
                       onboot='yes',
                       nozeroconf='yes',
                       userctl='no',
                       master='bond0',
                       slave='yes',
                       before_device=eth1.device_name),
            ConfigTask(node, eth1,
                       'Configure eth "eth1" on node "sc1"',
                       'litpnetwork::config',
                       'eth1',
                       ensure='present',
                       bootproto='static',
                       onboot='yes',
                       nozeroconf='yes',
                       userctl='no',
                       master='bond0',
                       slave='yes'),
            ConfigTask(node, bond,
                       'Configure bond "bond0" on node "sc1"',
                       'litpnetwork::config',
                       bond.device_name,
                       ensure='present',
                       before_device=bond.bridge,
                       bootproto='static',
                       onboot='yes',
                       bridge=bond.bridge,
                       nozeroconf='yes',
                       userctl='no',
                       type='Bonding',
                       hotplug='no',
                       bonding_opts='miimon=100 mode=5',
                       required_device=eth0.device_name),
        ]
        self.assertEquals(expected, tasks)

        #When a bond's properties are updated (ip, miimon or mode),
        #we don't want to generate any tasks for the slaves. We will assume
        #that the underlying slaves have been created and are in operation

        mock_vlan = Mock(item_type_id='vlan',
                         device_name='bond0.835',
                         ipaddress=None,
                         ipv6_autoconf=None,
                         network_name=None,
                         is_for_removal=lambda: False,)

        node.network_interfaces.append(mock_vlan)

        current_devices = [eth0, eth1, mock_vlan]

        def _mock_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [eth0, eth1]
            elif 'vlan' == query_item_type:
                return [mock_vlan]
            return []

        bond.bridge = None
        bond.is_initial=lambda: False
        bond.is_updated=lambda: True
        node.query = _mock_query

        tasks = self.plugin._device_tasks(None, node, bond, 'Configure')

        expected = [
            ConfigTask(node, bond,
                       'Update bond "bond0" on node "sc1"',
                       'litpnetwork::config',
                       bond.device_name,
                       ensure='present',
                       bootproto='static',
                       onboot='yes',
                       nozeroconf='yes',
                       userctl='no',
                       type='Bonding',
                       hotplug='no',
                       bonding_opts='miimon=100 mode=5',
                       required_device=eth0.device_name,
                       vlans_on_bond='bond0.835'),
            ]

        self.assertEquals(expected, tasks)

        current_devices = [eth0, eth1]

        bond1 = Mock(item_type_id='bond',
                     miimon=None,
                     arp_all_targets='any',
                     arp_validate='all',
                     arp_interval='500',
                     arp_ip_target='1.2.3.4',
                     primary=None,
                     primary_reselect=None,
                     mode='5',
                     device_name='bond1',
                     ipaddress=None,
                     ipv6address=None,
                     ipv6_autoconf=None,
                     bridge=None,
                     rx_ring_buffer=None,
                     tx_ring_buffer=None,
                     xmit_hash_policy=None,
                     is_initial=lambda: True,
                     applied_properties={},
                     get_vpath=lambda: '/bond1')

        # sets the master of eth1 as another bond, let's say bond1
        eth1.master = bond1.device_name

        def _mock_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [eth0, eth1]
            elif 'bond' == query_item_type:
                return [bond1]
            return []
        node.query = _mock_query

        tasks = self.plugin._device_tasks(None, node, bond1, 'Configure')
        expected = [
            ConfigTask(node, eth1,
                       'Configure eth "eth1" on node "sc1"',
                       'litpnetwork::config',
                       'eth1',
                       ensure='present',
                       bootproto='static',
                       onboot='yes',
                       nozeroconf='yes',
                       userctl='no',
                       master='bond1',
                       slave='yes'),
            ConfigTask(node, bond1,
                       'Configure bond "bond1" on node "sc1"',
                       'litpnetwork::config',
                       bond1.device_name,
                       ensure='present',
                       bootproto='static',
                       onboot='yes',
                       nozeroconf='yes',
                       userctl='no',
                       type='Bonding',
                       hotplug='no',
                       bonding_opts='arp_interval=500 arp_ip_target=1.2.3.4 arp_validate=all arp_all_targets=any mode=5',
                       required_device=eth1.device_name),
        ]

        tasks = self.plugin._device_tasks(None, node, bond1, 'Configure')
        self.assertEquals(expected, tasks)

        bond1.applied_properties = {'arp_ip_target' : '5.6.7.8'}
        tasks = self.plugin._device_tasks(None, node, bond1, 'Configure')

        self.assertTrue(any(['arp_ip_targets_to_clean' in t.kwargs
                             and t.kwargs['arp_ip_targets_to_clean'] == '5.6.7.8'
                             for t in tasks]))

        bond1.applied_properties = {}
        bond1.applied_properties_determinable = False
        tasks = self.plugin._device_tasks(None, node, bond1, 'Configure')

        self.assertTrue(any(['arp_ip_targets_to_clean' in t.kwargs
                             and t.kwargs['arp_ip_targets_to_clean'] == 'ALL'
                             for t in tasks]))

        bond1.miimon = None
        bond1.arp_all_targets = None
        bond1.arp_validate = None
        bond1.arp_interval = None
        bond1.arp_ip_target = None
        bond1.applied_properties = {}
        bond1.applied_properties_determinable = True

        tasks = self.plugin._device_tasks(None, node, bond1, 'Configure')

        exp1 = ConfigTask(node, bond1,
                         'Configure bond "bond1" on node "sc1"',
                         'litpnetwork::config',
                         bond1.device_name,
                         ensure='present',
                         bootproto='static',
                         onboot='yes',
                         nozeroconf='yes',
                         userctl='no',
                         type='Bonding',
                         hotplug='no',
                         bonding_opts='mode=5',
                         required_device=eth1.device_name)

        self.assertTrue(any([exp1 == t for t in tasks]))


        arp_bond = Mock(item_type_id='bond',
                        mode='5',
                        device_name='bond1',
                        ipaddress=None,
                        ipv6address=None,
                        bridge='br1',
                        is_initial=lambda: False,
                        is_for_removal=lambda: False,
                        arp_all_targets='all',
                        arp_validate='any',
                        arp_interval=5,
                        arp_ip_target='target',
                        applied_properties={},
                        get_vpath=lambda: '/bond1',
                        miimon=None)

        tasks = self.plugin._device_tasks(None, node, arp_bond, 'Configure')

        # Test updated task
        tasks = self.plugin._device_tasks(None, node, arp_bond, 'Update')
        expected_description = 'Update bond "bond1" on node "sc1"'
        self.assertEqual(expected_description, tasks[0].description)

    def test__net_iface_by_device_name(self):
        eth1 = Mock(is_for_removal=lambda: False,
                    device_name='eth1')
        eth12 = Mock(is_for_removal=lambda: False,
                     device_name='eth12')
        node = Mock(hostname='node1',
                    query=lambda a,device_name: [e for e in (eth12, eth1) \
                        if e.device_name == device_name])

        self.assertEqual('eth12', self.plugin._net_iface_by_device_name(
            node, 'eth12').device_name)

        self.assertEqual(None, self.plugin._net_iface_by_device_name(
            node, 'eth0'))

    def test_validation_of_v6_subnets(self):
        # Positive (mismatched) case
        mock_n1_eth0 = Mock(
            is_initial=lambda: True,
            is_updated=lambda: False,
            get_vpath=lambda: '/node/if1',
            item_type_id='eth',
            device_name='eth0',
            network_name='net1',
            ipv6address='fdde:4d7e:d471::833:61:199/96',
            is_for_removal=lambda: False)
        mock_n2_eth0 = Mock(
            is_initial=lambda: True,
            is_updated=lambda: False,
            get_vpath=lambda: '/node/if1',
            item_type_id='eth',
            device_name='eth0',
            network_name='net1',
            ipv6address='fdde:4d7e:d472::833:61:101/96',
            is_for_removal=lambda: False)

        # Negative case
        mock_n1_eth1 = Mock(
            is_initial=lambda: True,
            is_updated=lambda: False,
            is_for_removal=lambda: False,
            get_vpath=lambda: '/node/if2',
            item_type_id='eth',
            device_name='eth1',
            network_name='net2',
            ipv6address='fdde:4d7e:dddd::833:61:199/96',
            )
        mock_n2_eth1 = Mock(
            is_initial=lambda: True,
            is_updated=lambda: False,
            is_for_removal=lambda: False,
            get_vpath=lambda: '/node/if2',
            item_type_id='eth',
            device_name='eth1',
            network_name='net2',
            ipv6address='fdde:4d7e:dddd::833:61:101/96',
            )

        # Test nodes
        mock_node1 = Mock(
            hostname="Node1",
            is_initial=lambda: True,
            is_updated=lambda: False,
            is_for_removal=lambda: False,
            network_interfaces = [mock_n1_eth0,mock_n1_eth1],
            get_vpath=lambda: '/node1'
            )
        mock_node2 = Mock(
            hostname="Node2",
            is_initial=lambda: True,
            is_updated=lambda: False,
            is_for_removal=lambda: False,
            network_interfaces = [mock_n2_eth0,mock_n2_eth1],
            get_vpath=lambda: '/node1'
            )

        # Should only get errors regarding eth0 and not eth1
        def _mock_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node1,mock_node2]
            elif 'ms' == query_item_type:
                return []
        mock_model = Mock()
        mock_model.query = _mock_query
        self.assertEqual(
            set([ValidationError(
                item_path='/node/if1',
                 error_message='Device "eth0" on node "Node1" attached to'\
                 ' network "net1" is using a different IPv6 subnet to'\
                 ' other nodes on the network.'
                 ),
            ValidationError(
                item_path='/node/if1',
                 error_message='Device "eth0" on node "Node2" attached to'\
                 ' network "net1" is using a different IPv6 subnet to'\
                 ' other nodes on the network.'
                 )]),
            set(self.plugin._validate_consistent_network_v6_subnets(
                mock_model
                ))
            )

    def test_validation_of_v6_subnets_implicit_netmask(self):
        # This is a duplicate of the above that checks that the default /64
        # is used if the netmask is not specified. The bits flipped are the
        # two on the host/net border..
        mock_n1_eth0 = Mock(
            is_initial=lambda: True,
            is_updated=lambda: False,
            get_vpath=lambda: '/node/if1',
            item_type_id='eth',
            device_name='eth0',
            network_name='net1',
            ipv6address='fdde:ffff:ffff:ffff:0000:833:61:199',
            is_for_removal=lambda: False)
        mock_n2_eth0 = Mock(
            is_initial=lambda: True,
            is_updated=lambda: False,
            get_vpath=lambda: '/node/if1',
            item_type_id='eth',
            device_name='eth0',
            network_name='net1',
            ipv6address='fdde:ffff:ffff:fffe:0000:833:61:101',
            is_for_removal=lambda: False)
        mock_n1_eth1 = Mock(
            is_initial=lambda: True,
            is_updated=lambda: False,
            is_for_removal=lambda: False,
            get_vpath=lambda: '/node/if2',
            item_type_id='eth',
            device_name='eth1',
            network_name='net2',
            ipv6address='fdde:ffff:ffff:ffff:8000::1',
            )
        mock_n2_eth1 = Mock(
            is_initial=lambda: True,
            is_updated=lambda: False,
            is_for_removal=lambda: False,
            get_vpath=lambda: '/node/if2',
            item_type_id='eth',
            device_name='eth1',
            network_name='net2',
            ipv6address='fdde:ffff:ffff:ffff:0000::1',
            )
        mock_node1 = Mock(
            hostname="Node1",
            is_initial=lambda: True,
            is_updated=lambda: False,
            is_for_removal=lambda: False,
            network_interfaces = [mock_n1_eth0,mock_n1_eth1],
            get_vpath=lambda: '/node1'
            )
        mock_node2 = Mock(
            hostname="Node2",
            is_initial=lambda: True,
            is_updated=lambda: False,
            is_for_removal=lambda: False,
            network_interfaces = [mock_n2_eth0,mock_n2_eth1],
            get_vpath=lambda: '/node1'
            )
        def _mock_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node1,mock_node2]
            elif 'ms' == query_item_type:
                return []
        mock_model = Mock()
        mock_model.query = _mock_query
        self.assertEqual(
            set([ValidationError(
                item_path='/node/if1',
                 error_message='Device "eth0" on node "Node1" attached to'\
                 ' network "net1" is using a different IPv6 subnet to'\
                 ' other nodes on the network.'
                 ),
            ValidationError(
                item_path='/node/if1',
                 error_message='Device "eth0" on node "Node2" attached to'\
                 ' network "net1" is using a different IPv6 subnet to'\
                 ' other nodes on the network.'
                 )]),
            set(self.plugin._validate_consistent_network_v6_subnets(
                mock_model
                ))
            )

    def test_multicast_properties(self):
        node = NetworkMockNode('n1', 'node1')

        multicast_snooping = 0
        multicast_router = 1
        multicast_querier = 0
        hash_max = 512
        hash_elasticity = 4
        ipv6_autoconf = 'false'

        bridge = NetworkMockBridge('if0', 'br0', 'mgmt',
                                   multicast_snooping='%d' % multicast_snooping,
                                   multicast_router='%d' % multicast_router,
                                   multicast_querier='%d' % multicast_querier,
                                   hash_max='%d' % hash_max,
                                   hash_elasticity='%d' % hash_elasticity,
                                   ipv6_autoconf='%s' % ipv6_autoconf)
        node.network_interfaces.append(bridge)

        NetworkMock.set_state_initial([node, bridge])

        mgmt_net = Mock(name='mgmt', subnet='11.11.11.0/24',
                        applied_properties={"subnet": '11.11.11.0/24'})

        def _mock_context_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [node]
            if "network" == query_item_type:
                return [mgmt_net]
            else:
                return []

        context = NetworkMockContext()
        context.query = _mock_context_query

        tasks = self.plugin.create_configuration(context)
        self.assertEquals(1, len(tasks))
        bridge_task = tasks[0]

        self.assertEquals(bridge_task.call_type, 'litpnetwork::config')
        self.assertEquals(bridge_task.call_id, bridge.device_name)
        self.assertEquals(bridge_task.kwargs['type'], 'Bridge')
        self.assertEquals(bridge_task.kwargs['ipv6_autoconf'], 'no')

        opts_str = 'multicast_snooping=%d multicast_querier=%d multicast_router=%d hash_max=%d hash_elasticity=%d' % \
                   (multicast_snooping, multicast_querier, multicast_router, hash_max, hash_elasticity)
        self.assertEquals(bridge_task.kwargs['bridging_opts'], opts_str)

    def test_primary_bonding_properties(self):

        node = NetworkMockNode('n1', 'node1')

        primary = 'eth0'
        reselect = 'always'
        mode = 0
        miimon = 100

        bond = NetworkMockBond('if0', 'bond0', 'mgmt',
                               mode='%d' % mode,
                               miimon='%d' % miimon,
                               primary='%s' % primary,
                               primary_reselect='%s' % reselect)

        slave = NetworkMockEth('if1', 'eth0', 'aa:bb:cc:dd:ee:ff', 'non-mgmt',
                               master=bond.device_name)

        node.network_interfaces.append(bond)
        node.network_interfaces.append(slave)

        NetworkMock.set_state_initial([node, bond, slave])

        def _mock_node_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [slave]
            elif 'bond' == query_item_type:
                return [bond]
            else:
                return []
        node.query = _mock_node_query

        def _mock_context_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [node]
            else:
                return []

        context = NetworkMockContext()
        context.query = _mock_context_query

        tasks = self.plugin.create_configuration(context)
        self.assertEquals(2, len(tasks))    # 1 for the eth, 1 for the bond
        bond_task = tasks[1]

        self.assertEquals(bond_task.call_type, 'litpnetwork::config')
        self.assertEquals(bond_task.call_id, bond.device_name)
        self.assertEquals(bond_task.kwargs['type'], 'Bonding')

        opts_str = 'miimon=%s mode=%s primary=%s primary_reselect=%s' % \
                   (miimon, mode, primary, reselect)
        self.assertEquals(bond_task.kwargs['bonding_opts'], opts_str)
        self.assertEquals(bond_task.kwargs.get('primary_cleaning', 'false'), 'false')

        # ----

        bond.applied_properties_determinable = False

        tasks = self.plugin.create_configuration(context)
        self.assertEquals(2, len(tasks))
        bond_task = tasks[1]
        self.assertEquals(bond_task.kwargs.get('primary_cleaning', 'false'), 'false')

        # ----

        NetworkMock.set_state_updated([bond])
        tasks = self.plugin.create_configuration(context)
        self.assertEquals(2, len(tasks))
        bond_task = tasks[0]
        self.assertEquals(bond_task.kwargs.get('primary_cleaning'), 'true')

        bond.applied_properties_determinable = True

        # ----
        # Delete the primary properties

        NetworkMock.set_state_applied([node, bond, slave]) # To set up applied-properties
        NetworkMock.set_state_updated([bond])
        bond.primary = None
        bond.primary_reselect = None

        tasks = self.plugin.create_configuration(context)
        self.assertEquals(1, len(tasks), tasks)
        bond_task = tasks[0]
        self.assertEquals(bond_task.kwargs['primary_cleaning'], 'true')

    def test_pxenics(self):
        bond0 = self.mock_bond_interface('bond0')
        eth0 = Mock(item_type_id='eth', pxe_boot_only='true', device_name='eth0',
                    network_name=None, ipaddress=None, ipv6address=None,
                    bridge=None, ipv6_autoconf=None,
                    macaddress='00:00:00:00:00:01',
                    rx_ring_buffer=None, tx_ring_buffer=None,
                    txqueuelen=None)

        eth1 = self.mock_slave_interface('bond0', 'eth1')
        eth2 = self.mock_slave_interface('bond0', 'eth2')

        def _mock_node_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [eth0, eth1]
            elif 'bond' == query_item_type:
                return [bond0]
            return []

        node = Mock(hostname="sc1")
        node.network_interfaces = [eth0, eth1, eth2, bond0]
        node.query = _mock_node_query

        tasks = self.plugin._device_tasks(None, node, eth0, 'Configure')
        expected = ConfigTask(node, eth0,
                              'Configure eth "eth0" on node "sc1"',
                              'litpnetwork::config',
                              'eth0',
                              ensure='present',
                              bootproto='static',
                              onboot='yes',
                              nozeroconf='yes',
                              userctl='no',
                              hwaddr='00:00:00:00:00:01'
                              )

        self.assertEqual([expected], tasks)

    def test_pxe_boot_only_task_order(self):

        mgmt_net = Mock(subnet='10.1.2.0/24')
        mgmt_net.name = 'mgmt'
        mgmt_net.litp_management = 'true'
        mgmt_net.is_for_removal = lambda: False

        eth0 = NetworkMockEth('if0',
                              'eth0',
                              'aa:bb:cc:dd:ee:ff',
                              None,
                              pxe_boot_only='true')

        eth1 = NetworkMockEth('if1',
                              'eth1',
                              'aa:bb:cc:dd:bb:ff',
                              'mgmt',
                              ipaddress='10.1.2.1')

        def _mock_node_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [eth0, eth1]
            return []

        node = Mock(hostname="node1")
        node.network_interfaces = [eth0, eth1]
        node.is_for_removal = lambda: False
        node.is_ms = lambda: False
        node.query = _mock_node_query

        NetworkMock.set_state_initial([eth0, eth1])

        def _mock_context_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [node]
            if "network" == query_item_type:
                return [mgmt_net]
            else:
                return []

        context = NetworkMockContext()
        context.query = _mock_context_query

        tasks = self.plugin._new_or_updated_tasks(context)

        self.assertTrue(eth0 == tasks[0].model_item)
        self.assertTrue(eth1 == tasks[1].model_item)
        self.assertTrue(tasks[0] in tasks[1].requires)

    def test_rtx_buffers(self):
        initial_rx_ring_buffer = 1024
        initial_tx_ring_buffer = 512
        updated_rx_ring_buffer = 512
        updated_tx_ring_buffer = 1024

        eth0 = NetworkMockEth('if0',
                              'eth0',
                              '00:00:00:00:00:01',
                              '')

        def _mock_node_query(query_item_type):
            if 'eth' == query_item_type:
                return [eth0]
            return []

        node = NetworkMockNode('cs1', 'cs1')
        node.interfaces = [eth0]

        # Initial device case

        eth0.rx_ring_buffer=initial_rx_ring_buffer
        eth0.tx_ring_buffer=initial_tx_ring_buffer
        NetworkMock.set_state_initial([node, eth0])

        tasks = self.plugin._device_tasks(None, node, eth0, 'Configure')
        expected_ethtool_opts_str = "-G eth0 rx {0}; -G eth0 tx {1}".format(
            initial_rx_ring_buffer, initial_tx_ring_buffer)
        expected = ConfigTask(node, eth0,
                              'Configure eth "eth0" on node "sc1"',
                              'litpnetwork::config',
                              'eth0',
                              ensure='present',
                              bootproto='static',
                              onboot='yes',
                              nozeroconf='yes',
                              userctl='no',
                              hwaddr='00:00:00:00:00:01',
                              ipv6_autoconf='no',
                              ethtool_opts=expected_ethtool_opts_str,
                              )

        self.assertEqual([expected], tasks)

        # Updated device case

        eth0.rx_ring_buffer=updated_rx_ring_buffer
        eth0.tx_ring_buffer=updated_tx_ring_buffer
        NetworkMock.set_state_updated([node, eth0])

        tasks = self.plugin._device_tasks(None, node, eth0, 'Configure')
        expected_ethtool_opts_str = "-G eth0 rx {0}; -G eth0 tx {1}".format(
            updated_rx_ring_buffer, updated_tx_ring_buffer)
        expected = ConfigTask(node, eth0,
                              'Configure eth "eth0" on node "sc1"',
                              'litpnetwork::config',
                              'eth0',
                              ensure='present',
                              bootproto='static',
                              onboot='yes',
                              nozeroconf='yes',
                              userctl='no',
                              hwaddr='00:00:00:00:00:01',
                              ipv6_autoconf='no',
                              ethtool_opts=expected_ethtool_opts_str,
                              )

        self.assertEqual([expected], tasks)

    def test_txqueuelen_TORF196696_bonds(self):
        """
        Test to cover changes for TORF-196696 when the nic is part of a
        bond, those are done in a different part of the plugin
        """
        initial_txqueuelen = 500
        updated_txqueuelen = 1000
        deleted_txqueuelen = None

        bond = NetworkMockBond('bond0', 'bond0', 'mgmt', miimon=100,
                               mode=4)
        eth0 = NetworkMockEth('eth0', 'eth0', 'aa:bb:cc:dd:ee:aa', '',
                              master=bond.device_name,
                              txqueuelen=initial_txqueuelen)
        eth1 = NetworkMockEth('eth1', 'eth1', 'aa:bb:cc:dd:ee:ab', '',
                              master=bond.device_name,
                              txqueuelen=initial_txqueuelen)

        def _mock_node_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [eth0, eth1]
            elif 'bond' == query_item_type:
                return [bond]
            return []

        node = NetworkMockNode('n1', 'node1')
        node.network_interfaces = [eth0, eth1]
        node.query = _mock_node_query

        NetworkMock.set_state_initial([node, bond, eth0, eth1])

        tasks = self.plugin._device_tasks(None, node, bond, 'Configure')
        expected_eth0 = ConfigTask(node, eth0,
                                   'Configure eth "eth0" on node "sc1"',
                                   'litpnetwork::config',
                                   'eth0',
                                   before_device='eth1',
                                   bootproto='static',
                                   ensure='present',
                                   ipv6_autoconf='no',
                                   master='bond0',
                                   onboot='yes',
                                   slave='yes',
                                   nozeroconf='yes',
                                   userctl='no',
                                   txqueuelen=initial_txqueuelen
                                   )
        self.assertTrue(expected_eth0 in tasks)
        expected_eth1 = ConfigTask(node, eth1,
                                   'Configure eth "eth1" on node "sc1"',
                                   'litpnetwork::config',
                                   'eth1',
                                   bootproto='static',
                                   ensure='present',
                                   ipv6_autoconf='no',
                                   master='bond0',
                                   onboot='yes',
                                   slave='yes',
                                   nozeroconf='yes',
                                   userctl='no',
                                   txqueuelen=initial_txqueuelen
                                   )
        self.assertTrue(expected_eth1 in tasks)

        # Updated property case 1: Update txqueuelen
        eth0.txqueuelen = updated_txqueuelen
        NetworkMock.set_state_applied([eth1, bond, node])
        NetworkMock.set_state_updated([eth0])
        tasks = self.plugin._device_tasks(None, node, eth0, 'Update')
        expected_eth0 = ConfigTask(node, eth0,
                                   'Update eth "eth0" on node "sc1"',
                                   'litpnetwork::config',
                                   'eth0',
                                   before_device='eth1',
                                   bootproto='static',
                                   ensure='present',
                                   ipv6_autoconf='no',
                                   master='bond0',
                                   onboot='yes',
                                   slave='yes',
                                   nozeroconf='yes',
                                   userctl='no',
                                   txqueuelen=updated_txqueuelen
                                   )
        self.assertTrue(expected_eth0 in tasks)

        # Delete property case
        eth0.txqueuelen = deleted_txqueuelen
        eth1.txqueuelen = deleted_txqueuelen
        NetworkMock.set_state_updated([eth0, eth1])

        tasks = self.plugin._device_tasks(None, node, eth0, 'Update')
        expected_eth0 = ConfigTask(node, eth0,
                                   'Update eth "eth0" on node "sc1"',
                                   'litpnetwork::config',
                                   'eth0',
                                   before_device='eth1',
                                   bootproto='static',
                                   ensure='present',
                                   ipv6_autoconf='no',
                                   master='bond0',
                                   onboot='yes',
                                   slave='yes',
                                   nozeroconf='yes',
                                   userctl='no'
                                   )
        self.assertTrue(expected_eth0 in tasks)

        tasks = self.plugin._device_tasks(None, node, eth1, 'Update')
        expected_eth1 = ConfigTask(node, eth1,
                                   'Update eth "eth1" on node "sc1"',
                                   'litpnetwork::config',
                                   'eth1',
                                   bootproto='static',
                                   ensure='present',
                                   ipv6_autoconf='no',
                                   master='bond0',
                                   onboot='yes',
                                   slave='yes',
                                   nozeroconf='yes',
                                   userctl='no'
                                   )
        self.assertTrue(expected_eth1 in tasks)

    def test_txqueuelen_TORF196696_standalone(self):
        """
        Test to cover changes for TORF-196696 when the nic is not part of a
        bond
        """

        eth0 = NetworkMockEth('if0',
                              'eth0',
                              '00:00:00:00:00:01',
                              '')

        initial_txqueuelen = 500
        updated_txqueuelen = 1000
        deleted_txqueuelen = None
        node = NetworkMockNode('cs1', 'cs1')
        node.interfaces = [eth0]

        eth0.txqueuelen = initial_txqueuelen
        NetworkMock.set_state_initial([node, eth0])
        tasks = self.plugin._device_tasks(None, node, eth0, 'Configure')
        expected = ConfigTask(node, eth0,
                              'Configure eth "eth0" on node "sc1"',
                              'litpnetwork::config',
                              'eth0',
                              ensure='present',
                              bootproto='static',
                              onboot='yes',
                              nozeroconf='yes',
                              userctl='no',
                              hwaddr='00:00:00:00:00:01',
                              ipv6_autoconf='no',
                              txqueuelen=initial_txqueuelen
                              )
        self.assertTrue(expected in tasks)

        # Updated property case 1: Update txqueuelen
        eth0.txqueuelen = updated_txqueuelen
        NetworkMock.set_state_updated([node, eth0])
        tasks = self.plugin._device_tasks(None, node, eth0, 'Update')
        expected = ConfigTask(node, eth0,
                              'Update eth "eth0" on node "sc1"',
                              'litpnetwork::config',
                              'eth0',
                              ensure='present',
                              bootproto='static',
                              onboot='yes',
                              nozeroconf='yes',
                              userctl='no',
                              hwaddr='00:00:00:00:00:01',
                              ipv6_autoconf='no',
                              txqueuelen=updated_txqueuelen
                              )
        self.assertTrue(expected in tasks)

        # Updated property case 2: Update another property,
        # txqueuelen stays the same
        eth0.rx_ring_buffer = 42
        NetworkMock.set_state_updated([node, eth0])
        tasks = self.plugin._device_tasks(None, node, eth0, 'Update')
        expected = ConfigTask(node, eth0,
                              'Update eth "eth0" on node "sc1"',
                              'litpnetwork::config',
                              'eth0',
                              ensure='present',
                              bootproto='static',
                              onboot='yes',
                              nozeroconf='yes',
                              userctl='no',
                              hwaddr='00:00:00:00:00:01',
                              ipv6_autoconf='no',
                              txqueuelen=updated_txqueuelen,
                              ethtool_opts="-G eth0 rx 42"
                              )
        self.assertTrue(expected in tasks)

        # Delete property case
        eth0.txqueuelen = deleted_txqueuelen
        NetworkMock.set_state_updated([node, eth0])
        tasks = self.plugin._device_tasks(None, node, eth0, 'Update')
        expected = ConfigTask(node, eth0,
                              'Update eth "eth0" on node "sc1"',
                              'litpnetwork::config',
                              'eth0',
                              ensure='present',
                              bootproto='static',
                              onboot='yes',
                              nozeroconf='yes',
                              userctl='no',
                              hwaddr='00:00:00:00:00:01',
                              ipv6_autoconf='no',
                              ethtool_opts="-G eth0 rx 42"
                              )
        self.assertTrue(expected in tasks)

    def test_xmit_hash_policy_TORF196696(self):
        """
        Test to cover changes for TORF-196696
        """

        bond = NetworkMockBond('bond0', 'bond0', 'mgmt', miimon=100,
                               mode=4)
        eth0 = NetworkMockEth('eth0', 'eth0', 'aa:bb:cc:dd:ee:aa', '',
                              master=bond.device_name)
        eth1 = NetworkMockEth('eth1', 'eth1', 'aa:bb:cc:dd:ee:ab', '',
                              master=bond.device_name)

        def _mock_node_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [eth0, eth1]
            elif 'bond' == query_item_type:
                return [bond]
            return []

        node = NetworkMockNode('n1', 'node1')
        node.network_interfaces = [eth0, eth1]
        node.query = _mock_node_query

        NetworkMock.set_state_initial([node, bond, eth0, eth1])

        # Regression for mode=4; no other changes
        tasks = self.plugin._device_tasks(None, node, bond, 'Configure')
        expected_task = ConfigTask(
                node, bond,
                'Configure bond "bond0" on node "sc1"',
                'litpnetwork::config',
                bond.device_name,
                ensure='present',
                bootproto='static',
                onboot='yes',
                nozeroconf='yes',
                userctl='no',
                type='Bonding',
                hotplug='no',
                bonding_opts='miimon=100 mode=4',
                required_device=eth0.device_name)
        self.assertTrue(expected_task in tasks)

        # Create; with mode & policy set
        bond.xmit_hash_policy = 'layer3+4'
        tasks = self.plugin._device_tasks(None, node, bond, 'Configure')
        expected_task = ConfigTask(
                node, bond,
                'Configure bond "bond0" on node "sc1"',
                'litpnetwork::config',
                bond.device_name,
                ensure='present',
                bootproto='static',
                onboot='yes',
                nozeroconf='yes',
                userctl='no',
                type='Bonding',
                hotplug='no',
                bonding_opts='miimon=100 mode=4 xmit_hash_policy=layer3+4',
                required_device=eth0.device_name)
        self.assertTrue(expected_task in tasks)

        # Update; add policy to existing bond
        bond.xmit_hash_policy = 'layer2'
        NetworkMock.set_state_applied([node, eth0, eth1])
        NetworkMock.set_state_updated([bond])
        tasks = self.plugin._device_tasks(None, node, bond, 'Update')
        expected_task = ConfigTask(
                node, bond,
                'Update bond "bond0" on node "sc1"',
                'litpnetwork::config',
                bond.device_name,
                ensure='present',
                bootproto='static',
                onboot='yes',
                nozeroconf='yes',
                userctl='no',
                type='Bonding',
                hotplug='no',
                bonding_opts='miimon=100 mode=4 '
                             'xmit_hash_policy=layer2',
                required_device=eth0.device_name)
        self.assertTrue(expected_task in tasks)

        # Unset the xmit_hash_policy property
        bond.xmit_hash_policy = None
        NetworkMock.set_state_applied([node, eth0, eth1, bond])
        NetworkMock.set_state_updated([bond])
        tasks = self.plugin._device_tasks(None, node, bond, 'Update')
        expected = ConfigTask(
                node, bond,
                'Update bond "bond0" on node "sc1"',
                'litpnetwork::config',
                bond.device_name,
                ensure='present',
                bootproto='static',
                onboot='yes',
                nozeroconf='yes',
                userctl='no',
                type='Bonding',
                primary_cleaning='true',
                arp_ip_targets_to_clean='',
                hotplug='no',
                bonding_opts='miimon=100 mode=4',
                required_device=eth0.device_name)
        self.assertEquals(expected, tasks[0])

    def test_torf323439(self):
        bond = NetworkMockBond('bond0', 'bond0', 'mgmt', arp_all_targets='any',
                               arp_validate='all',
                               arp_interval=2000, arp_ip_target='10.0.1.1',
                               primary='eth0'
                               )
        NetworkMock.set_properties(bond)
        NetworkMock.set_applied_properties(bond)
        eth0 = NetworkMockEth('eth0', 'eth0', '00:00:00:00:00:00',
            'mgmt', master=bond.device_name)
        eth1 = NetworkMockEth('eth1', 'eth1', '00:00:00:00:00:01',
            'mgmt', master=bond.device_name)
        NetworkMock.set_state_applied([bond, eth0, eth1])

        node = NetworkMockNode('n1', "sc1")
        node.network_interfaces = [eth0, eth1, bond]

        # only arp_ip_target property modified
        bond.arp_ip_target = '10.0.1.2'
        NetworkMock.set_state_updated([bond])
        tasks = self.plugin._device_tasks(None, node, bond, 'Update')
        self.assertTrue(len(tasks) == 1)
        self.assertTrue(hasattr(tasks[0], '_pre_vxvm_bond'))
        self.assertEquals(tasks[0]._pre_vxvm_bond, True)

        # arp_ip_target and other properties also modified
        bond.arp_interval = 4000
        tasks = self.plugin._device_tasks(None, node, bond, 'Update')
        self.assertTrue(len(tasks) == 1)
        self.assertTrue(hasattr(tasks[0], '_pre_vxvm_bond'))

        # Other properties modified but not arp_ip_target
        bond.arp_ip_target = '10.0.1.1'
        bond.arp_validate = None
        tasks = self.plugin._device_tasks(None, node, bond, 'Update')
        self.assertTrue(len(tasks) == 1)
        self.assertFalse(hasattr(tasks[0], '_pre_vxvm_bond'))

        # bond interface is initial
        bond.arp_interval = 2000
        bond.arp_validate = 'all'
        NetworkMock.set_state_initial([bond])
        tasks = self.plugin._device_tasks(None, node, bond, 'Update')
        self.assertFalse(hasattr(tasks[0], '_pre_vxvm_bond'))
