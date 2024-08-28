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
import os
from mock import Mock
from nose.tools import nottest

from litp.core.plugin_manager import PluginManager
from litp.core.model_manager import ModelManager
from litp.core.plugin_context_api import PluginApiContext
from litp.extensions.core_extension import CoreExtension

from network_plugin.network_plugin import NetworkPlugin, RouteTask, sort_route_params
from network_extension.network_extension import NetworkExtension


class TestRouteTask(unittest.TestCase):

    def test_network_route_task(self):
        routes_collection = Mock(get_vpath=lambda:
                                    "/deployments/d1/clusters/c1/nodes/node1/routes",
                                   children=[Mock(), Mock()])
        node = Mock(id='node1',
                    hostname='node1',
                    get_vpath=lambda:
                        '/deploymnets/d1/clusters/c1/nodes/node1',
                    routes=routes_collection)
        model_item = node.network_profile
        route_tuples = [
                ('10.10.10.0', '0.0.0.0', '10.10.10.1'),
                ('10.10.10.0', '255.255.255.0', '10.10.10.1'),
                ('192.168.1.0', '255.255.255.0', '192.168.1.254'),
            ]
        routes = [
            ('GATEWAY0=10.10.10.1',
             'ADDRESS0=10.10.10.0',
             'NETMASK0=0.0.0.0'),
            ('GATEWAY1=10.10.10.1',
             'ADDRESS1=10.10.10.0',
             'NETMASK1=255.255.255.0'),
            ('GATEWAY2=192.168.1.254',
             'ADDRESS2=192.168.1.0',
             'NETMASK2=255.255.255.0'),
        ]
        description = 'Setup routes for node "{0}"'.format(node.hostname)
        call_id = node.id
        kwargs = {'device': 'eth0', 'routes': route_tuples}

        task = RouteTask(node, model_item, description, call_id, **kwargs)
        self.assertEqual("litpnetwork::route", task.call_type)


class TestNetworkRoutes(unittest.TestCase):

    def setUp(self):
        self.model = ModelManager()
        self.plugin_manager = PluginManager(self.model)
        self.context = PluginApiContext(self.model)

        self.plugin_manager.add_property_types(
            CoreExtension().define_property_types())
        self.plugin_manager.add_item_types(
            CoreExtension().define_item_types())

        self.plugin = NetworkPlugin()
        self.model.register_property_types(
            NetworkExtension().define_property_types())
        self.model.register_item_types(
            NetworkExtension().define_item_types())
        self.plugin_manager.add_plugin('TestPlugin', 'some.test.plugin',
                                       '1.0.0', self.plugin)

    def _create_standard_items02(self):
        self.model.create_root_item('root', '/')
        self.model.create_item('deployment', '/deployments/d1')
        self.model.create_item('cluster', "/deployments/d1/clusters/cluster1")

        # Create nodes
        node1 = self.model.create_item("node", "/deployments/d1/clusters/cluster1/nodes/node1", hostname="node1")
        node2 = self.model.create_item("node", "/deployments/d1/clusters/cluster1/nodes/node2", hostname="node2")
        node3 = self.model.create_item("node", "/deployments/d1/clusters/cluster1/nodes/node3", hostname="node3")

        for (idx, node) in enumerate((node1, node2, node3)):
            if_collection = node.network_interfaces.get_vpath()

            self.model.create_item("eth", os.path.join(if_collection, "nic0"),
                    device_name="eth0", ipaddress="10.0.1.{0}".format(idx+1),
                    network_name="mgmt",
                    macaddress='de:ad:be:ef:{0:02d}:01'.format(idx))
            self.model.create_item("eth", os.path.join(if_collection, "nic1"),
                    device_name="eth1", ipaddress="10.0.2.{0}".format(idx+1),
                    network_name="heartbeat",
                    macaddress='de:ad:be:ef:{0:02d}:02'.format(idx))
            self.model.create_item("eth", os.path.join(if_collection, "nic2"),
                    device_name="eth2", ipaddress="10.0.3.{0}".format(idx+1),
                    network_name="storage",
                    macaddress='de:ad:be:ef:{0:02d}:03'.format(idx))
            self.model.create_item("eth", os.path.join(if_collection, "nic3"),
                    device_name="eth3", ipaddress="10.0.4.{0}".format(idx+1),
                    network_name="data",
                    macaddress='de:ad:be:ef:{0:02d}:04'.format(idx))

        # Create new-style network items
        self.model.create_item('network',
                '/infrastructure/networking/networks/mgmt_network',
                name='mgmt', subnet='10.0.1.0/24', litp_management='true')

        self.model.create_item('network',
                '/infrastructure/networking/networks/hrbt_ntwk',
                name='heartbeat', subnet='10.0.2.0/24')

        self.model.create_item('network',
                '/infrastructure/networking/networks/stge_ntwk',
                name='storage', subnet='10.0.3.0/24')

        self.model.create_item('network',
                '/infrastructure/networking/networks/data_ntwk', name='data',
                subnet='10.0.4.0/24')

        # Create systems
        self.sys1_url = "/infrastructure/systems/system1"
        self.sys2_url = "/infrastructure/systems/system2"
        self.sys3_url = "/infrastructure/systems/system3"
        self.model.create_item('system', self.sys1_url, system_name="MN1VM")
        self.model.create_item('system', self.sys2_url, system_name="MN2VM")
        self.model.create_item('system', self.sys3_url, system_name="MN3VM")

        # Deploy system to nodes
        self.model.create_inherited(self.sys1_url, node1.get_vpath() + "/system")
        self.model.create_inherited(self.sys2_url, node2.get_vpath() + "/system")
        self.model.create_inherited(self.sys3_url, node3.get_vpath() + "/system")

        # Create system's network interfaces
        self.model.create_item('nic', self.sys1_url + '/network_interfaces/nic_0', interface_name="eth0", macaddress='08:00:27:5B:C1:3F')
        self.model.create_item('nic', self.sys1_url + '/network_interfaces/nic_1', interface_name="eth1", macaddress='08:00:27:54:C4:34')
        self.model.create_item('nic', self.sys1_url + '/network_interfaces/nic_2', interface_name="eth2", macaddress='08:00:27:33:C1:3A')
        self.model.create_item('nic', self.sys1_url + '/network_interfaces/nic_3', interface_name="eth3", macaddress='08:00:27:12:F2:15')

        self.model.create_item('nic', self.sys2_url + '/network_interfaces/nic_0', interface_name="eth0", macaddress='08:00:27:65:C2:1D')
        self.model.create_item('nic', self.sys2_url + '/network_interfaces/nic_1', interface_name="eth1", macaddress='08:00:27:48:A8:B4')
        self.model.create_item('nic', self.sys2_url + '/network_interfaces/nic_2', interface_name="eth2", macaddress='08:00:27:12:E5:A1')
        self.model.create_item('nic', self.sys2_url + '/network_interfaces/nic_3', interface_name="eth3", macaddress='08:00:27:63:88:B1')

        self.model.create_item('nic', self.sys3_url + '/network_interfaces/nic_0', interface_name="eth0", macaddress='08:00:27:23:C3:B3')
        self.model.create_item('nic', self.sys3_url + '/network_interfaces/nic_1', interface_name="eth1", macaddress='08:00:27:63:73:53')
        self.model.create_item('nic', self.sys3_url + '/network_interfaces/nic_2', interface_name="eth2", macaddress='08:00:27:73:F9:B3')
        self.model.create_item('nic', self.sys3_url + '/network_interfaces/nic_3', interface_name="eth3", macaddress='08:00:27:24:A7:63')

    def _create_IPv6_standard_items(self):
        self.model.create_root_item('root', '/')
        self.model.create_item('deployment', '/deployments/d1')
        self.model.create_item('cluster', "/deployments/d1/clusters/cluster1")

        # Create nodes
        node1 = self.model.create_item("node", "/deployments/d1/clusters/cluster1/nodes/node1", hostname="node1")

        if_collection = node1.network_interfaces.get_vpath()

        self.model.create_item("eth", os.path.join(if_collection, "nic0"),
                device_name="eth0", ipv6address="fdde:4d7e:d471::898:90:101/96",
                network_name="mgmt",
                macaddress='de:ad:be:ef:00:01')

        # Create new-style network items
        self.model.create_item('network',
                '/infrastructure/networking/networks/mgmt_network',
                name='mgmt',
                litp_management='true')

        # Create systems
        self.sys1_url = "/infrastructure/systems/system1"
        self.model.create_item('system', self.sys1_url, system_name="MN1VM")

        # Deploy system to nodes
        self.model.create_inherited(self.sys1_url, node1.get_vpath() + "/system")

        # Create system's network interfaces
        self.model.create_item('nic', self.sys1_url + '/network_interfaces/nic_0', interface_name="eth0", macaddress='08:00:27:5B:C1:3F')

    def test__v4_move_eth_with_route_to_bond(self):

        self._create_standard_items02()

        nic_vpath = '/deployments/d1/clusters/cluster1/nodes/node1/network_interfaces/nic0'
        eth = self.model.get_item(nic_vpath)

        # add routes to model
        route1 = self.model.create_item(
            "route", "/infrastructure/networking/routes/foo",
            subnet="10.11.22.0/24", gateway="10.0.1.11")

        route2 = self.model.create_item(
            "route", "/infrastructure/networking/routes/boo",
            subnet="10.11.33.0/24", gateway="10.0.1.12")

        # deploy to node1
        self.model.create_inherited(
            route1.get_vpath(),
            "/deployments/d1/clusters/cluster1/nodes/node1/routes/foo")

        self.model.create_inherited(
            route1.get_vpath(),
            "/deployments/d1/clusters/cluster1/nodes/node1/routes/boo")

        tasks = self.plugin._new_routes_tasks(self.context)

        # We expect 2 tasks. One to set the routes and other to reload them.
        self.assertEqual(2, len(tasks))
        expected_task_items = set([nic_vpath,])
        self.assertEquals(
            expected_task_items,
            set([task.model_item.get_vpath() for task in tasks])
        )

        eth.set_applied()

        # Lets remove network and IP from interface and add it to a new bond.
        # Expected behavior is that interface routes are moved to bond

        # Remove IP and network from eth0
        self.model.update_item(nic_vpath, ipaddress=None, network_name=None)

        # Create bond
        bond = self.model.create_item("bond",
            "/deployments/d1/clusters/cluster1/nodes/node1/network_interfaces/bond",
            device_name = "bond0",
            ipaddress = "10.0.1.1",
            network_name = "mgmt")

        # Change interface to bond
        self.model.update_item(nic_vpath, master='bond0')

        tasks = self.plugin._new_routes_tasks(self.context)

        # We expect 3 tasks:
        # - Update nic route
        # - Update bond route
        # - Reload routes

        self.assertEqual(3, len(tasks))


    def test__v6_move_eth_with_route_to_bond(self):

        self._create_IPv6_standard_items()

        nic_vpath = '/deployments/d1/clusters/cluster1/nodes/node1/network_interfaces/nic0'
        eth = self.model.get_item(nic_vpath)

        # add routes to model
        route1 = self.model.create_item(
            "route6", "/infrastructure/networking/routes/foo",
            subnet="2001:4a7a::0/96", gateway="fdde:4d7e:d471::898:90:102")

        route2 = self.model.create_item(
            "route6", "/infrastructure/networking/routes/boo",
            subnet="2001:4a7b::0/96", gateway="fdde:4d7e:d471::898:90:103")

        # deploy to node1
        r1 = self.model.create_inherited(
            route1.get_vpath(),
            "/deployments/d1/clusters/cluster1/nodes/node1/routes/foo")

        r2 = self.model.create_inherited(
            route1.get_vpath(),
            "/deployments/d1/clusters/cluster1/nodes/node1/routes/boo")

        tasks = self.plugin._new_routes_tasks(self.context)

        # We expect 2 tasks. One to set the routes and other to reload them.
        self.assertEqual(2, len(tasks))
        expected_task_items = set([nic_vpath,])
        self.assertEquals(
            expected_task_items,
            set([task.model_item.get_vpath() for task in tasks])
        )

        eth.set_applied()

        # Lets remove network and IP from interface and add it to a new bond.
        # Expected behavior is that interface routes are moved to bond

        # Remove IP and network from eth0
        self.model.update_item(nic_vpath, ipv6address=None, network_name=None)

        # Create bond
        bond = self.model.create_item("bond",
            "/deployments/d1/clusters/cluster1/nodes/node1/network_interfaces/bond",
            device_name = "bond0",
            ipv6address = "fdde:4d7e:d471::898:90:101/96",
            network_name = "mgmt")

        # Change interface to bond
        self.model.update_item(nic_vpath, master='bond0')

        tasks = self.plugin._new_routes_tasks(self.context)

        # We expect 3 tasks:
        # - Update nic route
        # - Update bond route
        # - Reload routes

        self.assertEqual(3, len(tasks))

    def test__get_new_route_tasks(self):
        self._create_standard_items02()

        # add routes to model
        route1 = self.model.create_item(
            "route", "/infrastructure/networking/routes/boo",
            subnet="10.0.0.0/24", gateway="10.0.1.254")
        route2 = self.model.create_item(
            "route", "/infrastructure/networking/routes/foo",
            subnet="192.168.1.1/24", gateway="10.0.4.254")
        route3 = self.model.create_item(
            "route", "/infrastructure/networking/routes/bar",
            subnet="0.0.0.0/0", gateway="10.0.1.254")

        # deploy to node1
        self.model.create_inherited(
            route1.get_vpath(),
            "/deployments/d1/clusters/cluster1/nodes/node1/routes/backup")
        self.model.create_inherited(
            route2.get_vpath(),
            "/deployments/d1/clusters/cluster1/nodes/node1/routes/manage")
        self.model.create_inherited(
            route3.get_vpath(),
            "/deployments/d1/clusters/cluster1/nodes/node1/routes/default")

        tasks = self.plugin._new_routes_tasks(self.context)
        # We expect two tasks, one per interface used to reach the routes's
        # several gateways
        self.assertEqual(3, len(tasks))
        expected_task_items = set(['/deployments/d1/clusters/cluster1/nodes/node1/network_interfaces/nic0',
            '/deployments/d1/clusters/cluster1/nodes/node1/network_interfaces/nic3'])

        self.assertEquals(
            expected_task_items,
            set([task.model_item.get_vpath() for task in tasks])
        )

    def test__get_new_route_tasks_with_removed_routes(self):
        self._create_standard_items02()

        # add routes to model
        route1 = self.model.create_item(
            "route", "/infrastructure/networking/routes/boo",
            subnet="10.0.0.0/24", gateway="10.0.1.254")
        route2 = self.model.create_item(
            "route", "/infrastructure/networking/routes/foo",
            subnet="192.168.1.1/24", gateway="10.0.4.254")
        route3 = self.model.create_item(
            "route", "/infrastructure/networking/routes/bar",
            subnet="0.0.0.0/0", gateway="10.0.1.254")

        # deploy to node1
        self.model.create_inherited(
            route1.get_vpath(),
            "/deployments/d1/clusters/cluster1/nodes/node1/routes/backup")
        self.model.create_inherited(
            route2.get_vpath(),
            "/deployments/d1/clusters/cluster1/nodes/node1/routes/manage")
        self.model.create_inherited(
            route3.get_vpath(),
            "/deployments/d1/clusters/cluster1/nodes/node1/routes/default")
        removed = self.model.get_item('/deployments/d1/clusters/cluster1/nodes/node1/routes/backup')
        removed.set_for_removal()

        tasks = self.plugin._new_routes_tasks(self.context)

        self.assertEqual(3, len(tasks))

        dev_route_tasks = [task for task in tasks if hasattr(task.model_item, 'device_name')]

        task_eth0_gateway = [task for task in dev_route_tasks if task.model_item.device_name == 'eth0'][0].kwargs['gateway']
        task_eth0_address = [task for task in dev_route_tasks if task.model_item.device_name == 'eth0'][0].kwargs['address']
        task_eth0_netmask = [task for task in dev_route_tasks if task.model_item.device_name == 'eth0'][0].kwargs['netmask']

        task_eth3_gateway = [task for task in dev_route_tasks if task.model_item.device_name == 'eth3'][0].kwargs['gateway']
        task_eth3_address = [task for task in dev_route_tasks if task.model_item.device_name == 'eth3'][0].kwargs['address']
        task_eth3_netmask = [task for task in dev_route_tasks if task.model_item.device_name == 'eth3'][0].kwargs['netmask']

        task_reload_devices = [task for task in dev_route_tasks if task.call_id == 'node1_route_reload'][0].kwargs['devices']

        self.assertEquals(['0.0.0.0'], task_eth0_address)
        self.assertEquals(['10.0.1.254'], task_eth0_gateway)
        self.assertEquals(['0.0.0.0'], task_eth0_netmask)

        self.assertEquals(['192.168.1.0'], task_eth3_address)
        self.assertEquals(['10.0.4.254'], task_eth3_gateway)
        self.assertEquals(['255.255.255.0'], task_eth3_netmask)

        self.assertEquals(set(['eth0', 'eth3']), set(task_reload_devices))

    def test__get_new_route_tasks_correct_device(self):
        route1 = Mock(name='route1', subnet='10.0.0.0/24', gateway='10.0.1.254')
        route2 = Mock(name='route2', subnet='192.168.1.0/24', gateway='10.0.2.254')
        route3 = Mock(name='route3', subnet='192.168.2.0/24', gateway='10.0.3.254')

        mocknetworks = [
            Mock(subnet='10.0.1.0/24'),
            Mock(subnet='10.0.2.0/24'),
            Mock(subnet='10.0.3.0/24')
            ]
        # 'name' is a special attribute for the Mock creator, so
        # a bit of trickery is needed in this case..
        mocknetworks[0].configure_mock(name='net0')
        mocknetworks[1].configure_mock(name='net1')
        mocknetworks[2].configure_mock(name='net2')

        node1 = Mock(hostname='node1',
            routes=[route1, route2, route3],
            network_interfaces=[
                Mock(network_name='net0', device_name='eth0'),
                Mock(network_name='net1', device_name='eth1'),
                Mock(network_name='net2', device_name='eth2')
                ],
            )

        mockcontext = Mock(
            query=lambda item, name: [n for n in mocknetworks if n.name == name]
        )

        self.assertEqual('eth0', self.plugin._device_name_for_IPv4_route(mockcontext, node1, route1.gateway).device_name)
        self.assertEqual('eth1', self.plugin._device_name_for_IPv4_route(mockcontext, node1, route2.gateway).device_name)
        self.assertEqual('eth2', self.plugin._device_name_for_IPv4_route(mockcontext, node1, route3.gateway).device_name)

    def test_heartbeat_nets(self):
        routes = []
        mocknetworks = []
        network_interfaces = []
        route1 = Mock(name='route1', subnet='10.0.0.0/24', gateway='10.0.1.254')
        route2 = Mock(name='route2', subnet='192.168.1.0/24', gateway='10.0.2.254')
        route3 = Mock(name='route3', subnet='192.168.2.0/24', gateway='10.0.3.254')

        mocknetworks = [
            Mock(subnet='10.0.1.0/24'),
            Mock(subnet='10.0.2.0/24'),
            Mock(subnet=None)
            ]
        # 'name' is a special attribute for the Mock creator, so
        # a bit of trickery is needed in this case..
        mocknetworks[0].configure_mock(name='net0')
        mocknetworks[1].configure_mock(name='net1')
        mocknetworks[2].configure_mock(name='hb1')

        node1 = Mock(hostname='node1',
            routes=[route1, route2, route3],
            network_interfaces=[
                Mock(network_name='net0', device_name='eth0', ipaddress='10.0.1.2'),
                Mock(network_name='net1', device_name='eth1', ipaddress='10.0.2.2'),
                Mock(network_name='hb1', device_name='eth2', ipaddress=None)
                ],
            )

        mockcontext = Mock(
            query=lambda item, name: [n for n in mocknetworks if n.name == name]
        )

        self.assertEqual('eth0', self.plugin._device_name_for_IPv4_route(mockcontext, node1, route1.gateway).device_name)
        self.assertEqual('eth1', self.plugin._device_name_for_IPv4_route(mockcontext, node1, route2.gateway).device_name)
        no_device = self.plugin._device_name_for_IPv4_route(mockcontext, node1, route3.gateway)
        self.assertEqual(None, no_device)


    def test_gateway_update_interface_change(self):
        networkA = Mock(subnet='10.0.0.0/8')
        networkA.name = 'foo'

        networkB = Mock(subnet='192.168.1.0/24')
        networkB.name = 'bar'

        networks = [networkA, networkB]

        node = Mock(
                hostname='node1',
                get_vpath=lambda: '/node',
                is_for_removal=lambda: False,
                network_interfaces=[
                    Mock(
                        device_name='eth0',
                        macaddress='11:22:33:44:55:66',
                        network_name='foo',
                        ipaddress='10.0.0.23',
                        get_vpath=lambda: '/node/nic1',
                        is_for_removal=lambda: False,
                        is_updated=lambda:False,

                    ),
                    Mock(
                        device_name='eth1',
                        macaddress='77:88:99:AA:BB:CC',
                        network_name='bar',
                        ipaddress='192.168.1.100',
                        get_vpath=lambda: '/node/nic2',
                        is_for_removal=lambda: False,
                        is_updated=lambda:False,
                    ),
                ]
            )

        node_routes = [
            Mock(item_type_id='route',
                 name='default',
                 subnet='0.0.0.0/0',
                 gateway='10.0.0.1',
                 is_initial=lambda: True,
                 is_updated=lambda: False,
                 is_applied=lambda: False,
                 is_for_removal=lambda: False),
            Mock(item_type_id='route',
                 name='extra',
                 subnet='20.0.0.0/8',
                 gateway='10.0.0.2',
                 is_initial=lambda: False,
                 is_updated=lambda: True,
                 is_applied=lambda: False,
                 is_for_removal=lambda: False,
                 applied_properties={'name': 'extra', 'gateway': '192.168.1.1', 'subnet': '20.0.0.0/8'})
        ]

        node.routes = node_routes

        def _mock_node_query(type, **kwargs):
            if 'is_initial' in kwargs:
                return [node_routes[0]]
            elif 'is_updated' in kwargs:
                return [node_routes[1]]
            elif 'is_applied' in kwargs:
                return []
            else:
                return node_routes

        node.query = _mock_node_query


        mock_context = Mock()
        def _mock_context_query(type, **kwargs):
            if 'network' == type:
                if 'name' in kwargs:
                    return [net for net in networks if kwargs['name'] == net.name]
                else:
                    return networks
            elif 'ms' == type:
                return []
            else:
                return [node]

        mock_context.query = _mock_context_query

        tasks = self.plugin._new_routes_tasks(mock_context)
        self.assertEquals(3, len(tasks))

        expected_set_of_interfaces = set(['/node/nic1', '/node/nic2'])
        self.assertEquals(expected_set_of_interfaces, set([task.model_item.get_vpath() for task in tasks]))

        nic1_task = [task for task in tasks if '/node/nic1' == task.model_item.get_vpath()][0]
        nic2_task = [task for task in tasks if '/node/nic2' == task.model_item.get_vpath()][0]
        self.assertEquals(2, len(nic1_task.kwargs['address']))
        self.assertEquals(0, len(nic2_task.kwargs['address']))
        self.assertEquals(2, len(nic1_task.kwargs['netmask']))
        self.assertEquals(0, len(nic2_task.kwargs['netmask']))
        self.assertEquals(2, len(nic1_task.kwargs['gateway']))
        self.assertEquals(0, len(nic2_task.kwargs['gateway']))
        self.assertEquals(2, len(nic1_task.kwargs['family']))
        self.assertEquals(0, len(nic2_task.kwargs['family']))


    def test_gateway_update_no_nic(self):
        network1 = Mock(subnet='192.168.1.0/24')
        network1.name = 'bar'

        networks = [network1]

        node = Mock(
                hostname='node1',
                get_vpath=lambda: '/node',
                is_for_removal=lambda: False,
                network_interfaces=[
                    Mock(
                        device_name='eth0',
                        macaddress='77:88:99:AA:BB:CC',
                        network_name='bar',
                        ipaddress='192.168.1.100',
                        get_vpath=lambda: '/node/nic0',
                        is_for_removal=lambda: False,
                        is_updated=lambda: False,
                    ),
                ]
            )

        node_routes = [
                Mock(item_type_id='route', name='extra', subnet='20.0.0.0/8', gateway='192.168.1.1',
                     is_initial=lambda: False, is_updated=lambda: True, is_applied=lambda: False,
                     is_for_removal=lambda: False,
                     applied_properties={'name': 'extra', 'gateway': '172.168.1.1', 'subnet': '20.0.0.0/8'})
            ]
        node.routes = node_routes

        def _mock_node_query(type, **kwargs):
            if 'is_initial' in kwargs:
                return []
            elif 'is_updated' in kwargs:
                return [node_routes[0]]
            elif 'is_applied' in kwargs:
                return []
            else:
                return node_routes

        node.query = _mock_node_query


        mock_context = Mock()
        def _mock_context_query(type, **kwargs):
            if 'network' == type:
                if 'name' in kwargs:
                    return [net for net in networks if kwargs['name'] == net.name]
                else:
                    return networks
            elif 'ms' == type:
                return []
            else:
                return [node]

        mock_context.query = _mock_context_query

        tasks = self.plugin._new_routes_tasks(mock_context)
        self.assertEquals(2, len(tasks))

    def test_route_param_sorting(self):
        ordered_list = ['ADDRESS', 'NETMASK', 'GATEWAY']
        self.assertEquals(ordered_list, sorted(['ADDRESS', 'NETMASK', 'GATEWAY'], cmp=sort_route_params))
        self.assertEquals(ordered_list, sorted(['ADDRESS', 'GATEWAY', 'NETMASK'], cmp=sort_route_params))
        self.assertEquals(ordered_list, sorted(['NETMASK', 'ADDRESS', 'GATEWAY'], cmp=sort_route_params))
        self.assertEquals(ordered_list, sorted(['NETMASK', 'GATEWAY', 'ADDRESS'], cmp=sort_route_params))
        self.assertEquals(ordered_list, sorted(['GATEWAY', 'NETMASK', 'ADDRESS'], cmp=sort_route_params))
        self.assertEquals(ordered_list, sorted(['GATEWAY', 'ADDRESS', 'NETMASK'], cmp=sort_route_params))

    def test__add_ipvaddress_to_device(self):

        network1 = Mock(subnet='192.168.1.0/24')
        network1.name = 'foo'

        networks = [network1]

        # LITPCDS-7843, this issue happened when ipv6address was added
        # to device but there was not applied.properties['ipv6address]
        # so that scenario is what this test covers.
        # Checked for IPv4 as well

        node = Mock(
                hostname='node1',
                get_vpath=lambda: '/node',
                is_for_removal=lambda: False,
                network_interfaces=[
                    Mock(
                        device_name='br0',
                        network_name='foo',
                        get_vpath=lambda: '/node/nic1',
                        is_for_removal=lambda: False,
                        is_updated=lambda:True,
                        applied_properties={},
                        ipv6address='fdde:4d7e:d471::898:10:101/96',
                        ipaddres='192.168.1.100'
                    ),
                ]
            )

        node_routes = [
            Mock(item_type_id='route6', name='route', subnet='2001:4a7b::0/96',
                 gateway='fdde:4d7e:d471::898:10:102',
                 is_initial=lambda: False,
                 is_updated=lambda: True,
                 is_applied=lambda: False,
                 is_for_removal=lambda: False,
                 applied_properties={}),
            Mock(item_type_id='route', name='route', subnet='192.168.20.0/24',
                 gateway='192.168.1.1',
                 is_initial=lambda: False,
                 is_updated=lambda: True,
                 is_applied=lambda: False,
                 is_for_removal=lambda: False,
                 applied_properties={})
        ]

        node.routes = node_routes

        def _mock_node_query(type, **kwargs):
            if 'is_initial' in kwargs:
                return [node_routes[0]]
            elif 'is_updated' in kwargs:
                return [node_routes[1]]
            elif 'is_applied' in kwargs:
                return []
            else:
                return node_routes

        node.query = _mock_node_query

        mock_context = Mock()
        def _mock_context_query(type, **kwargs):
            if 'network' == type:
                if 'name' in kwargs:
                    return [net for net in networks if kwargs['name'] == net.name]
                else:
                    return networks
            elif 'ms' == type:
                return []
            else:
                return [node]

        mock_context.query = _mock_context_query

        tasks = self.plugin._new_routes_tasks(mock_context)
        self.assertEqual(2, len(tasks))

    def test_routes_reachable_through_local_networks(self):
        routes = []
        mocknetworks = []
        network_interfaces = []

        route1 = Mock(item_type_id='route',
                      subnet='0.0.0.0/0',
                      gateway='192.168.1.1',
                      get_vpath=lambda:'/routes/route1',
                      is_for_removal=lambda: False)
        route1.configure_mock(name='route1')

        route2 = Mock(item_type_id='route',
                      subnet='192.168.1.128/26',
                      gateway='192.168.1.1',
                      get_vpath=lambda:'/routes/route2',
                      is_for_removal=lambda: False)
        route2.configure_mock(name='route2')

        route3 = Mock(item_type_id='route6',
                      subnet='2222:4444::/64',
                      gateway='fdde:4444::1',
                      get_vpath=lambda:'/routes/route3',
                      is_for_removal=lambda: False)
        route3.configure_mock(name='route3')

        route4 = Mock(item_type_id='route6',
                      subnet='::/0',
                      gateway='fdde:4444::1',
                      get_vpath=lambda:'/routes/route4',
                      is_for_removal=lambda: False)
        route4.configure_mock(name='route3')

        mocknetworks = [
            Mock(subnet='192.168.1.128/26',
                 is_for_removal=lambda: False),
            Mock(subnet='192.168.1.0/26',
                 is_for_removal=lambda: False),
        ]

        # 'name' is a special attribute for the Mock creator, so
        # a bit of trickery is needed in this case..
        mocknetworks[0].configure_mock(name='net0')
        mocknetworks[1].configure_mock(name='net1')

        node1 = Mock(hostname='node1',
            routes=[route1, route2, route3, route4],
            networks=mocknetworks,
            network_interfaces=[
                Mock(network_name='net0',
                     device_name='eth0',
                     ipaddress='192.168.1.129',
                     ipv6address='',
                     get_vpath=lambda:'/network_interfaces/if1',
                     is_for_removal=lambda: False),
                Mock(network_name='net1',
                     device_name='eth1',
                     ipaddress='192.168.1.10',
                     ipv6address='',
                     get_vpath=lambda:'/network_interfaces/if2',
                     is_for_removal=lambda: False),
                Mock(device_name='eth2',
                     ipaddress='',
                     get_vpath=lambda:'/network_interfaces/if3',
                     ipv6address='2222:4444::10/64',
                     is_for_removal=lambda: False)
                ],
            )

        errors = self.plugin.\
            _validate_routes_not_reachable(node1, mocknetworks)

        self.assertEqual(2, len(errors))
        self.assertEqual('A route with value "192.168.1.128/26" for property ' \
                         '"subnet" is invalid as it is accessible via ' \
                         'interface named "eth0"',
                         errors[0].error_message)
        self.assertEqual('A route with value "2222:4444::/64" for property ' \
                         '"subnet" is invalid as it is accessible via ' \
                         'interface named "eth2"',
                         errors[1].error_message)
