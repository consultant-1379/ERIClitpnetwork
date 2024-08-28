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

from litp.core.plugin_manager import PluginManager
from litp.core.model_manager import ModelManager
from litp.core.model_item import ModelItem
from litp.core.plugin_context_api import PluginApiContext
from litp.core.validators import ValidationError
from litp.extensions.core_extension import CoreExtension

from network_plugin.network_plugin import NetworkPlugin
from network_extension.network_extension import NetworkExtension


class TestNetworkValidation(unittest.TestCase):

    def setUp(self):
        self.model_manager = ModelManager()
        self.plugin_manager = PluginManager(self.model_manager)
        self.context = PluginApiContext(self.model_manager)

        self.plugin_manager.add_property_types(
            CoreExtension().define_property_types())
        self.plugin_manager.add_item_types(
            CoreExtension().define_item_types())

        self.api = NetworkExtension()
        self.plugin = NetworkPlugin()
        self.model_manager.register_property_types(
            self.api.define_property_types())
        self.model_manager.register_item_types(self.api.define_item_types())
        self.plugin_manager.add_plugin('TestPlugin', 'some.test.plugin',
                                       '1.0.0', self.plugin)
        self.default_route = None
        self.node1_path = None
        self.networks_path = '/infrastructure/networking/networks/'
        self.routes_path = '/infrastructure/networking/routes/'

    def tearDown(self):
        pass

    def _create_standard_items(self):
        root = self.model_manager.create_root_item('root', '/')

        deploy = self.model_manager.create_item('deployment', '/deployments/d1')

        cluster = self.model_manager.create_item('cluster',
                                                 '/deployments/d1/clusters/c1')
        for item in [root, deploy, cluster]:
            self.assertTrue(isinstance(item, ModelItem))

    def _create_node(self, node_id, host):
        url = '/deployments/d1/clusters/c1/nodes/' + node_id
        node_item = self.model_manager.create_item('node', url, hostname=host)
        self.assertTrue(isinstance(node_item, ModelItem))
        self.node1_path = url
        return node_item

    def test_validate_vlan_ids_unique(self):
        vlan1 = Mock(device_name="eth1.10",
                     is_for_removal=lambda: False,
                     get_vpath=lambda: '/a/b/c')
        vlan2 = Mock(device_name="eth2.11",
                     is_for_removal=lambda: False,
                     get_vpath=lambda: '/d/e/f')
        vlan_interfaces = [vlan1, vlan2]

        node = Mock(hostname="sc1",
                    is_for_removal=lambda: False,
                    query=lambda q: vlan_interfaces)

        errors = self.plugin._validate_vlan_ids_unique(node)
        self.assertEqual([], errors)

        # ------------
        vlan2.device_name="eth2.10"
        errors = self.plugin._validate_vlan_ids_unique(node)
        emsg = 'VLAN ID "10" is used for more than one interface, it must be unique.'
        expected_errors = [ValidationError('/a/b/c', error_message=emsg),
                           ValidationError('/d/e/f', error_message=emsg)]
        self.assertEqual(expected_errors, errors)

    def test_validate_device_names_unique(self):
        '''
        Validate that device_names are unique - with Node scope
        '''

        # No device_name error expected
        network_interfaces = [Mock(device_name='foo',
                                   is_for_removal=lambda: False),
                              Mock(device_name='bar',
                                   is_for_removal=lambda: False)]
        node = Mock(network_interfaces=network_interfaces, hostname="sc-1")
        errors = self.plugin._validate_device_names_unique(node)
        self.assertEqual([], errors)

        # device_name values are *not* unqiue
        network_interfaces = [Mock(device_name='bar',
                                   is_for_removal=lambda: False),
                              Mock(device_name='bar',
                                   is_for_removal=lambda: False)]
        node = Mock(network_interfaces=network_interfaces, hostname="sc-1")
        errors = self.plugin._validate_device_names_unique(node)
        self.assertEqual(1, len(errors))

    def test_ms_ip_not_removed(self):
        mgmt_net = Mock(subnet='10.1.2.0/24')
        mgmt_net.name = 'foo'
        mgmt_net.litp_management = 'true'

        # No 'new' IP, just an old one.
        # User is attempting to delete the MS IP.
        iface = Mock(is_updated=lambda: True,
                     ipaddress=None,
                     ipv6address=None,
                     network_name='foo',
                     applied_properties={'ipaddress': '1.2.3.4'},
                     get_vpath=lambda: '/x/y/z')

        node = Mock(network_interfaces=[iface])

        errors = self.plugin._validate_ms_mgmt_ip_not_removed(node, mgmt_net)
        emsg = 'Removal of the IPv4 address from the MS management interface is not currently supported'
        self.assertEqual([ValidationError('/x/y/z', error_message=emsg)],
                         errors)

    def _ip_route_create_default_route(self, route_name, route_id):
        default_route = self.model_manager.create_item(
            'route',
            self.routes_path + route_id,
            subnet='0.0.0.0/0',
            gateway='10.0.0.1',
            )
        self.assertTrue(isinstance(default_route, ModelItem))
        return default_route

    def tests_validate_overlapping_subnets(self):

        '''
        Validate no overlapping subnets on a per node basis.
        Route subnets should be ignored
        '''

        # Over lapping Network subnets
        net1 = Mock(subnet="10.0.0.0/24")
        net1.name = "mgmt_ipv4"

        net2 = Mock(subnet="10.0.0.0/16")
        net2.name = "backup_ipv4"

        net3 = Mock(subnet="10.0.0.0/8")
        net3.name = "backup2"

        ipv4_networks = [net1, net2, net3]

        iface1 = Mock(ipaddress="10.0.0.2",
                      ipv6address=None,
                      network_name="mgmt_ipv4",
                      item_type_id = 'eth',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/iface1')
        iface2 = Mock(ipaddress="10.0.0.3",
                      ipv6address=None,
                      network_name="backup_ipv4",
                      item_type_id = 'bond',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/iface2')
        iface3 = Mock(ipaddress="10.0.0.4",
                      ipv6address=None,
                      network_name="backup2",
                      item_type_id = 'eth',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/iface3')
        iface5 = Mock(ipaddress="10.0.0.100",
                      ipv6address=None,
                      network_name="mgmt_ipv4",
                      item_type_id = 'bond',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/iface5')
        iface6 = Mock(ipaddress=None,
                      ipv6address="::192.168.0.0/120",
                      network_name="mgmt_ipv4",
                      item_type_id = 'bond',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/iface6')
        iface7 = Mock(ipaddress=None,
                      ipv6address="::192.168.0.0/121",
                      network_name="mgmt_ipv4",
                      item_type_id = 'bond',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/iface7')

        node1 = Mock(network_interfaces=[iface1, iface2, iface3],
                    hostname='node1',
                    routes=None,
                    get_vpath=lambda: '/x/y/z')


        node3 = Mock(network_interfaces=[iface1, iface5],
                    hostname='node3',
                    routes=None,
                    get_vpath=lambda: '/d/e/f')

        node4 = Mock(network_interfaces=[iface6, iface7],
                    hostname='node4',
                    routes=None,
                    get_vpath=lambda: '/m/n/o')


        errors = self.plugin._validate_network_subnets_overlap(\
                                            node1, ipv4_networks)

        emsg = 'Overlapping network subnet ' + \
               'defined on network interface '

        #Two networks on the same node with overlapping ipv4 subnets
        self.assertEqual(set([ValidationError(item_path='/iface1',
                        error_message=emsg),
                        ValidationError(item_path='/iface3',
                        error_message=emsg),
                        ValidationError(item_path='/iface2',
                        error_message=emsg)]), set(errors))

        errors = self.plugin._validate_network_subnets_overlap(\
                                            node3, ipv4_networks)

        self.assertEqual(set([]), set(errors))


        errors = self.plugin._validate_network_subnets_overlap(\
                                            node4, ipv4_networks)

        #Two networks on the same node with overlapping ipv6 subnets
        self.assertEqual(set([ValidationError(item_path='/iface6',
                        error_message=emsg),
                        ValidationError(item_path='/iface7',
                        error_message=emsg)]), set(errors))

    def tests_validate_gateways_local(self):

        '''
        Validate number of Networks for Route gateway
        '''

        # Over lapping Network subnets
        net1 = Mock(subnet="10.0.0.0/24")
        net1.name = "mgmt"

        net2 = Mock(subnet="10.0.0.0/16")
        net2.name = "backup"

        networks = [net1, net2]

        # Interfaces using separate Networks

        # The ipv6address=None is required, because MagickMock does odd
        # things when queried for nonexistent attributes.
        iface1 = Mock(ipaddress="1.2.3.4",
                      ipv6address=None,
                      network_name="mgmt",
                      is_for_removal=lambda: False)
        iface2 = Mock(ipaddress="1.2.3.5",
                      ipv6address=None,
                      network_name="backup",
                      is_for_removal=lambda: False)

        # A Route with a gateway *not* in one of our Networks
        route1 = Mock(is_for_removal=lambda: False,
                      item_type_id = 'route',
                      gateway="30.0.0.1",
                      get_vpath=lambda: '/f/g/h')

        node = Mock(network_interfaces=[iface1, iface2],
                    routes=[route1],
                    hostname='node',
                    get_vpath=lambda: '/x/y/z')

        errors = self.plugin._validate_gateways_local(node, networks)

        emsg = 'Route gateway is not reachable '\
        'from any of the interfaces on node "node"'
        self.assertEqual([ValidationError('/f/g/h', error_message=emsg)],
                         errors)

        # -----

        # The Route with a gateway in our Network(s)
        route1.gateway = "10.0.0.1"
        errors = self.plugin._validate_gateways_local(node, networks)

        emsg = 'Route gateway is reachable from more than one interface on node "node"'
        self.assertEqual([ValidationError('/f/g/h', error_message=emsg)],
                         errors)

    def tests_validate_ipv6_gateway_local(self):

        '''
        Validate that local IPv6 address can not be
        used as GW.
        '''

        local_ip = "fdde:4d7e:d471::898:90:101"

        net1 = Mock(subnet="2001:4a7e::0/96")
        net1.name = "net6"

        networks = [net1]

        iface1 = Mock(ipv6address="{0}/96".format(local_ip),
                      ipvaddress=None,
                      network_name="net6",
                      is_for_removal=lambda: False)

        # A Route using local IPv6 as gateway
        route1 = Mock(is_for_removal=lambda: False,
                      item_type_id = 'route6',
                      gateway=local_ip,
                      get_vpath=lambda: '/f/g/h')

        node = Mock(network_interfaces=[iface1],
                    routes=[route1],
                    hostname='node',
                    get_vpath=lambda: '/x/y/z')

        errors = self.plugin._validate_gateways_local(node, networks)

        emsg = 'Local IPv6 address "{0}" ' \
               'can not be used as gateway.'.format(local_ip)
        self.assertEqual([ValidationError('/f/g/h', error_message=emsg)],
                         errors)

    def test_validate_name_usage(self):
        self._create_standard_items()
        self._create_node('n1', 'node1')

        a = self.model_manager.create_item(
            'network',
            self.networks_path + 'mgmt_network',
            subnet='10.0.0.0/24',
            name='mgmt',
            litp_management='true'
            )

        b = self.model_manager.create_item(
            'route',
            self.routes_path + 'defroute',
            subnet='0.0.0.0/0', gateway='10.0.0.1'
            )

        c = self.model_manager.create_inherited(
            b.get_vpath(),
            self.node1_path + '/routes/default')

        d = self.model_manager.create_inherited(
            b.get_vpath(),
            '/ms/routes/default'
            )
        e = self.model_manager.create_item(
            "eth",
            '/ms/network_interfaces/if0',
            network_name="mgmt",
            device_name="eth0",
            ipaddress='10.0.0.3',
            macaddress='08:00:27:65:C2:1D'
            )

        f = self.model_manager.create_item(
            "eth",
            self.node1_path + "/network_interfaces/if0",
            network_name="mgmt",
            device_name="eth0",
            ipaddress='10.0.0.2',
            macaddress='08:00:27:65:C2:1E'
            )

        g = self.model_manager.create_item(
            "eth",
            self.node1_path + "/network_interfaces/if1",
            network_name="mgmt",
            device_name="eth1",
            ipaddress="10.0.0.2",
            macaddress='08:00:27:48:A8:B4'
            )

        for item in [a, b, c, d, e, f, g]:
            self.assertTrue(isinstance(item, ModelItem))

        net_ifaces_path = self.node1_path + '/network_interfaces/'

        self.assertEquals(
            set([
                ValidationError(self.node1_path + "/routes/default", error_message='Route gateway is reachable from more than one interface on node "node1"'),
                ValidationError(net_ifaces_path + "if0", error_message='IP addresses must be unique per node.'),
                ValidationError(net_ifaces_path + "if1", error_message='IP addresses must be unique per node.'),
                ValidationError(net_ifaces_path + "if0", error_message='IP addresses must be unique per network.'),
                ValidationError(net_ifaces_path + "if1", error_message='IP addresses must be unique per network.'),
                ValidationError(net_ifaces_path + "if0", error_message='Network name "mgmt" must be used by one network-interface.'),
                ValidationError(net_ifaces_path + "if1", error_message='Network name "mgmt" must be used by one network-interface.'),
                ValidationError(net_ifaces_path + "if0", error_message='The management network must be used for one network interface.')
                ]),
            set(self.plugin.validate_model(self.context))
            )

    # -------------------------------
    def _create_net_items(self, node1, mgmt_net):
        a = self.model_manager.create_item(
            'network',
            self.networks_path + 'n0',
            name="mgmt",
            subnet="10.0.0.0/24",
            litp_management=mgmt_net)

        b = self.model_manager.create_item(
            'eth',
            node1.get_vpath() + '/network_interfaces/n0',
            ipaddress='10.0.0.5',
            ipv6address='2001::2:3', # dual-stack..
            network_name='mgmt',
            macaddress="00:00:00:00:00:00",
            device_name="eth0")

        c = self.model_manager.create_item(
            'eth',
            '/ms/network_interfaces/n0',
            bridge='br0',
            macaddress="00:00:00:00:00:01",
            device_name="eth0")

        d = self.model_manager.create_item(
            'bridge',
            '/ms/network_interfaces/b0',
            ipaddress='10.0.0.7',
            network_name='mgmt',
            device_name="br0")

#       from pprint import pprint; pprint(d)

        for item in [a, b, c, d]:
            self.assertTrue(isinstance(item, ModelItem))

    def test_validate_model_ok(self):
        '''
        Happy path to validate the positive case of Validation being ok
        '''

        self._create_standard_items()
        node1 = self._create_node('n1', 'sc1')

        default_route = self._ip_route_create_default_route('def', 'def')

        for path in [node1.get_vpath(), '/ms']:
            l = self.model_manager.create_inherited(default_route.get_vpath(),
                                                    path + '/routes/r0')
            self.assertTrue(isinstance(l, ModelItem))

        self._create_net_items(node1, 'true')

        errors = self.plugin.validate_model(self.context)
        self.assertEqual([], errors)

    def test_validate_model_not_ok(self):
        '''
        Validate the basic -ive case of no Mgmt network
        '''

        self._create_standard_items()
        node1 = self._create_node('n1', 'sc1')

        default_route = self._ip_route_create_default_route('def', 'def')

        for path in [node1.get_vpath(), '/ms']:
            l = self.model_manager.create_inherited(default_route.get_vpath(),
                                                    path + '/routes/r0')
            self.assertTrue(isinstance(l, ModelItem))

        self._create_net_items(node1, 'false')

        errors = self.plugin.validate_model(self.context)

        msg = 'There must be exactly one network assigned ' \
              'litp_management="true"'
        expected_errors = [ValidationError('/infrastructure/networking/networks',
                                           error_message=msg)]
        self.assertEqual(expected_errors, errors)

    def test_validate_ips_unique_in_node(self):

        '''
        IP addresses must be unique - with Node scope.
        '''

        # 2 network-interfaces with the same IP
        duplicated_ip = "1.2.3.4"
        iface1 = Mock(ipaddress=duplicated_ip,
                      ipv6address=None,
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/a/b/c')

        iface2 = Mock(ipaddress=duplicated_ip,
                      ipv6address=None,
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/y/z')

        node = Mock(network_interfaces=[iface1, iface2],
                    hostname='sc1')

        self.assertEquals(
                [ValidationError('/a/b/c',
                                 error_message="IP addresses must be unique per node."),
                 ValidationError('/x/y/z',
                                 error_message="IP addresses must be unique per node.")],
                self.plugin._validate_ips_unique_in_node(node))

        # -----

        # Change the 2nd network-interface to a unique IP
        iface2 = Mock(ipaddress="1.2.3.5",
                      ipv6address="",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/y/z')

        node = Mock(network_interfaces=[iface1, iface2],
                    hostname='sc1')

        self.assertEquals([], self.plugin._validate_ips_unique_in_node(node))

        # -----
        # Add a 3rd interface thats marked for deletion
        iface3 = Mock(ipaddress="1.2.3.6",
                      ipv6address="",
                      is_for_removal=lambda: True,
                      get_vpath=lambda: '/d/e/f')

        node = Mock(network_interfaces=[iface1, iface2, iface3],
                    hostname='sc1')

        self.assertEquals([], self.plugin._validate_ips_unique_in_node(node))

    def test_validate_ips_unique_in_network(self):

        '''
        IP addresses must be unique - with Network scope.
        '''

        # 2 network-interfaces with the same IP
        ip1 = "1.2.3.4"
        ip2 = "1.2.3.5"
        iface1_1 = Mock(ipaddress= ip1,
                      ipv6address=None,
                      network_name='network1',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/a/n1/if0')

        iface1_2 = Mock(ipaddress=ip2,
                      ipv6address=None,
                      network_name='network2',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/n1/if1')

        iface2_1 = Mock(ipaddress= ip1,
                      ipv6address=None,
                      network_name='network1',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/a/n2/if0')

        iface2_2 = Mock(ipaddress=ip2,
                      ipv6address=None,
                      network_name='network2',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/n2/if1')


        iface2_3 = Mock(ipaddress=ip1,
                      ipv6address=None,
                      network_name='network2',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/n2/if2')

        node1 = Mock(network_interfaces=[iface1_1, iface1_2],
                    hostname='sc1')

        node2 = Mock(network_interfaces=[iface2_1, iface2_2, iface2_3],
                    hostname='sc2')

        self.assertEquals(
                [ValidationError('/x/n1/if1',
                                 error_message="IP addresses must be unique per network."),
                 ValidationError('/x/n2/if1',
                                 error_message="IP addresses must be unique per network."),
                 ValidationError('/a/n1/if0',
                                error_message="IP addresses must be unique per network."),
                 ValidationError('/a/n2/if0',
                                error_message="IP addresses must be unique per network.")],
                 self.plugin._validate_ips_unique_in_network([node1, node2]))

    def test_validate_ipv6s_unique_in_network(self):

        '''
        IPv6 addresses must be unique - with Network scope.
        '''

        # 2 network-interfaces with the same IP
        ip1 = "fe80::fc54:ff:fe84:0001/64"
        ip2 = "fe80::fc54:ff:fe84:0002/64"
        iface1_1 = Mock(ipv6address= ip1,
                      ipaddress=None,
                      network_name='network1',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/a/n1/if0')

        iface1_2 = Mock(ipv6address=ip2,
                      ipaddress=None,
                      network_name='network2',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/n1/if1')

        iface2_1 = Mock(ipv6address= ip1,
                      ipaddress=None,
                      network_name='network1',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/a/n2/if0')

        iface2_2 = Mock(ipv6address=ip2,
                      ipaddress=None,
                      network_name='network2',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/n2/if1')

        iface2_3 = Mock(ipv6address=ip1,
                      ipaddress=None,
                      network_name='network2',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/n2/if2')

        node1 = Mock(network_interfaces=[iface1_1, iface1_2],
                    hostname='sc1')

        node2 = Mock(network_interfaces=[iface2_1, iface2_2, iface2_3],
                    hostname='sc2')

        self.assertEquals(
                [ValidationError('/x/n1/if1',
                                 error_message="IPv6 addresses must be unique per network."),
                 ValidationError('/x/n2/if1',
                                 error_message="IPv6 addresses must be unique per network."),
                 ValidationError('/a/n1/if0',
                                 error_message="IPv6 addresses must be unique per network."),
                 ValidationError('/a/n2/if0',
                                 error_message="IPv6 addresses must be unique per network.")],
                self.plugin._validate_ips_unique_in_network([node1, node2]))

    def test_validate_ipv6_unique_in_node(self):
        duplicated_v6_ip = "fe80::fc54:ff:fe84:a1c7/64"

        # Let's compare two IPv6-only interfaces
        iface1 = Mock(ipv6address=duplicated_v6_ip,
                      ipaddress='',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/if1')

        iface2 = Mock(ipv6address=duplicated_v6_ip,
                      ipaddress='',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/if2')

        node = Mock(network_interfaces=[iface1, iface2],
                    hostname='sc1')

        self.assertEquals(
                [ValidationError('/if1',
                                 error_message="IPv6 addresses must be unique per node."),
                 ValidationError('/if2',
                                 error_message="IPv6 addresses must be unique per node.")],
                self.plugin._validate_ips_unique_in_node(node))

        # -----------

        iface2 = Mock(ipv6address="fe80::baca:3aff:fe96:8da4/64",
                      ipaddress='',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/if2')

        # Mixed-bag of IPv4 and IPv6 interfaces
        duplicated_v4_ip = '10.11.12.13'
        iface3 = Mock(ipaddress=duplicated_v4_ip,
                      ipv6address='',
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/if3')

        iface4 = Mock(ipv6address=duplicated_v6_ip,
                      ipaddress=duplicated_v4_ip,
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/if4')

        node.network_interfaces = [iface1, iface2, iface3, iface4]
        expected_errors = [
            ValidationError(item_path='/if1',
                      error_message="IPv6 addresses must be unique per node."),
            ValidationError(item_path='/if3',
                        error_message="IP addresses must be unique per node."),
            ValidationError(item_path='/if4',
                        error_message="IP addresses must be unique per node."),
            ValidationError(item_path='/if4',
                       error_message="IPv6 addresses must be unique per node.")
        ]
        errors = self.plugin._validate_ips_unique_in_node(node)
        self.assertEquals(expected_errors, errors)

    def test_validate_node_macs_unique(self):
        '''
        MAC address must be unique
        '''

        # 2 network-interfaces with the same MAC
        duplicated_mac = "00:00:00:00:00:00"
        iface1 = Mock(macaddress=duplicated_mac,
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/node1/b/c')

        iface2 = Mock(macaddress=duplicated_mac,
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/node2/y/z')

        node1 = Mock(network_interfaces=[iface1], hostname='sc1')
        node2 = Mock(network_interfaces=[iface2], hostname='sc2')
        context = Mock()
        context.query = lambda x: [iface1, iface2]

        self.assertEquals(
                [ValidationError('/node1/b/c',
                                 error_message="MAC addresses must be unique "
                                 "in the deployment model."),
                 ValidationError('/node2/y/z',
                                 error_message="MAC addresses must be unique "
                                 "in the deployment model.")],
                self.plugin._validate_macs_unique(context))

        # Change the 2nd network-interface to a unique MAC
        iface2.macaddress="00:00:00:00:00:01"

        self.assertEquals([], self.plugin._validate_macs_unique(context))

    def test_validate_mgmt_network(self):
        node1_path = '/deployments/d1/cluster/c1/nodes/n1'

        # No networks and no network-interfaces on Node
        node1 = Mock(network_interfaces=[],
                    hostname='sc1',
                    get_vpath=lambda: node1_path)

        # -----

        # Create 1 network - 1 network must be designated as the management network
        mgmt_net = Mock(get_vpath=lambda: self.networks_path + 'net0')
        mgmt_net.name = 'mgmt'

        emsg = "The management network must be used for one network interface."

        self.assertEqual([ValidationError(node1_path, error_message=emsg)],
                         self.plugin._validate_mgmt_network_usage(node1,
                                                                  mgmt_net))

        # -----

        # 2 network-interfaces with bogus network names
        iface1 = Mock(network_name="net_name1",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/u/v/w')

        iface2 = Mock(network_name="net_name2",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/y/z')

        node1 = Mock(network_interfaces=[iface1, iface2],
                     hostname='sc1',
                     get_vpath=lambda: node1_path)

        self.assertEqual([ValidationError(node1_path, error_message=emsg)],
                         self.plugin._validate_mgmt_network_usage(node1,
                                                                  mgmt_net))

        # -----

        # 2 network-interfaces both assigned to the management network
        duplicated_net_name = mgmt_net.name
        iface1 = Mock(network_name=duplicated_net_name,
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/a/b/c')

        iface2 = Mock(network_name=duplicated_net_name,
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/d/e/f')

        node1 = Mock(network_interfaces=[iface1, iface2],
                     hostname='sc1',
                     get_vpath=lambda: node1_path)

        self.assertEqual([ValidationError('/a/b/c', error_message=emsg)],
                         self.plugin._validate_mgmt_network_usage(node1,
                                                                  mgmt_net))

    def test_validate_net_name_usage_duplicate_use(self):
        '''
        Validate the use of Network names
        '''

        node1_path = '/deployments/d1/cluster/c1/nodes/n1'

        # 3 network-interfaces, 1st without a network name,
        # 2nd & 3rd share a network name
        iface1 = Mock(network_name="",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/a/b/c')
        iface2 = Mock(network_name="duplicate",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/d/e/f')
        iface3 = Mock(network_name="duplicate",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/g/h/i')

        node1 = Mock(network_interfaces=[iface1, iface2, iface3],
                     hostname='sc1',
                     get_vpath=lambda: node1_path)

        net1 = Mock(); net1.name = 'duplicate'
        net2 = Mock(); net2.name = 'foo'
        networks = [net1, net2]

        emsg = 'Network name "duplicate" must be used by one network-interface.'
        expected = ValidationError('/d/e/f', error_message=emsg)
        errors = self.plugin._validate_network_name_usage(node1, networks)
        print expected,errors
        self.assertTrue(expected in errors)

    def test_validate_net_name_usage_net_not_defined(self):
        '''
        Validate used network_name exists in defined networks
        '''

        node1_path = '/deployments/d1/cluster/c1/nodes/n1'

        # interface trying to use not defined network
        iface1 = Mock(network_name="foo",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/a/b/c')

        node1 = Mock(network_interfaces=[iface1],
                     hostname='sc1',
                     get_vpath=lambda: node1_path)

        net1 = Mock();
        net1.name = 'bar'
        net1.is_for_removal=lambda: False

        net2 = Mock();
        net2.name = 'baz'
        net2.is_for_removal=lambda: False

        net3 = Mock();
        net3.name = 'removed'
        net3.is_for_removal=lambda: True

        networks = [net1, net2, net3]

        emsg = 'Property network_name "foo" does not match a defined network.'
        expected = ValidationError('/a/b/c', error_message=emsg)
        errors = self.plugin._validate_network_name_usage(node1, networks)
        self.assertTrue(expected in errors)

        # Test that we skip interfaces that are for removal
        iface2 = Mock(
                network_name="nonesuch",
                is_for_removal=lambda: True,
                get_vpath=lambda: node1_path + '/network_interfaces/goner'
            )

        node1.network_interfaces = [iface2]
        errors = self.plugin._validate_network_name_usage(node1, networks)
        self.assertEquals([], errors)

        # Test use of for_removal network
        iface3 = Mock(
                network_name="removed",
                is_for_removal=lambda: False,
                get_vpath=lambda: node1_path + '/network_interfaces/foo'
            )

        node1.network_interfaces = [iface3]
        emsg = 'Property network_name "removed" does not match a defined network.'
        expected = ValidationError(iface3.get_vpath(), error_message=emsg)
        errors = self.plugin._validate_network_name_usage(node1, networks)
        self.assertTrue(expected in errors)


    def test_validate_unique_net_names(self):
        '''
        Validate that Networks have unique names
        '''

        self._create_standard_items()

        # 3 uniquely named networks
        for net_name in ["foo", "bar", "baz"]:
            item = self.model_manager.create_item('network',
                                           self.networks_path + net_name,
                                           name=net_name)
            self.assertTrue(isinstance(item, ModelItem))

        self.assertEqual([],
                     self.plugin._validate_network_names_unique(self.context))

        # -----------------

        # 4th network with a duplicate name
        net = self.model_manager.create_item('network',
                                             self.networks_path + 'pzazz',
                                             name='baz')
        self.assertTrue(isinstance(net, ModelItem))

        self.assertTrue(ValidationError(self.networks_path + 'pzazz',
                        error_message='Network name "baz" is not unique.') in
                    self.plugin._validate_network_names_unique(self.context))

    def test_validate_only_one_mgmt_network(self):
        '''
        Validate number of management networks
        '''

        self._create_standard_items()

        emsg = 'There must be exactly one network assigned ' \
               'litp_management="true"'

        # 3 non-management networks
        for net_name in ["foo", "bar", "baz"]:
            item = self.model_manager.create_item('network',
                                                  self.networks_path + net_name,
                                                  name=net_name,
                                                  litp_management="false")
            self.assertTrue(isinstance(item, ModelItem))

        self.assertEqual([ValidationError(self.networks_path[:-1],
                                          error_message=emsg)],
                    self.plugin._validate_only_one_mgmt_network(self.context))

        # ----

        new_nets = []
        # 3 management networks
        for net_name in ["doe", "ray", "me"]:
            net = self.model_manager.create_item('network',
                                           self.networks_path + net_name,
                                           name=net_name,
                                           litp_management="true")
            self.assertTrue(isinstance(net, ModelItem))
            new_nets.append(net)

        # 1 of these are expected - could be any 1
        err1 = ValidationError(self.networks_path + 'doe', error_message=emsg)
        err2 = ValidationError(self.networks_path + 'ray', error_message=emsg)
        err3 = ValidationError(self.networks_path + 'me', error_message=emsg)

        errors = self.plugin._validate_only_one_mgmt_network(self.context)

        self.assertTrue((err1 in errors) or
                        (err2 in errors) or
                        (err3 in errors))

    def test_validate_ips_valid_for_network(self):
        '''
        Validate Node IPs belong to networks
        '''

        # 3 Networks, 1st without a network name.
        net1 = Mock(is_for_removal=lambda: False,
                    get_vpath=lambda: '/a/b/c',
                    subnet="10.0.0.0/24")
        net1.name = ''

        net2 = Mock(is_for_removal=lambda: False,
                    get_vpath=lambda: '/d/e/f',
                    subnet="20.0.0.0/24")
        net2.name = 'alpha'

        net3 = Mock(is_for_removal=lambda: False,
                    get_vpath=lambda: '/g/h/i',
                    subnet="30.0.0.0/24")
        net3.name = 'beta'

        # No subnet
        net4 = Mock(is_for_removal=lambda: False,
                    get_vpath=lambda: '/j/k/l',
                    subnet=None)
        net4.name = 'gamma'

        nets = [net1, net2, net3, net4]

        node1_path = '/deployments/d1/cluster/c1/nodes/n1'

        # -----

        # These network-interfaces have invalid IPs and network names
        iface1 = Mock(network_name="",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/u/v/w',
                      ipaddress="1.2.3.4")
        iface2 = Mock(network_name="bogus",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/y/z',
                      ipaddress="5.6.7.8")

        node1 = Mock(network_interfaces=[iface1, iface2],
                     hostname='sc1',
                     get_vpath=lambda: node1_path)

        # Test is deliberately nobbled as invalid network names is now
        # not the responsibility of this test. See LITPCDS-5925.
        self.assertEqual(
            [],
            self.plugin._validate_ips_valid_for_network(node1,nets)
            )
        # -----

        # This network-interface has an invalid IP with a valid network-name
        iface1 = Mock(network_name="alpha",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/y/z',
                      ipaddress="bogus")

        node1 = Mock(network_interfaces=[iface1],
                     hostname='sc1',
                     get_vpath=lambda: node1_path)

        emsg = "Invalid IP address."
        self.assertEqual([ValidationError('/x/y/z',
                                          error_message=emsg)],
                         self.plugin._validate_ips_valid_for_network(node1,
                                                                     nets))
        # -----

        # This network-interface has a valid network-name
        # but an IP not matching the network subnet
        iface1 = Mock(network_name="alpha",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/y/z',
                      ipaddress="4.5.6.7")

        node1 = Mock(network_interfaces=[iface1],
                     hostname='sc1',
                     get_vpath=lambda: node1_path)

        emsg = 'IP address "4.5.6.7" not within subnet ' + \
               '"20.0.0.0/24" of network "alpha".'
        self.assertEqual([ValidationError('/x/y/z',
                                          error_message=emsg)],
                         self.plugin._validate_ips_valid_for_network(node1,
                                                                     nets))
        # -----
        iface1 = Mock(network_name="gamma",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/y/z',
                      ipaddress="4.5.6.7")

        node1 = Mock(network_interfaces=[iface1],
                     hostname='sc1',
                     get_vpath=lambda: node1_path)

        self.assertEqual([],
                         self.plugin._validate_ips_valid_for_network(node1,
                                                                     nets))

    def test_assigning_network_address_to_if_is_disallowed(self):

        def node_query(*args, **kwargs):
            return []

        mock_if = Mock(
                get_vpath=lambda: '/node/if0',
                is_initial=lambda: True,
                is_updated=lambda: False,
                is_applied=lambda: False,
                is_for_removal=lambda: False,
                network_name='mock_net',
                ipaddress='11.11.11.0',
                item_type_id='eth',
                macaddress='00:11:22:33:44:55',
                device_name='eth0',
            )

        mock_net = Mock(
                subnet='11.11.11.0/24',
                is_for_removal=lambda: False,
                get_vpath=lambda: '/inf/networking/net0',
            )
        mock_net.name = 'mock_net'

        mock_node = Mock(
                hostname='mock_node',
                is_for_removal=lambda: False,
                get_vpath=lambda: '/node',
                query=Mock(side_effect=node_query),
                network_interfaces=[mock_if]
            )

        def _mock_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node]
            elif 'ms' == query_item_type:
                return []
            elif 'network' == query_item_type:
                return [mock_net]

        validation_errors = self.plugin._validate_ips_valid_for_network(
                mock_node,
                [mock_net]
            )

        self.assertEquals(1, len(validation_errors))

        expected_validation_error = ValidationError(
                item_path='/node/if0',
                error_message='Cannot assign IPv4 address "11.11.11.0" to this '
                    'interface as it is the network address for its network '
                    '"mock_net".'
            )
        self.assertEquals([expected_validation_error], validation_errors)

    def test_assigning_broadcast_address_to_if_is_disallowed(self):

        def node_query(*args, **kwargs):
            return []

        mock_if = Mock(
                get_vpath=lambda: '/node/if0',
                is_initial=lambda: True,
                is_updated=lambda: False,
                is_applied=lambda: False,
                is_for_removal=lambda: False,
                network_name='mock_net',
                ipaddress='10.10.1.127',
                item_type_id='eth',
                macaddress='00:11:22:33:44:55',
                device_name='eth0')

        mock_net = Mock(
                subnet='10.10.1.64/26',
                is_for_removal=lambda: False,
                get_vpath=lambda: '/inf/networking/net0')
        mock_net.name = 'mock_net'

        mock_node = Mock(
                hostname='mock_node',
                is_for_removal=lambda: False,
                get_vpath=lambda: '/node',
                query=Mock(side_effect=node_query),
                network_interfaces=[mock_if])

        def _mock_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node]
            elif 'ms' == query_item_type:
                return []
            elif 'network' == query_item_type:
                return [mock_net]

        validation_errors = self.plugin._validate_ips_valid_for_network(
                                                mock_node,
                                                [mock_net])

        self.assertEquals(1, len(validation_errors))

        expected_validation_error = ValidationError(
                item_path='/node/if0',
                error_message='Cannot assign IPv4 address "10.10.1.127" to this '
                    'interface as it is the broadcast address for its network '
                    '"mock_net".'
            )
        self.assertEquals([expected_validation_error], validation_errors)

    def test_validate_routes_not_removed(self):
        '''
        Validate routes not removed
        '''
        route1 = Mock(is_for_removal=lambda: True,
                      subnet="10.0.0.0/24",
                      get_vpath=lambda: '/a/b/c')

        route2 = Mock(is_for_removal=lambda: False,
                      subnet="20.0.0.0/24",
                      get_vpath=lambda: '/d/e/f')

        def _mock_get_vpath():
            return '/x/y/z'

        def _mock_iterator(self):
            for route in [route1, route2]:
                yield route

        # In the "routes" Collection we must replace
        # - the get_vpath()
        # - the iterator implementation
        mock_routes = Mock()
        mock_routes.get_vpath = _mock_get_vpath
        mock_routes.__iter__ = _mock_iterator

        mock_node = Mock(routes=mock_routes)

        errors = self.plugin._validate_route_not_removed(mock_node)

        emsg = "Route item cannot be removed. Removal is not supported."
        self.assertEqual([ValidationError('/a/b/c', error_message=emsg)],
                         errors)


    def test_validate_subnets_unique(self):
        '''
        Validate unique subnets for Routes
        '''

        duplicate_subnet = "10.0.0.0/24"

        route1 = Mock(is_for_removal=lambda: False,
                      subnet=duplicate_subnet,
                      item_type_id='route',
                      get_vpath=lambda: '/a/b/c')

        route2 = Mock(is_for_removal=lambda: False,
                      subnet=duplicate_subnet,
                      item_type_id='route',
                      get_vpath=lambda: '/d/e/f')

        def _mock_get_vpath():
            return '/x/y/z'

        def _mock_iterator(self):
            for route in [route1, route2]:
                yield route

        # One the "routes" Collection we must replace
        # - the get_vpath()
        # - the iterator implementation
        mock_routes = Mock()
        mock_routes.get_vpath = _mock_get_vpath
        mock_routes.__iter__ = _mock_iterator

        mock_node = Mock(routes=mock_routes)

        errors = self.plugin._validate_subnets_unique(mock_node)

        emsg = 'Destination subnet "' + duplicate_subnet + '" is duplicated ' + \
               'across several routes: /a/b/c /d/e/f'
        self.assertEqual([ValidationError('/x/y/z', error_message=emsg)],
                         errors)

    def test_validate_eth_bridge_valid_device_name(self):
        '''
        Validate that a "eth" item references a valid Bridge
        '''

        # Bridge 'br0' is non-existent
        eth = Mock(bridge="br0",
                   get_vpath=lambda: '/a/b/c',
                   is_for_removal=lambda: False)

        bridge = Mock(device_name='br0',
                      is_for_removal=lambda: False)

        node = Mock(hostname="sc-1")

        # No Bridge items will be found
        def _mock_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [eth]
            elif 'bridge' == query_item_type:
                return [bridge]
            else:
                return []

        node.query = _mock_query

        emsg = 'Property bridge "br0" does not correspond to a valid bridge.'

        # Scenario 1: the eth item is applied and references a bridge that
        # exists and is not for removal
        self.assertEquals([],
            self.plugin._validate_bridged_interface_bridge_valid_device_name(node))

        # Scenario 2: the eth item is applied and references a bridge that
        # exists but is marked for removal
        bridge.is_for_removal = lambda: True
        emsg = 'Property bridge "br0" is not a ' + \
               'valid bridge as it has state \'ForRemoval\''
        errors = self.plugin.\
            _validate_bridged_interface_bridge_valid_device_name(node)
        self.assertEqual([ValidationError("/a/b/c", error_message=emsg)],
                         errors)

        # Scenario 3: the eth item is applied and references a bridge that
        # doesn't exist
        def _mock_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [eth]
            else:
                return []
        node.query = _mock_query
        emsg = 'Property bridge "br0" does not correspond to a valid bridge.'
        errors = self.plugin.\
                 _validate_bridged_interface_bridge_valid_device_name(node)
        self.assertEqual([ValidationError("/a/b/c", error_message=emsg)],
                         errors)

        # Scenario 4: the eth item is for removal and the bridge doesn't exist
        eth.is_for_removal = lambda: True
        self.assertEquals([],
            self.plugin._validate_bridged_interface_bridge_valid_device_name(node))

    def test_validate_bond_bridge_valid_device_name(self):
        '''
        Validate that a "bond" item references a valid Bridge
        '''

        # Bridge 'br0' is non-existent
        bond = Mock(bridge="br0",
                    get_vpath=lambda: '/a/b/bond0',
                    is_for_removal=lambda: False)

        bridge = Mock(device_name='br0',
                      is_for_removal=lambda: False)

        node = Mock(hostname="sc-1")

        # No Bridge items will be found
        def _mock_query(query_item_type, **kwargs):
            if 'bond' == query_item_type:
                return [bond]
            elif 'bridge' == query_item_type:
                return [bridge]
            else:
                return []

        node.query = _mock_query

        emsg = 'Property bridge "br0" does not correspond to a valid bridge.'

        # Scenario 1: the bond item is applied and references a bridge that
        # exists and is not for removal
        self.assertEquals([],
            self.plugin._validate_bridged_interface_bridge_valid_device_name(node))

        # Scenario 2: the bond item is applied and references a bridge that
        # exists but is marked for removal
        bridge.get_vpath=lambda: '/a/b/br0'
        bridge.is_for_removal = lambda: True
        emsg = 'Property bridge "br0" is not a ' + \
               'valid bridge as it has state \'ForRemoval\''
        errors = self.plugin.\
            _validate_bridged_interface_bridge_valid_device_name(node)
        self.assertEqual([ValidationError("/a/b/bond0", error_message=emsg)],
                         errors)

        # Scenario 3: the bond item is applied and references a bridge that
        # doesn't exist
        def _mock_query(query_item_type, **kwargs):
            if 'bond' == query_item_type:
                return [bond]
            else:
                return []
        node.query = _mock_query
        emsg = 'Property bridge "br0" does not correspond to a valid bridge.'
        errors = self.plugin.\
            _validate_bridged_interface_bridge_valid_device_name(node)
        self.assertEqual([ValidationError("/a/b/bond0", error_message=emsg)],
                         errors)

        # Scenario 4: the bond item is for removal and the bridge doesn't exist
        bond.is_for_removal = lambda: True
        self.assertEquals([], self.plugin.\
                _validate_bridged_interface_bridge_valid_device_name(node))

    def test_validate_vlan_bridge_valid_device_name(self):
        '''
        Validate that a "vlan" item references a valid Bridge
        '''

        # Bridge 'br0' is non-existent
        vlan = Mock(bridge="br0",
                    get_vpath=lambda: '/a/b/vlan',
                    is_for_removal=lambda: False)

        bridge = Mock(device_name='br0',
                      is_for_removal=lambda: False)

        node = Mock(hostname="sc-1")

        # No Bridge items will be found
        def _mock_query(query_item_type, **kwargs):
            if 'vlan' == query_item_type:
                return [vlan]
            elif 'bridge' == query_item_type:
                return [bridge]
            else:
                return []

        node.query = _mock_query

        emsg = 'Property bridge "br0" does not correspond to a valid bridge.'

        # Scenario 1: the vlan item is applied and references a bridge that
        # exists and is not for removal
        self.assertEquals([],
            self.plugin._validate_bridged_interface_bridge_valid_device_name(node))

        # Scenario 2: the vlan item is applied and references a bridge that
        # exists but is marked for removal
        bridge.is_for_removal = lambda: True
        emsg = 'Property bridge "br0" is not a ' + \
               'valid bridge as it has state \'ForRemoval\''
        errors = self.plugin.\
            _validate_bridged_interface_bridge_valid_device_name(node)
        self.assertEqual([ValidationError("/a/b/vlan", error_message=emsg)],
                         errors)

        # Scenario 3: the vlan item is applied and references a bridge that
        # doesn't exist
        def _mock_query(query_item_type, **kwargs):
            if 'vlan' == query_item_type:
                return [vlan]
            else:
                return []
        node.query = _mock_query
        emsg = 'Property bridge "br0" does not correspond to a valid bridge.'
        errors = self.plugin.\
            _validate_bridged_interface_bridge_valid_device_name(node)
        self.assertEqual([ValidationError("/a/b/vlan", error_message=emsg)],
                         errors)

        # Scenario 4: the vlan item is for removal and the bridge doesn't exist
        vlan.is_for_removal = lambda: True
        self.assertEquals([], self.plugin.\
                _validate_bridged_interface_bridge_valid_device_name(node))

    def test_for_removal_states(self):
        '''
        In various places the Plugin discounts items that are
        removed or for-removal; covering those branches here.
        '''

        mock_node = Mock(is_for_removal=lambda: True)

        context = Mock(query=lambda q: [mock_node])

        tasks = self.plugin._new_routes_tasks(context)
        self.assertEqual([], tasks)

        # ----

        mock_networking = Mock(query=lambda q: [])

        def _mock_query(query_item_type, **kwargs):
            if 'node' == query_item_type:
                return [mock_node]
            elif 'networking' == query_item_type:
                return [mock_networking]
            else:
                return []

        context = Mock()
        context.query = _mock_query

        errors = self.plugin.validate_model(context)
        self.assertEqual([], errors)

        # ----

        network = Mock(is_for_removal=lambda: True)
        context = Mock(query=lambda q: [network])

        errors = self.plugin._validate_network_names_unique(context)
        self.assertEqual([], errors)

        # ----

        iface = Mock(is_for_removal=lambda: True)
        node = Mock(network_interfaces=[iface],
                    hostname="sc-1")

        errors = self.plugin._validate_device_names_unique(node)
        self.assertEqual([], errors)

        # ----

        errors = self.plugin._validate_interface_l3_config(node, [])
        self.assertEqual([], errors)

        # ----

        errors = self.plugin._validate_ips_valid_for_network(node, [])
        self.assertEqual([], errors)

        # ----

        route = Mock(is_for_removal=lambda: True)
        node = Mock(routes=[route],
                    network_interfaces=[])
        errors = self.plugin._validate_subnets_unique(node)
        self.assertEqual([], errors)

        # ----

        errors = self.plugin._validate_gateways_local(node, [])
        self.assertEqual([], errors)

    def test_missing_attributes(self):
        '''
        In various places the Plugin discounts items that
        do not have a network_name or ipaddress etc -
        covering those scenarios here.
        '''

        iface = Mock(network_name=None,
                     ipaddress=None)
        node = Mock(network_interfaces=[iface])
        device = self.plugin._device_name_for_IPv4_route(None, node, None)
        self.assertEqual(None, device)

        # ----

        iface = Mock(network_name=None)
        node = Mock(network_interfaces=[iface],
                    hostname="sc-1")

        errors = self.plugin._validate_network_name_usage(node, [])
        self.assertEqual([], errors)

        # ----
        net = Mock(name="found", subnet="0.0.0.0/0")
        subnet = self.plugin._get_subnet_for_net_name('not-found', [net])
        self.assertEqual(None, subnet)

    def test_validate_only_supported_types_present(self):
        netif = Mock(item_type_id='network-interface',
                     item_id='if1',
                     get_vpath=lambda: '/node/network_interfaces/if1')

        node = Mock(hostname='mock_node',
                    is_for_removal=lambda: False,
                    get_vpath=lambda: '/node',
                    network_interfaces=[netif])

        msg = ('The interface type "%s" is not allowed. Allowed '
               'interface types are %s' % (netif.item_type_id,
                        " or ".join(NetworkPlugin.ALLOWED_INTERFACES)))

        expected = [ValidationError("/node/network_interfaces/if1",
                                    error_message=msg)]

        errors = self.plugin._validate_only_supported_types_present(node)

        self.assertEquals(expected, errors)

    def test_interface_tied_to_IP_network_needs_IP_address(self):
        mock_ipnet = Mock(subnet='10.1.2.0/26', litp_management='false')
        mock_ipnet.name = 'ip_net'

        mock_hb_net = Mock(litp_management='false', subnet='')
        mock_hb_net.name = 'hb_net'

        mock_if_no_ip = Mock(device_name='eth1', macaddress='11:12:13:14:15:16',
                network_name='ip_net', get_vpath=lambda: "/node/ifs/if1",
                ipaddress='', is_for_removal=lambda: False)
        mock_if_no_ip.ipv6address=''

        mock_if_ip = Mock(device_name='eth1', macaddress='11:12:13:14:15:16',
                network_name='hb_net', ipaddress='10.1.2.3', get_vpath=lambda:
                "/node/ifs/if1", is_for_removal=lambda: False)

        mock_if_ipv6 = Mock(device_name='eth1', macaddress='11:12:13:14:15:16',
                network_name='hb_net', ipv6address='fe80::fc54:ff:fe5b:90f/64',
                get_vpath=lambda: "/node/ifs/if1",
                is_for_removal=lambda: False)
        mock_if_ipv6.ipaddress=''

        mock_node = Mock(network_interfaces=[mock_if_no_ip])
        expected_error = ValidationError(item_path='/node/ifs/if1',
                error_message='This interface does not define an IPv4 address. It is tied to a network (ip_net) with a subnet defined.')
        actual_errors = self.plugin._validate_interface_l3_config(mock_node, [mock_ipnet])
        self.assertEquals([expected_error], actual_errors)

        # ----

        mock_node = Mock(network_interfaces=[mock_if_ip])
        expected_error = ValidationError(item_path='/node/ifs/if1',
                error_message='This interface defines an IPv4 address. It is not tied to a network (hb_net) with a valid subnet defined.')
        actual_errors = self.plugin._validate_interface_l3_config(mock_node, [mock_hb_net])
        self.assertEquals([expected_error], actual_errors)

        # ----
        mock_node = Mock(network_interfaces=[mock_if_ipv6])
        expected_error = ValidationError(item_path='/node/ifs/if1',
                error_message='This interface is tied to a non-IPv4 network "hb_net". It must not have an IPv4 address.')
        actual_errors = self.plugin._validate_interface_l3_config(mock_node, [mock_hb_net])
        self.assertEquals([], actual_errors)

        # ----

        mock_if_no_net = Mock(device_name='eth1', macaddress='11:12:13:14:15:16',
                get_vpath=lambda: "/node/ifs/if1", network_name='',
                is_for_removal=lambda: False)

        mock_node = Mock(network_interfaces=[mock_if_no_net])
        actual_errors = self.plugin._validate_interface_l3_config(mock_node, [mock_hb_net])
        self.assertEquals([], actual_errors)

        # ----

        mock_if_no_net = Mock(device_name='eth1', macaddress='11:12:13:14:15:16',
                get_vpath=lambda: "/node/ifs/if1", network_name='bogus',
                is_for_removal=lambda: False)

        mock_node = Mock(network_interfaces=[mock_if_no_net])
        actual_errors = self.plugin._validate_interface_l3_config(mock_node, [mock_hb_net])
        self.assertEquals([], actual_errors)

    def test_bridge_on_management_network_needs_IP_address(self):
        mock_net_mgmt = Mock(subnet='10.1.2.0/26', litp_management='true')
        mock_net_mgmt.name = 'mgmt'

        mock_if_no_ip = Mock(device_name='br0',
                network_name='mgmt', get_vpath=lambda: "/node/ifs/br0",
                item_type_id = 'bridge',
                ipaddress='', is_for_removal=lambda: False)

        mock_if_no_ip.ipv6address=''

        mock_node = Mock(network_interfaces=[mock_if_no_ip])
        expected_error = ValidationError(item_path='/node/ifs/br0',
                error_message='This interface is tied to management network'\
                              ' (mgmt) and it requires an IPv4 address.')
        actual_errors = self.plugin._validate_interface_l3_config(mock_node, [mock_net_mgmt])
        self.assertEquals([expected_error], actual_errors)

    def test_validate_bridge_is_used(self):
        self._create_standard_items()
        node1 = self._create_node('n1', 'sc1')

        default_route = self._ip_route_create_default_route('def', 'def')

        for path in [node1.get_vpath(), '/ms']:
            l = self.model_manager.create_inherited(default_route.get_vpath(),
                                                    path + '/routes/r0')
            self.assertTrue(isinstance(l, ModelItem))

        a = self.model_manager.create_item(
            'network',
            self.networks_path + 'n0',
            name="mgmt",
            subnet="10.0.0.0/24",
            litp_management='true')

        b = self.model_manager.create_item(
            'eth',
            node1.get_vpath() + '/network_interfaces/n0',
            ipaddress='10.0.0.5',
            network_name='mgmt',
            macaddress="00:00:00:00:00:00",
            device_name="eth0")

        d = self.model_manager.create_item(
            'bridge',
            '/ms/network_interfaces/b0',
            ipaddress='10.0.0.7',
            network_name='mgmt',
            device_name="br0")

        for item in [a, b, d]:
            self.assertTrue(isinstance(item, ModelItem))

        errors = self.plugin.validate_model(self.context)
        self.assertEqual(
        [ValidationError(
            '/ms/network_interfaces/b0',
            error_message='Bridge "br0" is not used.'
            )],
        errors)

    def test_validate_vlan_count(self):

        new_max = 3
        self.plugin.MAX_VLANS_PER_NODE = new_max
        vlans = []

        host = "sc1"

        for vlan_id in range(1, new_max + 2):
            vlan = Mock(is_for_removal=lambda: False)
            vlans.append(vlan)

        net_ifaces = Mock(get_vpath=lambda: '/a/b/c')

        node = Mock(hostname=host,
                    query=lambda q: vlans,
                    network_interfaces=net_ifaces)

        msg = 'Too many VLANs on node "%s". %d allowed, %d found' % \
              (host, new_max, new_max + 1)

        errors = self.plugin._validate_vlan_count(node)

        self.assertEquals([ValidationError('/a/b/c', error_message=msg)],
                          errors)

    def test_validate_format_vlan_device_names(self):

        eth = Mock(device_name="eth0",
                   is_for_removal=lambda: False)

        vlan = Mock(is_for_removal=lambda: False,
                    is_initial=lambda: True,
                    device_name=eth.device_name + '.2016',
                    get_vpath=lambda: '/x/y/z')

        def _mock_query(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [eth]
            elif 'vlan' == query_item_type:
                return [vlan]
            else:
                return []

        node = Mock(hostname="sc1",
                    query=_mock_query)

        errors = self.plugin._validate_format_vlan_device_names(node)
        self.assertEquals([], errors)

        # -----

        vlan.device_name = 'badly-formatted'

        errors = self.plugin._validate_format_vlan_device_names(node)
        self.assertEquals([], errors)   # Item validation shall deal with this

        # -----

        vlan.device_name = 'bogus.234'

        errors = self.plugin._validate_format_vlan_device_names(node)
        msg = 'Invalid VLAN device_name: unknown network interface item "bogus"'
        self.assertEquals([ValidationError('/x/y/z',
                           error_message=msg)], errors)

        # -----
        vlan.device_name = 'eth0.234'
        eth.is_for_removal=lambda: True

        errors = self.plugin._validate_format_vlan_device_names(node)
        msg = 'Invalid VLAN device_name: network interface item "eth0"' + \
              ' has state \'ForRemoval\''
        self.assertEquals([ValidationError('/x/y/z',
                           error_message=msg)], errors)

# IPv6

    def test_validate_v6_ips_unique_in_node(self):
        '''
        IPv6 addresses must be unique - with Node scope.
        '''

        # 2 network-interfaces with the same IP
        duplicated_ip = "2001::2:3:4"
        iface1 = Mock(ipv6address=duplicated_ip,
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/a/b/c')
        iface2 = Mock(ipv6address=duplicated_ip,
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/y/z')

        node = Mock(network_interfaces=[iface1, iface2],
                    hostname='sc1')
        self.assertEquals(
                [ValidationError('/a/b/c',
                                 error_message="IPv6 addresses must be unique per node."),
                 ValidationError('/x/y/z',
                                 error_message="IPv6 addresses must be unique per node.")],
                self.plugin._validate_ips_unique_in_node(node))

        # Change the 2nd network-interface to a unique IP
        iface2 = Mock(ipv6address="2001::2:3:5",
                      is_for_removal=lambda: False,
                      get_vpath=lambda: '/x/y/z')
        node = Mock(network_interfaces=[iface1, iface2],
                    hostname='sc1')
        self.assertEquals([], self.plugin._validate_ips_unique_in_node(node))

    def test_validate_v6_ms_ip_not_updated(self):
        mgmt_net = Mock()
        mgmt_net.name = 'foo'
        mgmt_net.litp_management = 'true'

        mockms = Mock()

        # IP address is changed to a different address,
        # expect a Validation Error
        mockms.network_interfaces = [Mock(is_updated=lambda: True,
                                          ipaddress=None,
                                          ipv6address='2001::3',
                                          network_name='foo',
                                          applied_properties={'ipv6address': '2001::4'},
                                          get_vpath=lambda: "/ms/network_interfaces/nic")]

        errors = self.plugin._validate_ms_mgmt_ip_not_removed(mockms, mgmt_net)
        self.assertEqual([], errors)

        # IP address is *not* updated, expect no errors
        mockms = Mock()
        mockms.network_interfaces = [Mock(is_updated=lambda: False,
                                          ipv6address='2001::3',
                                          network_name='foo',
                                          applied_properties={'ipv6address': '2001::3'},
                                          get_vpath=lambda: "/ms/network_interfaces/nic")]

        errors_expected = []
        errors = self.plugin._validate_ms_mgmt_ip_not_removed(mockms, mgmt_net)
        self.assertEqual(errors_expected, errors)

        # IP address is updated to the same address, expect no errors
        mockms.network_interfaces = [Mock(is_updated=lambda: True,
                                          ipaddress=None,
                                          ipv6address='2001::3',
                                          network_name='foo',
                                          applied_properties={'ipv6address': '2001::3'},
                                          get_vpath=lambda: "/ms/network_interfaces/nic")]
        errors_expected = []
        errors = self.plugin._validate_ms_mgmt_ip_not_removed(mockms, mgmt_net)
        self.assertEqual(errors_expected, errors)

        # -----

        # No 'new' IP, just an old one.
        # User is attempting to delete the MS IP.
        iface = Mock(is_updated=lambda: True,
                     ipaddress=None,
                     ipv6address=None,
                     network_name='foo',
                     applied_properties={'ipv6address': '2001::4'},
                     get_vpath=lambda: '/x/y/z')

        node = Mock(network_interfaces=[iface])

        errors = self.plugin._validate_ms_mgmt_ip_not_removed(node, mgmt_net)
        self.assertEqual([], errors)

    def test_validate_v6_ms_ip_not_updated_not_mgm_net(self):
        mgmt_net = Mock(subnet='2002::2')
        mgmt_net.name = 'foo'
        mgmt_net.litp_management = 'true'

        # IP address is changed to a different address,
        # expect a Validation Error
        mockms = Mock()
        mockms.network_interfaces = [Mock(is_updated=lambda: True,
                                          ipv6address='2001::3',
                                          network_name='bar',  # Using non mgmt network
                                          applied_properties={'ipv6address': '2001::4'},
                                          get_vpath=lambda: "/ms/network_interfaces/nic")]

        errors = self.plugin._validate_ms_mgmt_ip_not_removed(mockms, mgmt_net)
        self.assertEqual([], errors)

    def test_validate_v6_ms_mgmt_is_dual_stack(self):
        mgmt_net = Mock(subnet='2002::2')
        mgmt_net.name = 'foo'
        mgmt_net.litp_management = 'true'

        mockms = Mock()
        mockms.hostname = 'fakehost'
        mockms.network_interfaces = [Mock(
                is_for_removal=lambda: False,
                ipaddress=None,
                ipv6address='2001::3',
                network_name='foo',  # Using non mgmt network
                applied_properties={'ipv6address': '2001::4'},
                get_vpath=lambda: "/ms/network_interfaces/nic")
                ]

        # IPv6 only - should fail..
        errors = self.plugin._validate_ipv6_mgmt_is_dual_stack(mockms, mgmt_net)
        self.assertEqual(
            [ValidationError(
                item_path="/ms/network_interfaces/nic",
                error_message="The management network cannot be IPv6 only.")],
            errors
            )

        # Make node dual-stack and recheck..
        mockms.network_interfaces[0].ipaddress = '1.2.3.4'
        errors = self.plugin._validate_ipv6_mgmt_is_dual_stack(mockms, mgmt_net)
        self.assertEqual([], errors)

    def test_validate_bond_is_used_by_eth(self):
        bond = Mock(
            device_name="bond0",
            is_for_removal=lambda: False,
            get_vpath=lambda: '/some/path'
            )

        eth = Mock(
            device_name="eth0",
            master='bond0',
            is_for_removal=lambda: False,
            get_vpath=lambda: '/some/path'
            )

        def _mock_query_negative(query_item_type, **kwargs):
            if 'bond' == query_item_type:
                return [bond]
            else:
                return []

        def _mock_query_positive(query_item_type, **kwargs):
            if 'bond' == query_item_type:
                return [bond]
            elif 'eth' == query_item_type:
                return [eth]
            else:
                return []

        nodefail = Mock(
            hostname="sc1",
            query=_mock_query_negative
            )

        nodepass = Mock(
            hostname="sc1",
            query=_mock_query_positive
            )

        errors = self.plugin._validate_bond_used_by_eth(nodefail)
        self.assertEquals(
            [ValidationError(
                item_path='/some/path',
                error_message='Bond "bond0" is not a master for any "eth" devices'
                )],
            errors
            )

        errors = self.plugin._validate_bond_used_by_eth(nodepass)
        self.assertEquals([], errors)

    def test_validate_eth_not_bonded_and_tagged(self):

        eth0 = Mock(master=None,
                    is_for_removal=lambda: False,
                    is_updated=lambda: False,
                    get_vpath=lambda: '/a/b',
                    device_name="eth0")

        eth1 = Mock(master=None,
                    is_for_removal=lambda: False,
                    is_updated=lambda: False,
                    get_vpath=lambda: '/a/c',
                    device_name="eth1")

        # eth2 & eth3 slaves of bond0
        eth2 = Mock(master="bond0",
                    is_for_removal=lambda: False,
                    is_updated=lambda: False,
                    get_vpath=lambda: '/a/d',
                    device_name="eth2")

        eth3 = Mock(master="bond0",
                    is_for_removal=lambda: False,
                    is_updated=lambda: False,
                    get_vpath=lambda: '/a/e',
                    device_name="eth3")

        # vlan i/f eth0 not bonded
        vlan1 = Mock(is_for_removal=lambda: False,
                     is_updated=lambda: False,
                     get_vpath=lambda: '/a/e',
                     device_name="eth0.1234")

        # vlan i/f eth1 not bonded
        vlan2 = Mock(is_for_removal=lambda: False,
                     is_updated=lambda: False,
                     get_vpath=lambda: '/a/f',
                     device_name="eth1.2345")

        def _mock_query(query_item_type, **kwargs):
            if 'vlan' == query_item_type:
                return [vlan1, vlan2]
            elif 'eth' == query_item_type:
                return [eth0, eth1, eth2, eth3]
            else:
                return []

        node = Mock(hostname="sc1",
                    network_interfaces=Mock(get_vpath=lambda: '/a'),
                    query=_mock_query)

        errors = self.plugin._validate_eth_not_bonded_and_tagged(node)
        self.assertEquals([], errors)

        # ----

        # i/f eth2 is now both Bonded & Vlan tagged.
        vlan2.device_name = "eth2.2345"

        errors = self.plugin._validate_eth_not_bonded_and_tagged(node)
        msg = 'The following network interfaces are Bonded and VLAN ' + \
              'tagged; this is not currently supported: eth2'
        expected = ValidationError(item_path='/a',
                                   error_message=msg)
        self.assertEquals([expected], errors)


    def test_validate_bond_and_all_slaves_removed(self):
        bond = Mock(device_name="bond0",
                    is_for_removal=lambda: False,
                    get_vpath=lambda: '/some/bond')

        eth0 = Mock(device_name="eth0",
                    master='bond0',
                    is_for_removal=lambda: False,
                    get_vpath=lambda: '/some/eth0')

        eth1 = Mock(device_name="eth1",
                    master='bond0',
                    is_for_removal=lambda: False,
                    get_vpath=lambda: '/some/eth1')

        def _mock_query(query_item_type, **kwargs):
            if 'bond' == query_item_type:
                return [bond]
            elif 'eth' == query_item_type:
                return [eth0, eth1]
            else:
                return []

        node = Mock(hostname="sc1",
                    query=_mock_query)

        # Nothing has been removed
        errors = self.plugin._validate_bond_and_all_slaves_removed(node)
        self.assertEquals([], errors)

        # -----
        err1 = ValidationError(item_path='/some/eth0',
                               error_message='All eth peers of "eth0" and ' +
                                             'slaves of Bond "bond0" ' +
                                             'must be removed in the same plan.')
        err2 = ValidationError(item_path='/some/eth0',
                               error_message='Bond "bond0" does not have state \'ForRemoval\' ' +
                                            'while slave eths do. A Bond and all slave eths ' +
                                            'must be removed in the same plan.')
        err3 = ValidationError(item_path='/some/eth1',
                               error_message='Bond "bond0" does not have state \'ForRemoval\' ' +
                                            'while slave eths do. A Bond and all slave eths ' +
                                            'must be removed in the same plan.')

        # -----

        # Now just 1 eth being removed
        eth0.is_for_removal = lambda: True
        errors = self.plugin._validate_bond_and_all_slaves_removed(node)
        expected = [err1, err2]
        self.assertEquals(expected, errors)

        # -----

        # Now the 2 eths are being removed
        eth1.is_for_removal = lambda: True
        errors = self.plugin._validate_bond_and_all_slaves_removed(node)
        expected = [err2, err3]
        self.assertEquals(expected, errors)

        # -----

        # Now the 2 eths and bond are being removed
        bond.is_for_removal = lambda: True
        errors = self.plugin._validate_bond_and_all_slaves_removed(node)
        self.assertEquals([], errors)

    def test_validate_eth_master_is_bond(self):
        bond = Mock(
            device_name="bond0",
            is_for_removal=lambda: False,
            get_vpath=lambda: '/some/path'
            )

        eth = Mock(
            device_name="eth0",
            master='bond0',
            is_for_removal=lambda: False,
            is_initial=lambda: True,
            get_vpath=lambda: '/some/path'
            )

        def _mock_query_negative(query_item_type, **kwargs):
            if 'eth' == query_item_type:
                return [eth]
            else:
                return []

        def _mock_query_positive(query_item_type, **kwargs):
            if 'bond' == query_item_type:
                return [bond]
            elif 'eth' == query_item_type:
                return [eth]
            else:
                return []

        nodefail = Mock(
            hostname="sc1",
            query=_mock_query_negative
            )

        nodepass = Mock(
            hostname="sc1",
            query=_mock_query_positive
            )

        errors = self.plugin._validate_eth_master_is_bond(nodefail)
        self.assertEquals(
            [ValidationError(
                item_path='/some/path',
                error_message='eth "master" "bond0" is not a valid Bond "device_name"'
                )],
            errors
            )

        errors = self.plugin._validate_eth_master_is_bond(nodepass)
        self.assertEquals([], errors)

    def test_validate_vlan_on_nodes_not_mgmt(self):
        '''
        Validate that vlans are not assigned the
        management-network network-name.
        '''

        # Create a management network
        mgmt_net = Mock(litp_management='true')
        mgmt_net.name = 'mgmt'

        network_interfaces = [Mock(network_name='net1',
                                   is_for_removal=lambda: False)]

        node = Mock(query=lambda q: network_interfaces, hostname="mn1")

        errors = self.plugin._validate_vlan_on_nodes_not_mgmt(node, mgmt_net)
        self.assertEqual([], errors)


        # Attempt to create a vlan on mgmt network
        network_interfaces = [Mock(network_name='mgmt',
                                   is_for_removal=lambda:False,
                                   get_vpath=lambda: '/x/y/z',
                                   device_name='eth0.123')]

        node = Mock(query=lambda q: network_interfaces, hostname="mn1")

        errors = self.plugin._validate_vlan_on_nodes_not_mgmt(node, mgmt_net)

        emsg = 'Device "eth0.123" is not valid. VLAN tagging of the management ' + \
               'interface on a peer node is not supported'
        self.assertEqual([ValidationError('/x/y/z', error_message=emsg)],
                         errors)

    def test_validate_no_ip_swapping(self):
        v4_ip1 = '10.4.21.51'
        v4_ip2 = '10.4.21.52'
        v6_ip1 = '2001::3'
        v6_ip2 = '2001::4'

        nic1a = Mock(item_type_id='eth',
                     device_name='eth0',
                     ipaddress=v4_ip1,
                     ipv6address=v6_ip1,
                     network_name='data',
                     is_initial=lambda: False,
                     is_updated=lambda: False,
                     is_for_removal=lambda: False,
                     get_vpath=lambda: '/nic/nic1a',
                     applied_properties={})
        nics1 = [nic1a]
        node1 = Mock(hostname='mn1',
                     is_ms=lambda: False,
                     network_interfaces = nics1)

        nic2a = Mock(item_type_id='eth',
                     device_name='eth0',
                     ipaddress=v4_ip2,
                     ipv6address=v6_ip2,
                     network_name=nic1a.network_name,
                     is_initial=lambda: False,
                     is_updated=lambda: False,
                     is_for_removal = lambda: False,
                     get_vpath=lambda: '/nic/nic2a',
                     applied_properties={})
        nic2b = Mock(item_type_id='eth',
                     device_name='eth1',
                     ipaddress='10.4.22.52',
                     network_name='storage',
                     is_initial=lambda: False,
                     is_updated=lambda: False,
                     is_for_removal=lambda: False,
                     get_vpath=lambda: '/nic/nic2b',
                     applied_properties={})
        nic2b.applied_properties = {'ipaddress': nic2b.ipaddress}
        nics2 = [nic2a, nic2b]
        node2 = Mock(hostname='mn2',
                     is_ms = lambda: False,
                     network_interfaces = nics2)

        nic3a = Mock(item_type_id='eth',
                     device_name='eth0',
                     ipaddress='10.4.21.53',
                     network_name=nic2a.network_name,
                     is_initial=lambda: False,
                     is_updated=lambda: False,
                     is_for_removal = lambda: False,
                     get_vpath=lambda: '/nic/nic3a',
                     applied_properties={})
        nic3b = Mock(item_type_id='eth',
                     device_name='eth1',
                     ipaddress='10.4.22.53',
                     network_name=nic2b.network_name,
                     is_initial=lambda: False,
                     is_updated=lambda: False,
                     is_for_removal=lambda: False,
                     get_vpath=lambda: '/nic/nic3b',
                     applied_properties={})
        nics3 = [nic3a, nic3b]

        node3 = Mock(hostname='ms1',
                     is_ms = lambda: False,
                     network_interfaces = nics3)

        all_nodes = [node1, node2, node3]

        errors = self.plugin._validate_no_ip_swapping(all_nodes)
        self.assertEqual([], errors)

        # ----

        # Swap v4 IPs (on same network) and mark NICs as Updated
        nic1a.applied_properties = {'ipaddress': nic1a.ipaddress}
        nic2a.applied_properties = {'ipaddress': nic2a.ipaddress}
        nic1a.ipaddress = v4_ip2
        nic2a.ipaddress = v4_ip1
        nic1a.is_updated = lambda: True
        nic2a.is_updated = lambda: True

        template = 'Swapping IPv4 address on network "data" with Applied IPv4 address on node "%s" is not supported'
        expected1 = ValidationError(error_message = template % node2.hostname,
                                    item_path = nic1a.get_vpath())
        expected2 = ValidationError(error_message = template % node1.hostname,
                                    item_path = nic2a.get_vpath())

        errors = self.plugin._validate_no_ip_swapping(all_nodes)
        self.assertEqual([expected1, expected2], errors)

        # ----

        # Swapped v4 IPs, 1 NIC is initial, other is Updated
        nic1a.applied_properties = {}
        nic1a.is_initial = lambda: True
        nic1a.is_updated = lambda: False
        errors = self.plugin._validate_no_ip_swapping(all_nodes)
        self.assertEqual([expected1], errors)

        # ----

        # Swapped v4 IPs, appropriates states, but changed NIC is on a different network
        nic2a.network_name = 'something_unrelated'
        errors = self.plugin._validate_no_ip_swapping(all_nodes)
        self.assertEqual([], errors)

        nic1a.is_initial = lambda: False
        nic1a.is_updated = lambda: True
        nic1a.applied_properties = {'ipaddress': v4_ip1}

        # ----

        # Swapped v4 IPs, NICs updated, now 1 node is an MS, changed NIC is on a different network
        node1.is_ms = lambda: True
        errors = self.plugin._validate_no_ip_swapping(all_nodes)
        self.assertEqual([], errors)

        # ----
        # Swapped v4 IPs, NICs updated, 1 node is an MS, changed NICs on same network
        nic2a.network_name = 'data'
        errors = self.plugin._validate_no_ip_swapping(all_nodes)
        self.assertEqual([expected1, expected2], errors)

        # ----
        # Restore v4 IPs - leave state as Updated
        nic1a.ipaddress = v4_ip1
        nic2a.ipaddress = v4_ip2
        node1.is_ms = lambda: False
        # ----

        # Swap v6 IPs (on same network)
        nic1a.applied_properties = {'ipv6address': nic1a.ipv6address}
        nic2a.applied_properties = {'ipv6address': nic2a.ipv6address}
        nic1a.ipv6address = v6_ip2
        nic2a.ipv6address = v6_ip1

        template = 'Swapping IPv6 address on network "data" with Applied IPv6 address on node "%s" is not supported'
        expected1 = ValidationError(error_message = template % node2.hostname,
                                    item_path = nic1a.get_vpath())
        expected2 = ValidationError(error_message = template % node1.hostname,
                                    item_path = nic2a.get_vpath())

        errors = self.plugin._validate_no_ip_swapping(all_nodes)
        self.assertEqual([expected1, expected2], errors)

        # ----

        # Swapped v6 IPs, 1 NIC is Initial, other is Updated
        nic1a.applied_properties = {}
        nic1a.is_initial = lambda: True
        nic1a.is_updated = lambda: False
        errors = self.plugin._validate_no_ip_swapping(all_nodes)
        self.assertEqual([expected1], errors)

        # ----

        # Swapped v6 IPs, appropriates states, but changed NIC is on a different network
        nic2a.network_name = 'something_unrelated'
        errors = self.plugin._validate_no_ip_swapping(all_nodes)
        self.assertEqual([], errors)

        nic1a.is_initial = lambda: False
        nic1a.is_updated = lambda: True
        nic1a.applied_properties = {'ipv6address': v6_ip1}

        # ----

        # Swapped v6 IPs, NICs updated, now 1 node is an MS, changed NIC is on a different network
        node1.is_ms = lambda: True
        errors = self.plugin._validate_no_ip_swapping(all_nodes)
        self.assertEqual([], errors)

        # ----

        # Swapped v6 IPs, NICs updated, 1 node is an MS, changed NICs on same network
        nic2a.network_name = 'data'
        errors = self.plugin._validate_no_ip_swapping(all_nodes)
        self.assertEqual([expected1, expected2], errors)


    def test_pxe_boot_only_set_on_ms(self):

        self._create_standard_items()
        self._create_node('n1', 'node1')

        mgmt_network = self.model_manager.create_item(
            'network',
            self.networks_path + 'mgmt_network',
            subnet='10.0.0.0/24',
            name='mgmt',
            litp_management='true'
        )

        default_route = self.model_manager.create_item(
            'route',
            self.routes_path + 'defroute',
            subnet='0.0.0.0/0', gateway='10.0.0.1'
        )

        self.model_manager.create_inherited(
            default_route.get_vpath(),
            self.node1_path + '/routes/default')

        self.model_manager.create_inherited(
            default_route.get_vpath(),
            '/ms/routes/default'
        )

        ms_if0 = self.model_manager.create_item(
            "eth",
            '/ms/network_interfaces/if0',
            network_name="mgmt",
            device_name="eth0",
            ipaddress='10.0.0.2',
            macaddress='08:00:27:65:C2:1D'
        )

        node1_if0 = self.model_manager.create_item(
            "eth",
            self.node1_path + "/network_interfaces/if0",
            network_name="mgmt",
            device_name="eth0",
            ipaddress='10.0.0.3',
            macaddress='08:00:27:65:C2:1E'
        )

        # Positive Case: MS interface creates without any problems
        self.assertFalse(self.plugin.validate_model(self.context))

        err_msg = 'Property "pxe_boot_only" cannot be set on the "ms"'
        err_if0 = ValidationError(
            item_path=ms_if0.get_vpath(), error_message=err_msg)

        # Negative Case: pxe_boot_only is set to true on the MS
        ms_if0.properties = {
            "device_name":   "eth0",
            "network_name":  "mgmt",
            "ipaddress":     "10.0.0.2",
            "macaddress":    "08:00:27:65:C2:1D",
            "pxe_boot_only": "true",
        }
        actual = self.plugin.validate_model(self.context)
        for a in actual:
            print a
        self.assertEqual(actual, [err_if0])

        # Negative Case: pxe_boot_only is set to false on the MS
        ms_if0.properties = {
            "device_name":   "eth0",
            "network_name":  "mgmt",
            "ipaddress":     "10.0.0.2",
            "macaddress":    "08:00:27:65:C2:1D",
            "pxe_boot_only": "false",
        }
        actual = self.plugin.validate_model(self.context)
        self.assertEqual(actual, [err_if0])

    def test_pxe_boot_only_set_and_node_initial(self):

        self._create_standard_items()
        node1 = self._create_node('n1', 'node1')

        if0 = self.model_manager.create_item(
            "eth",
            self.node1_path + "/network_interfaces/if0",
            device_name="eth0",
            macaddress='08:00:27:65:C2:1D',
            pxe_boot_only='true'
        )

        if1 = self.model_manager.create_item(
            "eth",
            self.node1_path + "/network_interfaces/if1",
            device_name="eth1",
            macaddress='08:00:27:65:C2:2D'
        )

        # Positive Case: only one nic set to pxe_boot_only true

        self.assertFalse(self.plugin.validate_model(self.context))

        # Positive Case: one nic true and one nic false

        if1.properties = {
            "device_name": "eth1",
            "macaddress": "08:00:27:65:C2:2D",
            "pxe_boot_only": "false"
        }

        self.assertFalse(self.plugin.validate_model(self.context))

        # Positive Case: both nics are false

        if0.properties = {
            "device_name": "eth0",
            "macaddress": "08:00:27:65:C2:1D",
            "pxe_boot_only": "false"
        }
        self.assertFalse(self.plugin.validate_model(self.context))

        # Negative Case: both nics are set to true
        if0.properties = {
            "device_name": "eth0",
            "macaddress": "08:00:27:65:C2:1D",
            "pxe_boot_only": "true"
        }

        if1.properties = {
            "device_name": "eth1",
            "macaddress": "08:00:27:65:C2:2D",
            "pxe_boot_only": "true"
        }

        err_msg = ('Property "pxe_boot_only" can be set to "true" on only '
                   'one interface on node "node1"')

        errors = self.plugin.validate_model(self.context)
        err_if0 = ValidationError(
            item_path=if0.get_vpath(), error_message=err_msg)
        err_if1 = ValidationError(
            item_path=if1.get_vpath(), error_message=err_msg)
        expected_errors = [err_if0, err_if1]
        self.assertEquals(expected_errors, errors)


    def test_pxe_boot_only_not_initial_node(self):

        self._create_standard_items()
        node1 = self._create_node('n1', 'node1')
        node1.set_applied()
        if0 = self.model_manager.create_item(
            "eth",
            self.node1_path + "/network_interfaces/if0",
            device_name="eth0",
            macaddress='08:00:27:65:C2:1D',
            pxe_boot_only='true'
            )

        err_msg = ('Property "pxe_boot_only" can be set to "true" '
                   'only on nodes in "Initial" state')

        errors = self.plugin.validate_model(self.context)
        err_if0 = ValidationError(item_path=if0.get_vpath(),
                                  error_message=err_msg)
        expected_errors = [err_if0]
        self.assertEquals(expected_errors, errors)


    def test_pxe_boot_only_no_vlan_set(self):

        self._create_standard_items()
        node1 = self._create_node('n1', 'node1')

        self.model_manager.create_item(
            'network',
            self.networks_path + 'n1',
            name="mgmt",
            subnet="10.0.0.0/24",
            litp_management='true')
        self.model_manager.create_item(
            "eth",
            "/ms/network_interfaces/if1",
            device_name="eth1",
            macaddress='08:00:27:65:C2:3D',
            network_name="mgmt",
            ipaddress='10.0.0.10',
            )
        self.model_manager.create_item(
            'network',
            self.networks_path + 'n2',
            name="test",
            subnet="10.10.0.0/24",
            litp_management='false')
        if0 = self.model_manager.create_item(
            "eth",
            self.node1_path + "/network_interfaces/if0",
            device_name="eth0",
            macaddress='08:00:27:65:C2:1D',
            pxe_boot_only='true'
            )
        self.model_manager.create_item(
            "eth",
            self.node1_path + "/network_interfaces/if1",
            device_name="eth1",
            macaddress='08:00:27:65:C2:2D',
            network_name="mgmt",
            ipaddress='10.0.0.11',
            )
        self.model_manager.create_item(
            "vlan",
            self.node1_path + "/network_interfaces/vlan2",
            device_name="eth0.10",
            network_name="test",
            ipaddress='10.10.0.11',
            )
        err_msg = 'Item "eth" cannot be tagged when "pxe_boot_only"' \
                  ' property is set to "true"'
        errors = self.plugin.validate_model(self.context)
        err_if0 = ValidationError(item_path=if0.get_vpath(),
                                  error_message=err_msg)
        expected_errors = [err_if0]
        self.assertEquals(expected_errors, errors)


    def test_pxe_boot_only_applied(self):

        self._create_standard_items()
        node1 = self._create_node('n1', 'node1')
        if0 = self.model_manager.create_item(
            "eth",
            self.node1_path + "/network_interfaces/if0",
            device_name="eth0",
            macaddress='08:00:27:65:C2:1D',
            pxe_boot_only='true'
            )
        node1.set_applied()
        if0.set_applied()
        err_msg = ('Property "pxe_boot_only" can be set to "true" '
                   'only on nodes in "Initial" state')
        errors = self.plugin.validate_model(self.context)
        self.assertEquals([], errors)

    def test_remove_pxe_boot_only_applied_item(self):

        self._create_standard_items()
        node1 = self._create_node('n1', 'node1')
        if0 = self.model_manager.create_item(
            "eth",
            self.node1_path + "/network_interfaces/if0",
            device_name="eth0",
            macaddress='08:00:27:65:C2:1D',
            pxe_boot_only='true'
            )
        node1.set_applied()
        if0.set_applied()
        if0.delete_property('pxe_boot_only')
        errors = self.plugin.validate_model(self.context)
        self.assertEquals([], errors)

    def test_remove_pxe_boot_only_applied_property(self):

        self._create_standard_items()
        node1 = self._create_node('n1', 'node1')
        if0 = self.model_manager.create_item(
            "eth",
            self.node1_path + "/network_interfaces/if0",
            device_name="eth0",
            macaddress='08:00:27:65:C2:1D',
            pxe_boot_only='true'
            )
        node1.set_applied()
        if0.set_for_removal()
        err_msg = 'Property "pxe_boot_only" only can be set to "true" on nodes ' \
                  'in "Initial" state'
        errors = self.plugin.validate_model(self.context)
        self.assertEquals([], errors)

    def test_validation_txqueuelen(self):
        self._create_standard_items()
        node1 = self._create_node('n1', 'node1')
        node1.set_applied()

        def _create_eth(device_name, txqueuelen=None):
            macaddress = '08:00:27:65:C2:3{0}'.format(device_name[-1])
            item = self.model_manager.create_item(
                    "eth",
                    self.node1_path + "/network_interfaces/" + device_name,
                    device_name=device_name,
                    macaddress=macaddress
            )
            if txqueuelen:
                item.set_property('txqueuelen', txqueuelen)
            return item

        # Validate an eth item in state Initial with no txqueuelen set
        eth0 = _create_eth('eth0')
        eth0.set_initial()
        errors = self.plugin.validate_model(self.context)
        self.assertEquals([], errors)

        # Validate an eth item in state Initial with txqueuelen set
        eth1 = _create_eth('eth1', '150')
        eth1.set_initial()
        errors = self.plugin.validate_model(self.context)
        self.assertEquals([], errors)

        # Validate an eth item in state Updated with txqueuelen going from
        # unset to set
        eth2 = _create_eth('eth2')
        eth2.set_applied()
        eth2.set_property('txqueuelen', '300')
        eth2.set_updated()
        errors = self.plugin.validate_model(self.context)
        self.assertEquals([], errors)

        # Validate an eth item in state Updated with txqueuelen going from
        # one value to another value
        eth3 = _create_eth('eth3', '300')
        eth3.set_applied()
        eth3.set_property('txqueuelen', '42')
        eth3.set_updated()
        errors = self.plugin.validate_model(self.context)
        self.assertEquals([], errors)

        # Validate an eth item in state Initial where it was created with
        # txqueuelen and then the txqueuelen value deleted (still in Initial)
        eth4 = _create_eth('eth4', '150')
        eth4.set_initial()
        eth4.set_property('txqueuelen', None)
        errors = self.plugin.validate_model(self.context)
        self.assertEquals([], errors)

        # Validate an eth item going from state Applied with txqueuelen set
        # to state Updated with txqueuelen being deleted.
        eth5 = _create_eth('eth5', '150')
        eth5.set_applied()
        eth5.set_property('txqueuelen', None)
        eth5.set_updated()
        errors = self.plugin.validate_model(self.context)
        err_eth5 = ValidationError(
                item_path=eth5.get_vpath(),
                error_message='The txqueuelen property can not be '
                              'removed once set.')
        expected_errors = [err_eth5]
        self.assertEquals(expected_errors, errors)
