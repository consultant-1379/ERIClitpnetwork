##############################################################################
# COPYRIGHT Ericsson AB 2016
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
from mock import Mock
from litp.core.litp_logging import LitpLogger

log = LitpLogger()


class NetworkMock(Mock):

    def __init__(
            self,
            item_type_id,
            item_id,
            ms_for_get=None,
            node_for_get=None,
            cluster_for_get=None
    ):

        super(NetworkMock, self).__init__(item_id=item_id,
                                         item_type_id=item_type_id)

        self._model_item = None
        self.ms_for_get = ms_for_get
        self.node_for_get = node_for_get
        self.cluster_for_get = cluster_for_get

        self.properties = {}
        self.applied_properties = {}
        self.property_names = []
        self.get_vpath = lambda: "/%s/%s" % (self.item_type_id, self.item_id)
        self.get_source = lambda: self
        self.vpath = self.get_vpath()
        self.collections = {}
        self.subitems = {}

        self.applied_properties_determinable = True

    def get_ms(self):
        return self.ms_for_get

    def get_node(self):
        return self.node_for_get

    def get_cluster(self):
        return self.cluster_for_get

    @staticmethod
    def filter_on_item_properties(items, **properties):

        if not properties:
            return items

        filtered_items = []

        # iterate items from the model
        for item in items:
            # iterate query attributes and values
            for attr, value in properties.iteritems():

                # if the item has the attribute and it equals the value
                if getattr(item, attr) == value:
                    filtered_items.append(item)

        return filtered_items

    def query(self, item_type_id):
        return []

    @staticmethod
    def mock_query(items):

        def query(item_type, **properties):
            return NetworkMock.filter_on_item_properties(
                items.get(item_type, []), **properties)

        return query

        self.is_initial = lambda: True
        self.is_updated = lambda: False
        self.is_for_removal = lambda: False

    def query(self, arg, **kwargs):
        # this does not currently handle sub- item-types
        # this does not currently handle filtering kwargs
        items = []
        if self.collections.has_key(arg):
            items.extend(getattr(self, self.collections[arg]))
        for coll_attr in self.collections.values():
            coll = getattr(self, coll_attr)
            for child_item in coll:
                items.extend(child_item.query(arg, **kwargs))
        if self.subitems.has_key(arg):
            items.extend(getattr(self, self.subitems[arg]))
        for subitem_attr in self.subitems.values():
            child_item = getattr(self, subitem_attr)
            items.extend(child_item.query(arg, **kwargs))
        # print "%s.query('%s') -> %s" % (self, arg, items)
        return items

    @staticmethod
    def filter_on_item_properties(items, **properties):

        if not properties:
            return items

        filtered_items = []

        # iterate items from the model
        for item in items:
            # iterate query attributes and values
            for attr, value in properties.iteritems():

                # if the item has the attribute and it equals the value
                if getattr(item, attr) == value:
                    filtered_items.append(item)

        return filtered_items

    def query(self, item_type_id):
        return []

    @staticmethod
    def mock_query(items):

        def query(item_type, **properties):
            return NetworkMock.filter_on_item_properties(
                items.get(item_type, []), **properties)

        return query

    @staticmethod
    def set_properties(item):
        for prop_name in item.property_names:
            item.properties[prop_name] = getattr(item, prop_name)

    @staticmethod
    def set_applied_properties(item):
        for prop_name in item.property_names:
            item.applied_properties[prop_name] = getattr(item, prop_name)

    @staticmethod
    def _set_state_xxx(items, state):
        for item in items:
            if not isinstance(item, NetworkMock):
                raise Exception('Invalid Mock item', item)

            NetworkMock.set_properties(item)

            if 'applied' == state:
                item.is_applied = lambda: True
                item.is_for_removal = lambda: False
                item.is_updated = lambda: False
                item.is_initial = lambda: False
                NetworkMock.set_applied_properties(item)
            elif 'for_removal' == state:
                item.is_applied = lambda: False
                item.is_for_removal = lambda: True
                item.is_updated = lambda: False
                item.is_initial = lambda: False
            elif 'updated' == state:
                item.is_applied = lambda: False
                item.is_for_removal = lambda: False
                item.is_updated = lambda: True
                item.is_initial = lambda: False
            elif 'initial' == state:
                item.is_applied = lambda: False
                item.is_for_removal = lambda: False
                item.is_updated = lambda: False
                item.is_initial = lambda: True

    @staticmethod
    def set_state_applied(items):
        NetworkMock._set_state_xxx(items, 'applied')

    @staticmethod
    def set_state_updated(items):
        NetworkMock._set_state_xxx(items, 'updated')

    @staticmethod
    def set_state_initial(items):
        NetworkMock._set_state_xxx(items, 'initial')

    @staticmethod
    def set_state_for_removal(items):
        NetworkMock._set_state_xxx(items, 'for_removal')


class NetworkMockEth(NetworkMock):
    def __init__(self, item_id, device_name, macaddress, network_name,
                 ipaddress='', ipv6address='',
                 bridge='', master='', ipv6_autoconf='false',
                 rx_ring_buffer=None, tx_ring_buffer=None,
                 pxe_boot_only='false', txqueuelen=None):

        super(NetworkMockEth, self).__init__(item_type_id='eth',
                                             item_id=item_id)

        self.network_name = network_name
        self.ipaddress = ipaddress
        self.ipv6address = ipv6address
        self.ipv6_autoconf = ipv6_autoconf
        self.device_name = device_name
        self.macaddress = macaddress
        self.bridge = bridge
        self.master = master
        self.pxe_boot_only = pxe_boot_only
        self.rx_ring_buffer = rx_ring_buffer
        self.tx_ring_buffer = tx_ring_buffer
        self.txqueuelen = txqueuelen

        self.property_names = ['macaddress', 'bridge', 'master', 'device_name',
                               'network_name', 'ipaddress', 'ipv6address',
                               'pxe_boot_only',
                               'rx_ring_buffer', 'tx_ring_buffer',
                               'txqueuelen']


class NetworkMockBridge(NetworkMock):
    def __init__(self, item_id, device_name, network_name, ipaddress='', ipv6address='',
                 stp='', forwarding_delay='', hash_max='2048',
                 multicast_snooping='1', multicast_querier='1', multicast_router='2',
                 hash_elasticity='4', ipv6_autoconf='false'):

        super(NetworkMockBridge, self).__init__(item_type_id='bridge',
                                                item_id=item_id)

        self.network_name = network_name
        self.ipaddress = ipaddress
        self.ipv6address = ipv6address
        self.device_name = device_name
        self.stp = stp
        self.forwarding_delay = forwarding_delay
        self.hash_max = hash_max
        self.multicast_snooping = multicast_snooping
        self.multicast_querier = multicast_querier
        self.multicast_router = multicast_router
        self.hash_elasticity = hash_elasticity
        self.ipv6_autoconf = ipv6_autoconf

        self.property_names = ['network_name', 'ipaddress', 'ipv6address',
                               'device_name', 'stp', 'forwarding_delay', 'hash_max',
                               'multicast_snooping', 'multicast_querier', 'multicast_router',
                               'hash_elasticity', 'ipv6_autoconf']


class NetworkMockBond(NetworkMock):
    def __init__(self, item_id, device_name, network_name, ipaddress='', ipv6address='',
                 mode='0', bridge='', miimon='0',
                 arp_interval='0', arp_ip_target='', arp_validate='none', arp_all_targets='',
                 primary='', primary_reselect='always'):

        super(NetworkMockBond, self).__init__(item_type_id='bond',
                                              item_id=item_id)

        self.network_name = network_name
        self.ipaddress = ipaddress
        self.ipv6address = ipv6address
        self.device_name = device_name
        self.mode = mode
        self.bridge = bridge
        self.miimon = miimon
        self.arp_interval = arp_interval
        self.arp_ip_target = arp_ip_target
        self.arp_validate = arp_validate
        self.arp_all_targets = arp_all_targets
        self.primary = primary
        self.primary_reselect = primary_reselect

        self.property_names = ['network_name', 'ipaddress', 'ipv6address',
                               'device_name', 'mode', 'bridge', 'miimon',
                               'arp_interval', 'arp_ip_target', 'arp_validate', 'arp_all_targets',
                               'primary', 'primary_reselect']


class NetworkMockNode(NetworkMock):

    def __init__(self, item_id, hostname, item_type_id='node'):

        super(NetworkMockNode, self).__init__(
            item_type_id=item_type_id,
            item_id=item_id
        )

        self.hostname = hostname
        self.property_names = ['hostname']
        self.network_interfaces = []
        self.routes = []
        self.collections['network_interfaces'] = 'network_interfaces'
        self.collections['routes'] = 'routes'

    def is_ms(self):
        return self.item_type_id is 'ms'


class NetworkMockMS(NetworkMockNode):

    def __init__(self):

        super(NetworkMockMS, self).__init__(
            item_id='ms',
            hostname='ms1',
            item_type_id='ms'
        )


class NetworkMockCluster(NetworkMock):

    def __init__(
            self,
            item_id,
            cluster_type='',
            dependency_list=None,
            item_type_id='cluster'):

        super(NetworkMockCluster, self).__init__(
            item_type_id=item_type_id, item_id=item_id
        )

        self.cluster_type = cluster_type
        self.dependency_list = dependency_list
        self.cluster_id = item_id
        self.property_names = ['cluster_type', 'dependency_list']

        # these are all collections
        self.software = []
        self.nodes = []
        self.services = []
        self.software = []
        self.collections['software'] = 'software'
        self.collections['node'] = 'nodes'
        self.collections['service'] = 'services'
        self.collections['software'] = 'software'


class NetworkMockDeployment(NetworkMock):
    def __init__(self, item_id, item_type_id='deployment'):
        super(NetworkMockDeployment, self).__init__(
            item_type_id=item_type_id, item_id=item_id
        )
        self.clusters = []
        self.collections['cluster'] = 'clusters'


class NetworkMockContext(NetworkMock):
    def __init__(self):
        super(NetworkMockContext, self).__init__(item_type_id='', item_id='')
        self.rpc_command = None
