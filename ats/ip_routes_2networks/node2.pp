
class task_node2__litpnetwork_3a_3aconfig__eth0(){
    litpnetwork::config { "eth0":
        bootproto => "static",
        broadcast => "10.10.10.255",
        ensure => "present",
        hwaddr => "DE:AD:BE:EF:45:52",
        ipaddr => "10.10.10.102",
        is_mgmt_if => "true",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_node2__litpnetwork_3a_3aconfig__eth2(){
    litpnetwork::config { "eth2":
        bootproto => "static",
        broadcast => "192.168.100.255",
        ensure => "present",
        hwaddr => "52:54:00:53:f5:a0",
        ipaddr => "192.168.100.101",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_node2__litpnetwork_3a_3aroute__eth0__routes(){
    litpnetwork::route { "eth0_routes":
address => [
        "0.0.0.0",
        "192.168.0.0"
        ]
,
        device => "eth0",
        ensure => "present",
family => [
        "inet4",
        "inet4"
        ]
,
gateway => [
        "10.10.10.1",
        "10.10.10.1"
        ]
,
netmask => [
        "0.0.0.0",
        "255.255.255.0"
        ]
,
        node_name => "node2",
        require => [Litpnetwork::Config["eth0"]]
    }
}

class task_node2__litpnetwork_3a_3aroute__eth2__routes(){
    litpnetwork::route { "eth2_routes":
address => [
        "1.1.1.1"
        ]
,
        device => "eth2",
        ensure => "present",
family => [
        "inet4"
        ]
,
gateway => [
        "192.168.100.254"
        ]
,
netmask => [
        "255.255.255.255"
        ]
,
        node_name => "node2",
        require => [Litpnetwork::Config["eth2"]]
    }
}

class task_node2__litpnetwork_3a_3aroute__reload__node2__route__reload(){
    litpnetwork::route_reload { "node2_route_reload":
devices => [
        "eth2",
        "eth0"
        ]
,
        subscribe => [Litpnetwork::Route["eth2_routes"],Litpnetwork::Route["eth0_routes"]]
    }
}


node "node2" {

    class {'litp::mn_node':
        ms_hostname => "ms1",
        cluster_type => "NON-CMW"
        }


    class {'task_node2__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_node2__litpnetwork_3a_3aconfig__eth2':
    }


    class {'task_node2__litpnetwork_3a_3aroute__eth0__routes':
    }


    class {'task_node2__litpnetwork_3a_3aroute__eth2__routes':
    }


    class {'task_node2__litpnetwork_3a_3aroute__reload__node2__route__reload':
    }


}