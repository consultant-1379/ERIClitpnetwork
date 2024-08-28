class task_node2__litpnetwork_3a_3aconfig__eth0(){
    litpnetwork::config { "eth0":
        bootproto => "static",
        broadcast => "10.0.0.255",
        ensure => "present",
        hwaddr => "DE:AD:BE:EF:13:38",
        ipaddr => "10.0.0.3",
        is_mgmt_if => "true",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_node2__litpnetwork_3a_3aroute__eth0__routes(){
    litpnetwork::route { "eth0_routes":
address => [
        "0.0.0.0"
        ]
,
        device => "eth0",
        ensure => "present",
family => [
        "inet4"
        ]
,
gateway => [
        "10.0.0.254"
        ]
,
netmask => [
        "0.0.0.0"
        ]
,
        node_name => "node2",
        require => [Litpnetwork::Config["eth0"]]
    }
}

class task_node2__litpnetwork_3a_3aroute__reload__node2__route__reload(){
    litpnetwork::route_reload { "node2_route_reload":
devices => [
        "eth0"
        ]
,
        subscribe => [Litpnetwork::Route["eth0_routes"]]
    }
}


node "node2" {

    class {'litp::mn_node':
        ms_hostname => "ms1",
        cluster_type => "NON-CMW"
        }


    class {'task_node2__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_node2__litpnetwork_3a_3aroute__eth0__routes':
    }


    class {'task_node2__litpnetwork_3a_3aroute__reload__node2__route__reload':
    }


}