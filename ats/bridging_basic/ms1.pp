class task_ms1__litpnetwork_3a_3aconfig__br0(){
    litpnetwork::config { "br0":
        bootproto => "static",
        bridging_opts => "multicast_snooping=1 multicast_querier=0 multicast_router=1 hash_max=512 hash_elasticity=4",
        broadcast => "10.4.23.255",
        delay => "30",
        ensure => "present",
        hotplug => "no",
        ipaddr => "10.4.23.50",
        is_mgmt_if => "true",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        stp => "on",
        type => "Bridge",
        userctl => "no"
    }
}

class task_ms1__litpnetwork_3a_3aconfig__eth0(){
    litpnetwork::config { "eth0":
        before_device => "br0",
        bootproto => "static",
        bridge => "br0",
        ensure => "present",
        hwaddr => "08:00:27:24:8f:27",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_ms1__litpnetwork_3a_3aroute__br0__routes(){
    litpnetwork::route { "br0_routes":
address => [
        "0.0.0.0"
        ]
,
        device => "br0",
        ensure => "present",
family => [
        "inet4"
        ]
,
gateway => [
        "10.4.23.1"
        ]
,
netmask => [
        "0.0.0.0"
        ]
,
        node_name => "ms1",
        require => [Litpnetwork::Config["br0"]]
    }
}

class task_ms1__litpnetwork_3a_3aroute__reload__ms1__route__reload(){
    litpnetwork::route_reload { "ms1_route_reload":
devices => [
        "br0"
        ]
,
        subscribe => [Litpnetwork::Route["br0_routes"]]
    }
}


node "ms1" {

    class {'litp::ms_node':}


    class {'task_ms1__litpnetwork_3a_3aconfig__br0':
    }


    class {'task_ms1__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_ms1__litpnetwork_3a_3aroute__br0__routes':
    }


    class {'task_ms1__litpnetwork_3a_3aroute__reload__ms1__route__reload':
    }


}
