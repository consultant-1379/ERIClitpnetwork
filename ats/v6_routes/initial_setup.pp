class task_ms1__litpnetwork_3a_3aconfig__eth0(){
    litpnetwork::config { "eth0":
        bootproto => "static",
        broadcast => "10.44.235.255",
        ensure => "present",
        hwaddr => "00:11:22:AA:BB:CC",
        ipaddr => "10.44.235.100",
        is_mgmt_if => "true",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_ms1__litpnetwork_3a_3aconfig__eth1(){
    litpnetwork::config { "eth1":
        bootproto => "static",
        ensure => "present",
        hwaddr => "33:44:55:DD:EE:FF",
        ipv6addr => "2001:4860:4860::1/64",
        ipv6init => "yes",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_ms1__litpnetwork_3a_3aroute__eth1__routes(){
    litpnetwork::route { "eth1_routes":
address => [
        "3ffe:fffe:1:2::",
        "::"
        ]
,
        device => "eth1",
        ensure => "present",
family => [
        "inet6",
        "inet6"
        ]
,
gateway => [
        "2001:4860:4860::9999",
        "2001:4860:4860::8888"
        ]
,
netmask => [
        "ffff:ffff:ffff:ffff::",
        "::"
        ]
,
        node_name => "ms1",
        require => [Litpnetwork::Config["eth1"]]
    }
}

class task_ms1__litpnetwork_3a_3aroute__reload__ms1__route__reload(){
    litpnetwork::route_reload { "ms1_route_reload":
devices => [
        "eth1"
        ]
,
        subscribe => [Litpnetwork::Route["eth1_routes"]]
    }
}


node "ms1" {

    class {'litp::ms_node':}


    class {'task_ms1__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_ms1__litpnetwork_3a_3aconfig__eth1':
    }


    class {'task_ms1__litpnetwork_3a_3aroute__eth1__routes':
    }


    class {'task_ms1__litpnetwork_3a_3aroute__reload__ms1__route__reload':
    }


}