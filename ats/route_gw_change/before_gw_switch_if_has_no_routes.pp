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
        broadcast => "10.44.86.255",
        ensure => "present",
        hwaddr => "33:44:55:DD:EE:FF",
        ipaddr => "10.44.86.66",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_ms1__litpnetwork_3a_3aroute__eth0__routes(){
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
        "10.44.235.1"
        ]
,
netmask => [
        "0.0.0.0"
        ]
,
        node_name => "ms1",
        require => [Litpnetwork::Config["eth0"]]
    }
}

class task_ms1__litpnetwork_3a_3aroute__eth1__routes(){
    litpnetwork::route { "eth1_routes":
address => [
        "172.19.0.0"
        ]
,
        device => "eth1",
        ensure => "present",
family => [
        "inet4"
        ]
,
gateway => [
        "10.44.86.1"
        ]
,
netmask => [
        "255.255.0.0"
        ]
,
        node_name => "ms1",
        require => [Litpnetwork::Config["eth1"]]
    }
}

class task_ms1__litpnetwork_3a_3aroute__reload__ms1__route__reload(){
    litpnetwork::route_reload { "ms1_route_reload":
devices => [
        "eth1",
        "eth0"
        ]
,
        subscribe => [Litpnetwork::Route["eth1_routes"],Litpnetwork::Route["eth0_routes"]]
    }
}


node "ms1" {

    class {'litp::ms_node':}


    class {'task_ms1__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_ms1__litpnetwork_3a_3aconfig__eth1':
    }


    class {'task_ms1__litpnetwork_3a_3aroute__eth0__routes':
    }


    class {'task_ms1__litpnetwork_3a_3aroute__eth1__routes':
    }


    class {'task_ms1__litpnetwork_3a_3aroute__reload__ms1__route__reload':
    }


}