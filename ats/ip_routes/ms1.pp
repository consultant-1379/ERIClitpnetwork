class task_ms1__litpnetwork_3a_3aconfig__eth0(){
    litpnetwork::config { "eth0":
        bootproto => "static",
        broadcast => "10.10.10.255",
        ensure => "present",
        hwaddr => "08:00:27:5B:C1:3E",
        ipaddr => "10.10.10.4",
        is_mgmt_if => "true",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_ms1__litpnetwork_3a_3aroute__eth0__routes(){
    litpnetwork::route { "eth0_routes":
address => [
        "0.0.0.0",
        "172.16.19.0"
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
        "10.10.10.2",
        "10.10.10.2"
        ]
,
netmask => [
        "0.0.0.0",
        "255.255.255.0"
        ]
,
        node_name => "ms1",
        require => [Litpnetwork::Config["eth0"]]
    }
}

class task_ms1__litpnetwork_3a_3aroute__reload__ms1__route__reload(){
    litpnetwork::route_reload { "ms1_route_reload":
devices => [
        "eth0"
        ]
,
        subscribe => [Litpnetwork::Route["eth0_routes"]]
    }
}


node "ms1" {

    class {'litp::ms_node':}


    class {'task_ms1__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_ms1__litpnetwork_3a_3aroute__eth0__routes':
    }


    class {'task_ms1__litpnetwork_3a_3aroute__reload__ms1__route__reload':
    }


}