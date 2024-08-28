class task_mn1__litpnetwork_3a_3aconfig__eth0(){
    litpnetwork::config { "eth0":
        bootproto => "static",
        broadcast => "10.10.10.255",
        ensure => "present",
        hwaddr => "08:00:27:5B:C1:3F",
        ipaddr => "10.10.10.1",
        is_mgmt_if => "true",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_mn1__litpnetwork_3a_3aroute__eth0__routes(){
    litpnetwork::route { "eth0_routes":
address => [
        "0.0.0.0",
        "192.168.1.0"
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
        "10.10.10.1"
        ]
,
netmask => [
        "0.0.0.0",
        "255.255.255.0"
        ]
,
        node_name => "mn1",
        require => [Litpnetwork::Config["eth0"]]
    }
}

class task_mn1__litpnetwork_3a_3aroute__reload__mn1__route__reload(){
    litpnetwork::route_reload { "mn1_route_reload":
devices => [
        "eth0"
        ]
,
        subscribe => [Litpnetwork::Route["eth0_routes"]]
    }
}


node "mn1" {

    class {'litp::mn_node':
        ms_hostname => "ms1",
        cluster_type => "NON-CMW"
        }


    class {'task_mn1__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_mn1__litpnetwork_3a_3aroute__eth0__routes':
    }


    class {'task_mn1__litpnetwork_3a_3aroute__reload__mn1__route__reload':
    }


}