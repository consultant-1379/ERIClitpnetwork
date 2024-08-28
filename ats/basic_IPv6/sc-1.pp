
class task_sc_2d1__litpnetwork_3a_3aconfig__eth0(){
    litpnetwork::config { "eth0":
        bootproto => "static",
        broadcast => "10.10.10.255",
        ensure => "present",
        hwaddr => "08:00:27:5B:C1:3F",
        ipaddr => "10.10.10.102",
        is_mgmt_if => "true",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_sc_2d1__litpnetwork_3a_3aconfig__eth2(){
    litpnetwork::config { "eth2":
        bootproto => "static",
        ensure => "present",
        hwaddr => "08:00:27:43:B8:FC",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_sc_2d1__litpnetwork_3a_3aconfig__eth4(){
    litpnetwork::config { "eth4":
        bootproto => "static",
        ensure => "present",
        hwaddr => "08:00:27:CA:22:A6",
        ipv6addr => "2001:bb::1:2/64",
        ipv6init => "yes",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_sc_2d1__litpnetwork_3a_3aconfig__eth5(){
    litpnetwork::config { "eth5":
        bootproto => "static",
        broadcast => "20.20.20.255",
        ensure => "present",
        hwaddr => "08:00:27:0A:3F:43",
        ipaddr => "20.20.20.130",
        ipv6addr => "2001:ab::1:3/64",
        ipv6init => "yes",
        netmask => "255.255.255.128",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_sc_2d1__litpnetwork_3a_3aroute__eth0__routes(){
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
        "10.10.10.1"
        ]
,
netmask => [
        "0.0.0.0"
        ]
,
        node_name => "sc-1",
        require => [Litpnetwork::Config["eth0"]]
    }
}

class task_sc_2d1__litpnetwork_3a_3aroute__reload__sc_2d1__route__reload(){
    litpnetwork::route_reload { "sc-1_route_reload":
devices => [
        "eth0"
        ]
,
        subscribe => [Litpnetwork::Route["eth0_routes"]]
    }
}


node "sc-1" {

    class {'litp::mn_node':
        ms_hostname => "ms1",
        cluster_type => "NON-CMW"
        }


    class {'task_sc_2d1__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_sc_2d1__litpnetwork_3a_3aconfig__eth2':
    }


    class {'task_sc_2d1__litpnetwork_3a_3aconfig__eth4':
    }


    class {'task_sc_2d1__litpnetwork_3a_3aconfig__eth5':
    }


    class {'task_sc_2d1__litpnetwork_3a_3aroute__eth0__routes':
    }


    class {'task_sc_2d1__litpnetwork_3a_3aroute__reload__sc_2d1__route__reload':
    }


}