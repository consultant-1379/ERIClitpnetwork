class task_node1__litpnetwork_3a_3aconfig__br0(){
    litpnetwork::config { "br0":
        bootproto => "static",
        broadcast => "10.0.0.255",
        delay => "4",
        ensure => "present",
        ipaddr => "10.0.0.2",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        stp => "off",
        type => "Bridge",
        userctl => "no"
    }
}

class task_node1__litpnetwork_3a_3aconfig__eth0(){
    litpnetwork::config { "eth0":
        bootproto => "static",
        bridge => "br0",
        ensure => "present",
        hwaddr => "DE:AD:BE:EF:13:37",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_node1__litpnetwork_3a_3aconfig__lo(){
    litpnetwork::config { "lo":
        bootproto => "static",
        broadcast => "127.255.255.255",
        device => "lo",
        ensure => "present",
        ipaddr => "127.0.0.1",
        netmask => "255.0.0.0",
        network => "127.0.0.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_node1__litpnetwork_3a_3aroute__br0__routes(){
    litpnetwork::route { "br0_routes":
        device => "br0",
        ensure => "present",
routes => [
        "ADDRESS0=0.0.0.0 GATEWAY0=10.0.0.1 NETMASK0=0.0.0.0"
        ]

    }
}


node "node1" {

    class {'litp::mn_node':
        ms_hostname => "ms1"
        }


    class {'task_node1__litpnetwork_3a_3aconfig__br0':
    }


    class {'task_node1__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_node1__litpnetwork_3a_3aconfig__lo':
    }


    class {'task_node1__litpnetwork_3a_3aroute__br0__routes':
    }


}