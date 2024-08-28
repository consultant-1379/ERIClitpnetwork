
class task_node2__litpnetwork_3a_3aconfig__eth3(){
    litpnetwork::config { "eth3":
        bootproto => "static",
        broadcast => "10.10.10.255",
        ensure => "present",
        hwaddr => "08:00:27:24:8f:28",
        ipaddr => "10.10.10.107",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_node2__litpnetwork_3a_3aconfig__eth4(){
    litpnetwork::config { "eth4":
        bootproto => "static",
        broadcast => "10.10.11.255",
        ensure => "present",
        hwaddr => "08:00:27:24:8f:29",
        ipaddr => "10.10.11.107",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_node2__litpnetwork_3a_3aconfig__lo(){
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

class task_node2__litpnetwork_3a_3aroute__eth3__routes(){
    litpnetwork::route { "eth3_routes":
        device => "eth3",
        ensure => "present",
routes => [
        "ADDRESS0=0.0.0.0 GATEWAY0=10.10.10.1 NETMASK0=0.0.0.0"
        ]

    }
}


node "node2" {

    class {'litp::mn_node':
        ms_hostname => "ms1"
        }


    class {'task_node2__litpnetwork_3a_3aconfig__eth3':
    }


    class {'task_node2__litpnetwork_3a_3aconfig__eth4':
    }


    class {'task_node2__litpnetwork_3a_3aconfig__lo':
    }


    class {'task_node2__litpnetwork_3a_3aroute__eth3__routes':
    }


}
