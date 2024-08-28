
class task_node1__litpnetwork_3a_3aconfig__eth0(){
    litpnetwork::config { "eth0":
        bootproto => "static",
        broadcast => "10.10.10.255",
        ensure => "present",
        hwaddr => "08:00:27:24:8f:27",
        ipaddr => "10.10.10.105",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_node1__litpnetwork_3a_3aconfig__eth2(){
    litpnetwork::config { "eth2":
        bootproto => "static",
        broadcast => "10.10.20.255",
        ensure => "present",
        hwaddr => "08:00:27:43:B8:FC",
        ipaddr => "10.10.20.106",
        netmask => "255.255.255.0",
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

class task_node1__litpnetwork_3a_3aroute__eth0__routes(){
    litpnetwork::route { "eth0_routes":
        device => "eth0",
        ensure => "present",
routes => [
        "ADDRESS0=0.0.0.0 GATEWAY0=10.10.10.1 NETMASK0=0.0.0.0"
        ]

    }
}


node "node1" {

    class {'litp::mn_node':
        ms_hostname => "ms1"
        }


    class {'task_node1__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_node1__litpnetwork_3a_3aconfig__eth2':
    }


    class {'task_node1__litpnetwork_3a_3aconfig__lo':
    }


    class {'task_node1__litpnetwork_3a_3aroute__eth0__routes':
    }


}
