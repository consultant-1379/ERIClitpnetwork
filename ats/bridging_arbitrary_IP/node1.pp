class task_node1__litpnetwork_3a_3aconfig__br_4d_53___56_4d__bridge(){
    litpnetwork::config { "brMS_VM_bridge":
        bootproto => "static",
        broadcast => "10.0.0.255",
        delay => "4",
        ensure => "present",
        ipaddr => "10.0.0.43",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        stp => "off",
        type => "Bridge"
    }
}

class task_node1__litpnetwork_3a_3aconfig__eth0(){
    litpnetwork::config { "eth0":
        bootproto => "static",
        bridge => "brMS_VM_bridge",
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

class task_node1__litpnetwork_3a_3aroute__br_4d_53___56_4d__bridge__routes(){
    litpnetwork::route { "brMS_VM_bridge_routes":
        device => "brMS_VM_bridge",
        ensure => "present",
routes => [
        "ADDRESS0=0.0.0.0 GATEWAY0=10.0.0.254 NETMASK0=0.0.0.0"
        ]

    }
}


node "node1" {

    class {'litp::mn_node':
        ms_hostname => "ms1"
        }


    class {'task_node1__litpnetwork_3a_3aconfig__br_4d_53___56_4d__bridge':
    }


    class {'task_node1__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_node1__litpnetwork_3a_3aconfig__lo':
    }


    class {'task_node1__litpnetwork_3a_3aroute__br_4d_53___56_4d__bridge__routes':
    }


}
