class task_node1__litpnetwork_3a_3aconfig__bond0(){
    litpnetwork::config { "bond0":
        before_device => "br1",
        bonding_opts => "miimon=100 mode=1",
        bootproto => "static",
        bridge => "br1",
        ensure => "present",
        hotplug => "no",
        nozeroconf => "yes",
        onboot => "yes",
        required_device => "eth8",
        type => "Bonding",
        userctl => "no"
    }
}

class task_node1__litpnetwork_3a_3aconfig__br1(){
    litpnetwork::config { "br1":
        bootproto => "static",
        bridging_opts => "multicast_snooping=1 multicast_querier=0 multicast_router=1 hash_max=512 hash_elasticity=4",
        broadcast => "192.168.0.255",
        delay => "4",
        ensure => "present",
        hotplug => "no",
        ipaddr => "192.168.0.42",
        is_mgmt_if => "true",
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
        ensure => "present",
        hwaddr => "00:00:00:00:00:01",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_node1__litpnetwork_3a_3aconfig__eth8(){
    litpnetwork::config { "eth8":
        before_device => "eth9",
        bootproto => "static",
        ensure => "present",
        master => "bond0",
        nozeroconf => "yes",
        onboot => "yes",
        slave => "yes",
        userctl => "no"
    }
}

class task_node1__litpnetwork_3a_3aconfig__eth9(){
    litpnetwork::config { "eth9":
        bootproto => "static",
        ensure => "present",
        master => "bond0",
        nozeroconf => "yes",
        onboot => "yes",
        slave => "yes",
        userctl => "no"
    }
}


node "node1" {

    class {'litp::mn_node':
        ms_hostname => "ms1",
        cluster_type => "NON-CMW"
        }


    class {'task_node1__litpnetwork_3a_3aconfig__bond0':
    }


    class {'task_node1__litpnetwork_3a_3aconfig__br1':
        require => [Class["task_node1__litpnetwork_3a_3aconfig__eth0"]]
    }


    class {'task_node1__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_node1__litpnetwork_3a_3aconfig__eth8':
    }


    class {'task_node1__litpnetwork_3a_3aconfig__eth9':
    }


}
