class task_node1__litpnetwork_3a_3aconfig__br_4d_53___56_4d__bridge(){
    litpnetwork::config { "brMS_VM_bridge":
        bootproto => "static",
        bridging_opts => "multicast_snooping=1 multicast_querier=1 multicast_router=1 hash_max=262144 hash_elasticity=4",
        broadcast => "10.0.0.255",
        delay => "4",
        ensure => "present",
        hotplug => "no",
        ipaddr => "10.0.0.105",
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
        before_device => "brMS_VM_bridge",
        bootproto => "static",
        bridge => "brMS_VM_bridge",
        ensure => "present",
        hwaddr => "DE:AD:BE:EF:13:37",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_node1__litpnetwork_3a_3aconfig__eth9(){
    litpnetwork::config { "eth9":
        bootproto => "static",
        broadcast => "192.168.0.255",
        ensure => "present",
        hwaddr => "00:00:00:00:00:01",
        ipaddr => "192.168.0.1",
        is_mgmt_if => "true",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}

class task_node1__litpnetwork_3a_3aroute__br_4d_53___56_4d__bridge__routes(){
    litpnetwork::route { "brMS_VM_bridge_routes":
address => [
        "0.0.0.0"
        ]
,
        device => "brMS_VM_bridge",
        ensure => "present",
family => [
        "inet4"
        ]
,
gateway => [
        "10.0.0.254"
        ]
,
netmask => [
        "0.0.0.0"
        ]
,
        node_name => "node1",
        require => [Litpnetwork::Config["brMS_VM_bridge"]]
    }
}

class task_node1__litpnetwork_3a_3aroute__reload__node1__route__reload(){
    litpnetwork::route_reload { "node1_route_reload":
devices => [
        "brMS_VM_bridge"
        ]
,
        subscribe => [Litpnetwork::Route["brMS_VM_bridge_routes"]]
    }
}


node "node1" {

    class {'litp::mn_node':
        ms_hostname => "ms1",
        cluster_type => "NON-CMW"
        }


    class {'task_node1__litpnetwork_3a_3aconfig__br_4d_53___56_4d__bridge':
    }


    class {'task_node1__litpnetwork_3a_3aconfig__eth0':
    }


    class {'task_node1__litpnetwork_3a_3aconfig__eth9':
    }


    class {'task_node1__litpnetwork_3a_3aroute__br_4d_53___56_4d__bridge__routes':
    }


    class {'task_node1__litpnetwork_3a_3aroute__reload__node1__route__reload':
    }


}
