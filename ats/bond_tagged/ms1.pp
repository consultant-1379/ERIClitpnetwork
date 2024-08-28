class task_ms1__litpnetwork_3a_3aconfig__bond0(){
    litpnetwork::config { "bond0":
        bonding_opts => "miimon=100 mode=1",
        bootproto => "static",
        broadcast => "10.4.23.255",
        ensure => "present",
        hotplug => "no",
        ipaddr => "10.4.23.50",
        is_mgmt_if => "true",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        required_device => "eth11",
        type => "Bonding",
        userctl => "no"
    }
}

class task_ms1__litpnetwork_3a_3aconfig__bond0_2e123(){
    litpnetwork::config { "bond0.123":
        bootproto => "static",
        broadcast => "1.2.3.255",
        ensure => "present",
        hotplug => "no",
        ipaddr => "1.2.3.4",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        required_device => "bond0",
        userctl => "no",
        vlan => "yes"
    }
}

class task_ms1__litpnetwork_3a_3aconfig__eth11(){
    litpnetwork::config { "eth11":
        before_device => "eth20",
        bootproto => "static",
        ensure => "present",
        master => "bond0",
        nozeroconf => "yes",
        onboot => "yes",
        slave => "yes",
        userctl => "no"
    }
}

class task_ms1__litpnetwork_3a_3aconfig__eth20(){
    litpnetwork::config { "eth20":
        bootproto => "static",
        ensure => "present",
        master => "bond0",
        nozeroconf => "yes",
        onboot => "yes",
        slave => "yes",
        userctl => "no"
    }
}

class task_ms1__litpnetwork_3a_3aroute__bond0__routes(){
    litpnetwork::route { "bond0_routes":
address => [
        "0.0.0.0"
        ]
,
        device => "bond0",
        ensure => "present",
family => [
        "inet4"
        ]
,
gateway => [
        "10.4.23.1"
        ]
,
netmask => [
        "0.0.0.0"
        ]
,
        node_name => "ms1",
        require => [Litpnetwork::Config["bond0"]]
    }
}

class task_ms1__litpnetwork_3a_3aroute__reload__ms1__route__reload(){
    litpnetwork::route_reload { "ms1_route_reload":
devices => [
        "bond0"
        ]
,
        subscribe => [Litpnetwork::Route["bond0_routes"]]
    }
}


node "ms1" {

    class {'litp::ms_node':}


    class {'task_ms1__litpnetwork_3a_3aconfig__bond0':
    }


    class {'task_ms1__litpnetwork_3a_3aconfig__bond0_2e123':
    }


    class {'task_ms1__litpnetwork_3a_3aconfig__eth11':
    }


    class {'task_ms1__litpnetwork_3a_3aconfig__eth20':
    }


    class {'task_ms1__litpnetwork_3a_3aroute__bond0__routes':
    }


    class {'task_ms1__litpnetwork_3a_3aroute__reload__ms1__route__reload':
    }


}
