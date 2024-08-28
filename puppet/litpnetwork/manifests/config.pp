# This define manages interfaces.
define litpnetwork::config ($device = $name, $bootproto = 'static', $broadcast = undef, $ensure = 'present',
                        $ipaddr = undef, $netmask = undef, $network = undef, $nozeroconf = undef,
                        $onboot = undef, $userctl = undef, $hwaddr = undef,
                        $prefix = undef, $ipv6addr = undef, $ipv6_defaultgw = undef, $ipv6init = undef, $ipv6_autoconf = undef,
                        $domain = undef, $bridge = undef, $stp = undef, $delay = undef, $bridging_opts = undef, $peerdns = undef,
                        $dns1 = undef, $dns2 = undef, $type = undef, $vlan = undef, $bonding_opts = undef, $arp_ip_targets_to_clean = undef,
                        $master = undef, $slave = undef, $required_device = undef, $is_mgmt_if = undef,
                        $before_device = undef, $hotplug = undef, $vlans_on_bond = undef, $ethtool_opts = undef,
                        $primary_cleaning = undef, $txqueuelen = undef, $nm_controlled = 'no')
{
    include ::network

    # If this is a VLAN tagged interface, sleep between ifdown and ifup
    # to prevent known bug in RH: https://bugzilla.redhat.com/show_bug.cgi?id=855107
    # Bonds need time to be fully activated so sleep for 60 seconds
    if $vlan == 'yes' {
        $sleep = 1
    } elsif $type == 'Bonding' {
        $sleep = 60
    } else {
        $sleep = 2
    }

    $sys_net_dir = '/sys/class/net'

    if $ensure == 'present' {
        #Note, this is not checking whether the interface is a Bridge item type.
        #It is checking whether the interface(Eth, Bond or Vlan) has a bridge attribute defined.
        if ($bridge)
        {
            if ($is_mgmt_if == 'true')
            {
                if $arp_ip_targets_to_clean and $primary_cleaning == 'true'
                {
                    $notify = [Exec["clean_arp_ip_targets_${device}"],
                                Exec["clean_primary_${device}"],
                                Exec["wait_for_parent_bridge_${device}"],
                                Service['mcollective']]
                }
                elsif $primary_cleaning == 'true'
                {
                    $notify = [Exec["clean_primary_${device}"],
                                Exec["wait_for_parent_bridge_${device}"],
                                Service['mcollective']]
                }
                elsif $arp_ip_targets_to_clean
                {
                    $notify = [Exec["clean_arp_ip_targets_${device}"],
                                Exec["wait_for_parent_bridge_${device}"],
                                Service['mcollective']]
                }
                else
                {
                    $notify = [Exec["wait_for_parent_bridge_${device}"],
                                Service['mcollective']]
                }
            }
            else
            {
                if $arp_ip_targets_to_clean and $primary_cleaning == 'true'
                {
                    $notify = [Exec["clean_arp_ip_targets_${device}"],
                                Exec["clean_primary_${device}"],
                                Exec["wait_for_parent_bridge_${device}"]]
                }
                elsif $primary_cleaning == 'true'
                {
                    $notify = [Exec["clean_primary_${device}"],
                                Exec["wait_for_parent_bridge_${device}"]]
                }
                elsif $arp_ip_targets_to_clean
                {
                    $notify = [Exec["clean_arp_ip_targets_${device}"],
                                Exec["wait_for_parent_bridge_${device}"]]
                }
                else
                {
                    $notify = Exec["wait_for_parent_bridge_${device}"]
                }
            }
        #Case where interface does not have a bridge attribute defined
        } else {
            if ($vlans_on_bond) {
                  $notify_vlans_tagged_on_bond = Exec["restart_all_${vlans_on_bond}"]
            }

            if ($is_mgmt_if == 'true') {
                if $type == 'Bonding' and ($arp_ip_targets_to_clean or $primary_cleaning == 'true') {
                    if $arp_ip_targets_to_clean and $primary_cleaning == 'true'
                    {
                        $notify = [Exec["clean_arp_ip_targets_${device}"],
                                    Exec["clean_primary_${device}"],
                                    Exec["restart_${device}"],
                                    Service['mcollective']]
                    }
                    elsif $primary_cleaning == 'true'
                    {
                        $notify = [Exec["clean_primary_${device}"],
                                    Exec["restart_${device}"],
                                    Service['mcollective']]
                    }
                    elsif $arp_ip_targets_to_clean
                    {
                        $notify = [Exec["clean_arp_ip_targets_${device}"],
                                    Exec["restart_${device}"],
                                    Service['mcollective']]
                    }
                } else {
                    $notify = [Exec["restart_${device}"],
                                Service['mcollective']]
                }
            } else {
                if $type == 'Bonding' and ($arp_ip_targets_to_clean or $primary_cleaning == 'true')
                {
                    if $arp_ip_targets_to_clean and $primary_cleaning == 'true'
                    {
                        $notify = [Exec["clean_arp_ip_targets_${device}"],
                                    Exec["clean_primary_${device}"],
                                    Exec["restart_${device}"]]
                    }
                    elsif $arp_ip_targets_to_clean
                    {
                        $notify = [Exec["clean_arp_ip_targets_${device}"],
                                    Exec["restart_${device}"]]
                    }
                    elsif $primary_cleaning == 'true'
                    {
                        $notify = [Exec["clean_primary_${device}"],
                                    Exec["restart_${device}"]]
                    }
                } else {
                    $notify = Exec["restart_${device}"]
                }
            }
        }

        if $type == 'Bridge' or $vlan == 'yes' or $type == 'Bonding' {
            # Params for Bridge, VLAN & Bond devices

            if $vlan == 'yes' or $type == 'Bonding' {
                $require_config = [Exec["modprobe_bonding_max_bonds_${device}"],
                                    Exec["exists_virtual_${device}"],
                                    Litpnetwork::Config[$required_device],
                                    Exec["refresh_${device}"]]
                if $before_device {
                    $before_config = Litpnetwork::Config[$before_device]
                }
            } elsif $type == 'Bridge' {
                if $before_device {
                    if ($is_mgmt_if == 'true') {
                        $before_config = undef
                        $require_config = [Exec["modprobe_bonding_max_bonds_${device}"],
                                            Litpnetwork::Config[$before_device],
                                            Exec["restart_${before_device}"],
                                            Exec["refresh_${device}"]]
                    } else {
                        $before_config = Litpnetwork::Config[$before_device]
                        $require_config = [Exec["modprobe_bonding_max_bonds_${device}"],
                                            Exec["exists_virtual_${device}"],
                                            Exec["refresh_${device}"]]
                    }
                } else {
                  $before_config = undef
                  $require_config = [Exec["modprobe_bonding_max_bonds_${device}"],
                                      Exec["exists_virtual_${device}"],
                                      Exec["refresh_${device}"]]
                }
            }
            $require_ifup = Network::Interface[$device]
        } else {
            # Params for Eth device
            $require_config = [Exec["modprobe_bonding_max_bonds_${device}"],
                                Exec["exists_${device}"],
                                Exec["refresh_${device}"]]
            $require_ifup = [Network::Interface[$device],
                              Exec["exists_${device}"]]
            if $before_device {
                $before_config = Litpnetwork::Config[$before_device]
            }
        }

        # Ensure the device is up in case brought down manually
        if $master == undef {
            exec { "ifup_${device}":
                command => "ifup ${device} || (ip link set ${device} down && false)",
                path    => '/bin:/sbin:/usr/bin:/usr/sbin',
                require => $require_ifup,
                unless  => "ip link show ${device} | grep -o '<.*>' | grep -w UP",
            }
        } else {
            exec { "ifup_${device}":
                command => "ifup ${device} || (ip link set ${device} down && false)",
                path    => '/bin:/sbin:/usr/bin:/usr/sbin',
                require => $require_ifup,
                unless  => "ip link show ${device} | grep -o '<.*>' | grep -w UP && grep ${device} ${sys_net_dir}/${master}/bonding/slaves",
            }
        }
    }

    $net_scripts_path = '/etc/sysconfig/network-scripts'

    # Removes the ifcfg file for ${device} so network_config is executed and
    # device restart is attempted.
    # This is better done with File, but that one does not have "refreshonly" metaparam.
    exec { "refresh_${device}":
        command     => "rm -f ${net_scripts_path}/ifcfg-${device} && ip link set ${device} down",
        path        => '/bin:/sbin:/usr/bin:/usr/sbin',
        refreshonly => true,
    }


    network::interface {  $device:
        ensure         => $ensure,
        bootproto      => $bootproto,
        broadcast      => $broadcast,
        device         => $device,
        ipaddr         => $ipaddr,
        netmask        => $netmask,
        network        => $network,
        notify         => $notify,
        require        => $require_config,
        before         => $before_config,
        nozeroconf     => $nozeroconf,
        onboot         => $onboot,
        userctl        => $userctl,
        hwaddr         => $hwaddr,
        prefix         => $prefix,
        ipv6addr       => $ipv6addr,
        ipv6_autoconf  => $ipv6_autoconf,
        ipv6_defaultgw => $ipv6_defaultgw,
        ipv6init       => $ipv6init,
        domain         => $domain,
        bridge         => $bridge,
        bridge_stp     => $stp,
        delay          => $delay,
        bridging_opts  => $bridging_opts,
        peerdns        => $peerdns,
        dns1           => $dns1,
        dns2           => $dns2,
        type           => $type,
        vlan           => $vlan,
        bonding_opts   => $bonding_opts,
        hotplug        => $hotplug,
        master         => $master,
        slave          => $slave,
        ethtool_opts   => $ethtool_opts,
        nm_controlled  => $nm_controlled,
    }

    if $type != 'Bridge' and $type != 'Bonding' and $vlan != 'yes' {
      if $txqueuelen {
        exec { "txqueuelen_${device}":
          unless  => "grep -qw ${txqueuelen} /sys/class/net/${device}/tx_queue_len",
          path    => '/bin:/sbin:/usr/bin:/usr/sbin',
          command => "ip link set ${device} txqueuelen ${txqueuelen}"
        }
      }
    }

    if $vlan == 'yes' {
        $restart_command = "ifdown ${device}; sleep ${sleep}; ifup ${device} || (ip link set ${device} down && false)"
    } else {
        $restart_command = "ifdown ${device}; sleep 1; (ifup ${device} || (ip link set ${device} down && false)) && sleep ${sleep}"
    }

    exec { "restart_${device}":
        command     => $restart_command,
        path        => '/bin:/sbin:/usr/bin:/usr/sbin',
        refreshonly => true,
        notify      => $notify_vlans_tagged_on_bond,
        require     => $require_config,
    }

    if $type == 'Bonding' and $vlans_on_bond {
        exec { "restart_all_${vlans_on_bond}":
            command     => "for vlan in ${vlans_on_bond}; do ifdown \$vlan; done; sleep 3;
            for vlan in ${vlans_on_bond}; do ifup \$vlan; done",
            onlyif      => "ip link show ${device} up | grep -w 'UP'",
            path        => '/bin:/sbin:/usr/bin:/usr/sbin',
            provider    => shell,
            refreshonly => true,
        }
    }

    if $type == 'Bonding' and $arp_ip_targets_to_clean {
        $targets_file = "${sys_net_dir}/${device}/bonding/arp_ip_target"

        if $arp_ip_targets_to_clean == 'ALL'{
          $clean_cmd = "declare -i errors=0; for x in \$(cat ${targets_file});
          do echo -\$x > ${targets_file}; errors+=\$?; done; exit \$errors"
        } else {
          $clean_cmd = "declare -i errors=0; for ip in ${arp_ip_targets_to_clean}; do if grep -qw \$ip ${targets_file};
          then echo -\$ip > ${targets_file}; errors+=\$?; fi; done; exit \$errors"
        }

        exec { "clean_arp_ip_targets_${device}":
              command     => $clean_cmd,
              path        => '/bin:/sbin:/usr/bin:/usr/sbin',
              provider    => shell,
              refreshonly => true,
              before      => Exec["restart_${device}"],
              onlyif      => ["test -f ${targets_file}"],
        }
    }

    if $type == 'Bonding' and $primary_cleaning == 'true' {
        $dev_bonding_dir = "${sys_net_dir}/${device}/bonding"
        $pfile1 = "${dev_bonding_dir}/primary"
        $pfile2 = "${dev_bonding_dir}/primary_reselect"

        $clean_cmd_pri = "declare -i errors=0; echo '' > ${pfile1}; errors+=\$?; echo 'always 0' > ${pfile2}; errors+=\$?; exit \$errors"

        exec { "clean_primary_${device}":
              command     => $clean_cmd_pri,
              path        => '/bin:/sbin:/usr/bin:/usr/sbin',
              provider    => shell,
              refreshonly => true,
              before      => Exec["restart_${device}"],
              onlyif      => ["test -f ${pfile1}", "test -f ${pfile2}"],
        }
    }

    if $type != 'Bridge' and $vlan != 'yes' and $type != 'Bonding' {
        exec { "exists_${device}":
          command => "ls ${sys_net_dir}/${device}",
          path    => '/bin:/sbin:/usr/bin:/usr/sbin',
          unless  => "ip addr show ${device}",
        }
    } else {
        exec { "exists_virtual_${device}":
          command => 'true',
          path    => '/bin:/sbin:/usr/bin:/usr/sbin',
          unless  => "ip addr show ${device}",
        }
    }

    if $type != 'Bridge' and $vlan != 'yes' and $type != 'Bonding' {
        if $master {
            exec { "remove_old_config_${device}":
              command  => "for d in ${sys_net_dir}/${device}.*; do ifdown $(basename \$d);
              rm -f ${net_scripts_path}/ifcfg-$(basename \$d); done",
              path     => '/usr/bin/sh:/bin:/sbin:/usr/bin:/usr/sbin',
              provider => shell,
              onlyif   => "ip a | /bin/grep ${device}'\\.'",
            }
        }
    }

    exec { "wait_for_parent_bridge_${device}":
        command     => 'ip route list 0/0  && ip -6 route list default',
        path        => '/bin:/sbin:/usr/bin:/usr/sbin',
        onlyif      => "ip link show ${bridge} up | grep -w 'UP'",
        refreshonly => true,
        notify      => Exec["restart_${device}"],
    }

    $modprobe_local_conf = '/etc/modprobe.d/local-litp-network-options.conf'
    exec { "modprobe_bonding_max_bonds_${device}":
        command => "echo 'options bonding max_bonds=0' > ${modprobe_local_conf} && chmod 644 ${modprobe_local_conf}",
        path    => '/bin:/sbin:/usr/bin:/usr/sbin',
        onlyif  => ["test ! -f ${modprobe_local_conf}"],
    }
}
