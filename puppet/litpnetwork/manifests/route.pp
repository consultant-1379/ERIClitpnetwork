# This define manages routes.
define litpnetwork::route ($device = $name, $address = undef, $netmask = undef, $gateway = undef,
                        $family = undef, $ensure='present', $node_name = undef)
{

include ::network
  network::route { $device:
    ensure    => $ensure,
    ipaddress => $address,
    netmask   => $netmask,
    gateway   => $gateway,
    family    => $family,
  }
}

# This define loads routes.
define route_load
{
  exec { "load_routes_for_${name}":
    path    => '/usr/bin:/bin:/sbin:/usr/sbin',
    command => 'ip route list 0/0 && ip -6 route list default',
    unless  => "/etc/sysconfig/network-scripts/ifup-routes ${name}",
  }
}

# This define reloads routes.
define litpnetwork::route_reload($devices = undef)
{

  exec { 'remove_all_routes':
    path        => '/usr/bin:/bin:/sbin:/usr/sbin',
    command     => 'ip route flush scope global && ip -6 route flush proto boot',
    refreshonly => true,
  }

  route_load { $devices:
    require => Exec[remove_all_routes],
  }
}
