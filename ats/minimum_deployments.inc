litp create -t os-profile -p /software/profiles/rhel_6_4 -o name=sample-profile version=rhel6 path=/profiles/node-iso/ arch=x86_64 breed=redhat

litp create -t storage-profile-base -p /infrastructure/storage/storage_profiles/profile_1
litp create -t network -p /infrastructure/networking/networks/n1 -o name=mgmt subnet="192.168.0.0/24" litp_management=true
litp create -t network -p /infrastructure/networking/networks/n2 -o name=stream subnet="10.0.0.0/24" litp_management=false
litp create -t route -p /infrastructure/networking/routes/r1 -o subnet="0.0.0.0/0" gateway="10.0.0.254"

litp create -t deployment -p /deployments/d1
litp create -t cluster -p /deployments/d1/clusters/c1

litp create -t system -p /infrastructure/systems/s1 -o system_name=MN1
litp create -t node -p /deployments/d1/clusters/c1/nodes/n1 -o hostname=node1
litp inherit -p /deployments/d1/clusters/c1/nodes/n1/system -s /infrastructure/systems/s1
litp inherit -p /deployments/d1/clusters/c1/nodes/n1/os -s /software/profiles/rhel_6_4
litp inherit -p /deployments/d1/clusters/c1/nodes/n1/storage_profile -s /infrastructure/storage/storage_profiles/profile_1
litp inherit -p /deployments/d1/clusters/c1/nodes/n1/routes/r1 -s /infrastructure/networking/routes/r1
litp create -t eth -p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/eth9 -o device_name=eth9 macaddress=00:00:00:00:00:01 network_name=mgmt ipaddress=192.168.0.1

litp inherit -p /ms/routes/r1 -s /infrastructure/networking/routes/r1
litp create -t eth -p /ms/network_interfaces/if0 -o device_name=eth0 macaddress=DE:AD:BE:EF:13:39 ipaddress=192.168.0.111 network_name=mgmt

litp create -t eth -p /ms/network_interfaces/if1 -o device_name=vnet0 macaddress=DE:AD:BE:EF:13:45 network_name=stream ipaddress=10.0.0.3

litp create -p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/if0 -t eth    -o device_name=eth0  macaddress=DE:AD:BE:EF:13:37 bridge=brMS_VM_bridge
