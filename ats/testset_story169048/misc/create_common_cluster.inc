litp create -t eth -p /ms/network_interfaces/eth0 -o device_name=eth0 macaddress=DE:AD:BE:EF:13:39 ipaddress=192.168.0.111 network_name=internal

litp create -t deployment -p /deployments/d1
litp create -t cluster -p /deployments/d1/clusters/c1
litp create -t node -p /deployments/d1/clusters/c1/nodes/n1 -o hostname=node1
litp inherit -p /deployments/d1/clusters/c1/nodes/n1/storage_profile -s /infrastructure/storage/storage_profiles/profile_1
litp inherit -p /deployments/d1/clusters/c1/nodes/n1/system -s /infrastructure/systems/s1
litp inherit -p /deployments/d1/clusters/c1/nodes/n1/os -s /software/profiles/rhel_6_4

litp create -t eth -p    /deployments/d1/clusters/c1/nodes/n1/network_interfaces/eth8  -o device_name=eth8 macaddress=00:00:00:00:00:08 master=bond0
litp create -t eth -p    /deployments/d1/clusters/c1/nodes/n1/network_interfaces/eth9  -o device_name=eth9 macaddress=00:00:00:00:00:09 master=bond0
litp create -t bond -p   /deployments/d1/clusters/c1/nodes/n1/network_interfaces/bond0 -o device_name=bond0 mode=1 miimon=100 bridge=br1
litp create -t bridge -p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/br1   -o device_name=br1   network_name=internal ipaddress=192.168.0.42

litp create -t eth -p    /deployments/d1/clusters/c1/nodes/n1/network_interfaces/eth0  -o device_name=eth0 macaddress=00:00:00:00:00:01 pxe_boot_only=true