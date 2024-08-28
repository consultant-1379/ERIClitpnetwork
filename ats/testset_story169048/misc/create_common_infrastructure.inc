litp create -t storage-profile-base -p /infrastructure/storage/storage_profiles/profile_1
litp create -t system -p /infrastructure/systems/s1 -o system_name=MN1
litp create -t os-profile -p /software/profiles/rhel_6_4 -o name=sample-profile version=rhel6 path=/profiles/node-iso/ arch=x86_64 breed=redhat
litp create -t network -p /infrastructure/networking/networks/n1 -o name=internal subnet="192.168.0.0/24" litp_management=true