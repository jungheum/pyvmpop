@echo off
:: Reference - https://www.virtualbox.org/manual/ch08.html#vboxmanage-startvm

:: Create a new NAT network
VBoxManage natnetwork add --netname NatCFReDS --network "10.11.11.0/24" --enable

