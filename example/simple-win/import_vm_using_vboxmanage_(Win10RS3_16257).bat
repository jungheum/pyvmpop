@echo off
:: Reference - https://www.virtualbox.org/manual/ch08.html#vboxmanage-startvm

:: Import a VM using an OVA file from Microsoft
set vmname="Win10RS3_16257"
set image="D:\[Build.20170804].MSEdge.Win10_RS3.Preview.16.16257.VirtualBox\MSEdge - Win10_preview.ova"
set cpus=4
set memory=4096
VBoxManage import %image% --vsys 0 --vmname %vmname% --cpus %cpus% --memory %memory%

:: Set configutations: audio (hda), network (nat) and usb (3.0)
VBoxManage modifyvm %vmname% --audio dsound  --audiocontroller hda --nic1 nat --nicpromisc1 allow-vms --usbxhci on

:: Take a snapshot
VBoxManage snapshot %vmname% take "Snapshot 1" --description "init"
