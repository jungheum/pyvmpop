@echo off
:: Reference - https://www.virtualbox.org/manual/ch08.html#vboxmanage-startvm

:: Import a VM using an OVA file from Microsoft
set vmname="Win_7_IE09_(CFReDS)"
set image="D:\IE9 - Win7.ova"
set cpus=2
set memory=1024
VBoxManage import %image% --vsys 0 --vmname %vmname% --cpus %cpus% --memory %memory%

:: Set configutations: audio (hda), network (nat) and usb (2.0)
set natname="NatCFReDS"
VBoxManage modifyvm %vmname% --audio dsound  --audiocontroller hda --nic1 natnetwork --nat-network1 %natname% --nicpromisc1 allow-vms --usbehci on

VBoxManage startvm %vmname%
pause

:: Install Guest Additions by manual

VBoxManage controlvm %vmname% acpipowerbutton
pause

:: Set the second IDE drive (DVD) to empty
VBoxManage storageattach %vmname% --storagectl "IDE" --port 1 --device 0 --medium emptydrive

VBoxManage snapshot %vmname% take "Snapshot 1" --description "init"
