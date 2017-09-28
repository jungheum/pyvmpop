@echo off
:: Reference - https://www.virtualbox.org/manual/ch08.html#vboxmanage-startvm

:: Import a VM using an OVA file from Microsoft
set vmname="Vista_IE07_(CFReDS)"
set image="D:\IE7 - Vista.ova"
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

:: Set 32 bits
