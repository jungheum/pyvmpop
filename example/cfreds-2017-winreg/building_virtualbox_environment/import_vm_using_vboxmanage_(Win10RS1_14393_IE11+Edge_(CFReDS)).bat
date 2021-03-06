@echo off
:: Reference - https://www.virtualbox.org/manual/ch08.html#vboxmanage-startvm

:: Import a VM using an OVA file from Microsoft
set vmname="Win10RS1_14393_IE11+Edge_(CFReDS)"
set image="D:\Win10RS1_14393_IE11+Edge.ova"
set cpus=2
set memory=2048
VBoxManage import %image% --vsys 0 --vmname %vmname% --cpus %cpus% --memory %memory%

:: Set configutations: audio (hda), network (nat) and usb (3.0)
set natname="NatCFReDS"
VBoxManage modifyvm %vmname% --audio dsound  --audiocontroller hda --nic1 natnetwork --nat-network1 %natname% --nicpromisc1 allow-vms --usbxhci on

:: Add a new SATA controller
VBoxManage storagectl %vmname% --name "SATA" --add SATA

:: Add an existing disk to SATA 0,0
set disk="C:\pyvmpop\example\cfreds-2017-winreg\cfreds_2017_winreg_tiny_disk.vmdk"
VBoxManage storageattach %vmname% --storagectl "SATA" --port 0 --device 0 --type HDD --medium %disk%

VBoxManage startvm %vmname%
pause

:: Install Guest Additions by manual

VBoxManage controlvm %vmname% acpipowerbutton
pause

:: Set the second IDE drive (DVD) to empty
VBoxManage storageattach %vmname% --storagectl "IDE Controller" --port 1 --device 0 --medium emptydrive

VBoxManage snapshot %vmname% take "Snapshot 1" --description "init"
