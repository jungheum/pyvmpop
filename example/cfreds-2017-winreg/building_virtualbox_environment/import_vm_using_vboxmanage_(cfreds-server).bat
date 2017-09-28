@echo off
:: Reference - https://www.virtualbox.org/manual/ch08.html#vboxmanage-startvm

:: Import a VM using an OVA file from Microsoft
set vmname="cfreds-server"
set image="D:\Win10RS1_14393_IE11+Edge.ova"
set cpus=1
set memory=1024
VBoxManage import %image% --vsys 0 --vmname %vmname% --cpus %cpus% --memory %memory%

:: Set configutations: audio (hda), network (nat) and usb (3.0)
set natname="NatCFReDS"
VBoxManage modifyvm %vmname% --audio dsound  --audiocontroller hda --nic1 natnetwork --nat-network1 %natname% --nicpromisc1 allow-vms --usbxhci on

VBoxManage modifyvm %vmname% --clipboard hosttoguest
VBoxManage modifyvm %vmname% --draganddrop  hosttoguest
VBoxManage startvm %vmname%
pause
VBoxManage controlvm %vmname% setvideomodehint 1024 768 32
pause

:: Disable Windows Update
	REM $WindowsPolicies = "HKLM:\SOFTWARE\Policies\Microsoft\Windows"
	REM New-Item -Path $WindowsPolicies -Name WindowsUpdate
	REM New-Item -Path $WindowsPolicies\WindowsUpdate -Name AU
	REM Set-ItemProperty -Path $WindowsPolicies\WindowsUpdate\AU -Name NoAutoUpdate -Value 1

:: Disable turn off of monitor and hdd

:: Set NIC IP(10.11.11.127) DNS(8.8.8.8 / 8.8.4.4)

:: Add an admin account (cfreds-server1 / cs1nist)
	REM net user "cfreds-server1" "cs1nist" /add
	REM net localgroup Administrator "cfreds-server1" /add

:: Log on 'cfreds-server1'
	REM shutdown.exe -l

:: Copy reference files to Desktop

:: Set a shared directory at Desktop (\\\\10.11.11.127\\NETWORK_DIR)

:: Set remote desktop

pause
VBoxManage controlvm %vmname% acpipowerbutton
pause

:: Set the second IDE drive (DVD) to empty
VBoxManage storageattach %vmname% --storagectl "IDE Controller" --port 1 --device 0 --medium emptydrive

VBoxManage snapshot %vmname% take "Snapshot 1" --description "init"
