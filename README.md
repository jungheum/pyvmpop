# pyvmpop

A Python implementation of VMPOP (Virtual Machine POPulation) framework


## Installation

Install the latest version:

	$ git clone https://github.com/jungheum/pyvmpop
	$ cd pyvmpop
	$ python setup.py install

Requirements:

* [pyvbox](https://github.com/mjdorma/pyvbox) to enable a Virtual Machine Interface Module for VirtualBox
* [dfVFS](https://github.com/log2timeline/dfvfs) to enable for Data Extraction features
	
	
## Examples

### (1) \example\simple-win\

#### Tested Environment
	
* Windows 7 Enterprise (SP1)
* VirtualBox v5.1.26
* A virtual machine image (Windows 10 RS3 preview 16257) from [Microsoft](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)
* The virtual machine was imported to the VirtualBox hypervisor for executing the example. (Refer to \example\simple_win\import_vm_using_vboxmanage_(Win10RS3_16257).bat)

#### Excerpts from `simple-win.py`

Create a VmPop instance and configure basic options:

	from pyvmpop.vmpop import VmPop
	from pyvmpop.common_defines import *
	from pyvmpop.utility.pt_utils import PtUtils
	
	vm_name = "Win10RS3_16257"

	d, t = PtUtils.get_current_date_and_time()
	log_dir = ".\\[{}_{}]_{}".format(d, t.replace(":", "."), vm_name)
	shared_dir = "..\\..\\resource"

	vmpop = VmPop()
	vmpop.basic_config(
		hv_type=VmPopHypervisor.VBOX, os_type=VmPopOSType.Windows10_64,
		start_mode=VmPopStartMode.CLONE_LINKED, shared_dir=shared_dir, log_dir=log_dir
	)

	# Uncomment the below line for disabling the event monitoring
	# vmpop.automation.switch_for_event_monitor(condition=False)

Start VM and logon with the default account:
	
	mpop.connect_to_vm(vm_name=vm_name, user_id=default_id, password=default_pw)

	vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="Select 'CFTT' account")
	vmpop.automation.logon_account('IEUser', 'Passw0rd!')  # Logon  'IEUser' account

Launch the Edge browser	and visit a web-site:

	# Set the configuration for Edge
	edge = ("shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge",
			"C:\\Windows\\SystemApps\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\MicrosoftEdge.exe",
			VmPopWebBrowser.EDGE,
			False)

	# Launch a browser and use it
	ret, pid = vmpop.automation.launch_program(path_file=edge[0], path_target=edge[1], focus_to_pid=True)
	if ret is True:
		vmpop.automation.set_foreground_window(window_title="Edge")
		vmpop.automation.maximize_window()

		# Create a new tab
		vmpop.automation.control_web_browser(action=VmPopWebAction.NEW_TAB, browser=edge[2], evtlog_off=True)

		# Visit a web-site
		vmpop.automation.control_web_browser(
			action=VmPopWebAction.VISIT_URL, browser=edge[2], argument1="www.cfreds.nist.gov"
		)

		# Terminate this application
		vmpop.automation.terminate_process(pid=pid)
	
Create a shadow copy and shutdown the system:

	# Create a restore point
	vmpop.automation.create_restore_point(
		drive="C:\\", description="an example of restore point",
		rp_type=VmPopRPType.MODIFY_SETTINGS
	)

	# Shutdown the system
	vmpop.automation.shutdown(VmPopFunctionMode.HV)

	# Close the VmPop instance
	vmpop.close()
	
#### Results

The results were created on the log directory (\example\simple-win\\[2017-09-15_10.48.33]_Win10RS3_16257\\)

* 1 action log
* 5 event logs
* 1 screen capture

	
### (2) \example\cfreds-2017-winreg\

A VMPOP scenario to develop a system-generated registry dataset

#### Tested Environment
	
* Six virtual machine images (Vista, 7, 8, 8.1, 10 and 10RS1) from [Microsoft](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)
* Virtual machines were imported to the VirtualBox, and then configured according to assistance scripts. (Refer to \example\cfreds-2017-winreg\building_virtualbox_environment\\)

#### Details on the scenario and resources

* [NIST/CFReDS](https://www.cfreds.nist.gov)
* [Assistance tools for cfreds-2017-winreg](https://github.com/jungheum/cfreds-2017-winreg)


## License

Apache License 2.0


## Feedback

Please submit feedback via the pyvmpop [tracker](http://github.com/jungheum/pyvmpop/issues).

