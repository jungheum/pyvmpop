"""VmPopScenarioSimpleWindows

    * Description
        A simple example using the VMPOP package

    * Authors
        Jungheum Park <jungheum.park@nist.gov> & <junghmi@gmail.com>

    * License
        Apache License 2.0

    * Scenario
        -----------------------------------------------
        - Register a VM (Win10RS3_16257) to VirtualBox
          --> Pre-requirement
        -----------------------------------------------
        - Start VM
        - Logon the default account (IEUser)
        - Set the resolution
        - Disable UAC and Windows update
        - Restart the system
        - Logon the default account (IEUser)
        -----------------------------------------------
        - Launch 'Edge'
        - Visit 'cfreds.nist.gov'
        -----------------------------------------------
        - Launch 'notepad' through Windows Run
        - Write something, and save as the file
        -----------------------------------------------
        - Create a restore point
        - Shutdown
        -----------------------------------------------
"""

from pyvmpop.vmpop import VmPop
from pyvmpop.common_defines import *
from pyvmpop.utility.pt_utils import PtUtils

vm_name = "Win10RS3_16257"
default_id = "IEUser"
default_pw = "Passw0rd!"

d, t = PtUtils.get_current_date_and_time()
log_dir = ".\\[{}_{}]_{}".format(d, t.replace(":", "."), vm_name)
shared_dir = "..\\..\\resource"

# Create a VmPop instance and configure basic options
vmpop = VmPop()
vmpop.basic_config(
    hv_type=VmPopHypervisor.VBOX, os_type=VmPopOSType.Windows10_64,
    start_mode=VmPopStartMode.CLONE_LINKED, shared_dir=shared_dir, log_dir=log_dir
)

# Uncomment the below line for disabling the event monitoring
# vmpop.automation.switch_for_event_monitor(condition=False)

# Start VM and logon with the default account
vmpop.connect_to_vm(vm_name=vm_name, user_id=default_id, password=default_pw)

# Logon the default account
vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="Select 'CFTT' account")
vmpop.automation.logon_account(default_id, default_pw)  # Logon  'IEUser' account

# Set the resolution
vmpop.hypervisor.set_resolution(width=1024, height=768)

# Disable UAC
vmpop.automation.disable_uac(wait_s_for_window=15)
vmpop.hypervisor.send_event_keyboard(['ESC'], delay_s=1.0)
vmpop.automation.disable_uac(wait_s_for_window=10)  # Double-check

# Disable Windows update
vmpop.automation.disable_windows_update()

# Restart the system & Restore the user session
vmpop.automation.restart(mode=VmPopFunctionMode.HV)

# Logon the default account
vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Select 'CFTT' account")
vmpop.automation.logon_account(default_id, default_pw)  # Logon  'IEUser' account

vmpop.hypervisor.start_video_capturing("{}.webm".format(vm_name))

"""------------------------------------------
- Launch 'Edge'
- Visit 'cfreds.nist.gov'
------------------------------------------"""
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

"""------------------------------------------
- Launch 'notepad' through Windows Run
- Write something, and save as the file
------------------------------------------"""
filename = "VMPOP_example"

# Start of the event monitor
vmpop.automation.evtmon.start("Creating a text file \'{}\'".format(filename))

# Launch 'Notepad.exe' through Windows Run
vmpop.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.5, note="Windows Run")
vmpop.hypervisor.send_event_keyboard("notepad", delay_s=1.0)
vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Launch Notepad.exe")

# Write something
msg = "This is an example implementation using VMPOP.\n\n\nLet's save this text file."
vmpop.hypervisor.send_event_keyboard(msg, delay_s=1.5)

# Save it and close the process
vmpop.hypervisor.send_event_keyboard('s', ['CTRL'], delay_s=1.5, note="Save As")
vmpop.hypervisor.send_event_keyboard("{}".format(filename), delay_s=1.0)
vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Save a text file")
vmpop.automation.close_window()

# End of the event monitor
vmpop.automation.evtmon.stop()

# Create a restore point
vmpop.automation.create_restore_point(
    drive="C:\\", description="an example of restore point",
    rp_type=VmPopRPType.MODIFY_SETTINGS
)

# Shutdown the system
vmpop.automation.shutdown(VmPopFunctionMode.HV)

# Close the VmPop instance
vmpop.close()
