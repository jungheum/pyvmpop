"""VmPopScenarioCFReDS2017WinReg

    * Description
        VmPopScenario: cfreds-2017-winreg
            - A VMPOP scenario for generating reference Windows registry hives
            - Example implementation using VMPOP framework

    * Authors
        Jungheum Park <jungheum.park@nist.gov> & <junghmi@gmail.com>

    * Related Projects @ NIST
        - CFTT   (Computer Forensic Tool Testing)         www.cftt.nist.gov
        - CFReDS (Computer Forensic Reference Data Sets)  www.cfreds.nist.gov

    * License
        Apache License 2.0
"""

import os
import time
import traceback
from pyvmpop.vmpop import VmPop
from pyvmpop.common_defines import *
from pyvmpop.utility.pt_utils import PtUtils
from pyvmpop.logging.actlog_manager import ActionItem


VMPOP_DEBUG = False
VMPOP_EXTRACT_ONLY = False


class VmPopScenarioCFReDS2017WinReg:
    """VmPopScenario: cfreds-2017-winreg
    
    """
    def __init__(self):
        """The constructor for defining the common variables
        """
        self.os_list = list()  # (vm_name, VmPopOSType)
        self.os_list.append(("Win10RS1_14393_IE11+Edge_(CFReDS)", VmPopOSType.Windows10_64))
        self.os_list.append(("Win10_10586_IE11+Edge_(CFReDS)", VmPopOSType.Windows10_64))
        self.os_list.append(("Win81_IE11_(CFReDS)", VmPopOSType.Windows81))
        self.os_list.append(("Win_8_IE10_(CFReDS)", VmPopOSType.Windows8))
        self.os_list.append(("Win_7_IE09_(CFReDS)", VmPopOSType.Windows7))
        self.os_list.append(("Vista_IE07_(CFReDS)", VmPopOSType.WindowsVista))
        # self.os_list.append(("WinXP_IE08_(CFReDS)", VmPopOSType.WindowsXP))  # not supported because of procmon.exe

        # The VMs from Microsoft has the default account 'IEUser'
        self.default_id = "IEUser"
        self.default_pw = "Passw0rd!"

        self.shared_dir = "..\\..\\resource"
        self.snapshot_prefix = "[SNAPSHOT]_"

        self.hv_type = VmPopHypervisor.VBOX
        self.hv_start_mode = VmPopStartMode.CLONE_LINKED
        # self.hv_start_mode = VmPopStartMode.CURRENT
        # self.hv_start_mode = VmPopStartMode.SNAPSHOT
        # self.hv_start_mode = VmPopStartMode.CLONE_FULL

        self.rm1 = "4C530012550531106501"  # MBR & NTFS (SanDisk Cruzer Fit 4GB, VID_0781 & PID_5571)
        self.rm2 = "4C530012450531101593"  # MBR & FAT  (SanDisk Cruzer Fit 4GB, VID_0781 & PID_5571)
        self.rm3 = "4C530012230531102000"  # GPT & NTFS (SanDisk Cruzer Fit 4GB, VID_0781 & PID_5571)
        return

    def start(self):
        """Start population processes

            (1) Connecting to a target VM
            (2) Running a vmpop scenario established for this project
            (3) Exporting virtual storages of the target VM to VHD image files
            (4) Extracting forensically interesting data from the exported VHD files
            (5) Go to the 1st step if there exist target VMs to be processed
        """

        for vm_name, os_type in self.os_list:
            # Generate a name for creating a log directory for the current VM
            d, t = PtUtils.get_current_date_and_time()
            t = t.replace(":", ".")
            log_dir = "." if VMPOP_DEBUG is True else ".\\[{}_{}]_{}".format(d, t, vm_name)

            '''
            ======================================================================================
            VmPop (Virtual Machine Population System)
                - Automated reference virtual machine generator
            ======================================================================================
            '''
            vmpop = VmPop()
            if vmpop.basic_config(hv_type=self.hv_type,
                                  os_type=os_type,
                                  start_mode=self.hv_start_mode,
                                  shared_dir=self.shared_dir,
                                  log_dir=log_dir) is False:
                vmpop.close()
                continue

            if VMPOP_EXTRACT_ONLY is False:
                # Populate a VM with defined actions
                if self.scenario(vmpop, vm_name, self.default_id, self.default_pw) is False:
                    vmpop.close()
                    continue

                if VMPOP_DEBUG is True:
                    vmpop.close()
                    continue

                # Export the populated virtual machine as an image file
                # (VHD, RAW, VDI and VMDK are supported by VirtualBox)
                images = list()

                dl = vmpop.hypervisor.get_disk_list()
                if isinstance(dl, list):
                    for d in dl:
                        output_path = log_dir
                        output_path += "\\{}_{}_{}.{}".format(d.get('controller').split(" ", 1)[0],
                                                              d.get('controller_port'),
                                                              d.get('device_slot'),
                                                              VmPopImageFormat.VHD.name)
                        output_path = os.path.abspath(output_path)
                        ret = vmpop.hypervisor.export_disk(d.get('id'), output_path, VmPopImageFormat.VHD)
                        if ret is True:
                            images.append(output_path)

            # Extract forensically interesting data from the image
            if VMPOP_EXTRACT_ONLY is True:
                images = ['']  # set target file paths here

            for image in images:
                if vmpop.extractor.open_image(image) is False:
                    continue

                e_options = (VmPopExtractOption.FILE_WITH_DIR | VmPopExtractOption.FILE_WITHOUT_DIR)
                vmpop.extractor.extract(data_class=[VmPopDataClass.WINDOWS_REGISTRY], e_options=e_options)
                break

            # Close this VmPop instance
            vmpop.close()

        return

    def scenario(self, vmpop, vm_name, user_id, password):
        """Execute all action stages implemented this VmPop Scenario

            AS (Action Stage) 0
                - Pre-requirements for AS 1 to 8

            AS (Action Stage) 1 to 8
                - Reference actions

        Args:
            vmpop (VmPop): The active VmPop instance
            vm_name (str): The name of the target virtual machine
            user_id (str): The user account ID
            password (str): The user account password

        Return:
            True or False
        """
        try:
            if vmpop.connect_to_vm(vm_name=vm_name, user_id=user_id, password=password) is False:
                return False

            vmpop.hypervisor.start_video_capturing("{}.webm".format(vm_name))

            '''
            ================================================================================================
            Windows automation for CFReDS & CFTT - Windows Registry
            ================================================================================================
            '''
            vmpop.prglog_mgr.info("=== ACTION STAGE 0 ===".format())
            vmpop.actlog_mgr.add(ActionItem(desc="[BEGIN] ACTION STAGE 0", note="PRE-REQUIREMENT"))
            self.action_stage_0(vmpop)
            vmpop.actlog_mgr.add(ActionItem(desc="[ END ] ACTION STAGE 0"))

            vmpop.prglog_mgr.info("=== ACTION STAGE 1 ===".format())
            vmpop.actlog_mgr.add(ActionItem(desc="[BEGIN] ACTION STAGE 1", note="OS CONFIGURATION"))
            self.action_stage_1(vmpop)
            vmpop.actlog_mgr.add(ActionItem(desc="[ END ] ACTION STAGE 1"))

            vmpop.prglog_mgr.info("=== ACTION STAGE 2 ===".format())
            vmpop.actlog_mgr.add(ActionItem(desc="[BEGIN] ACTION STAGE 2", note="ACCOUNT"))
            self.action_stage_2(vmpop)
            vmpop.actlog_mgr.add(ActionItem(desc="[ END ] ACTION STAGE 2"))

            vmpop.prglog_mgr.info("=== ACTION STAGE 3 ===".format())
            vmpop.actlog_mgr.add(ActionItem(desc="[BEGIN] ACTION STAGE 3", note="BASIC ACTIONS with EXTERNAL DEVICE"))
            self.action_stage_3(vmpop)
            vmpop.actlog_mgr.add(ActionItem(desc="[ END ] ACTION STAGE 3"))

            vmpop.prglog_mgr.info("=== ACTION STAGE 4 ===".format())
            vmpop.actlog_mgr.add(ActionItem(desc="[BEGIN] ACTION STAGE 4", note="APPLICATION Part I"))
            self.action_stage_4(vmpop)
            vmpop.actlog_mgr.add(ActionItem(desc="[ END ] ACTION STAGE 4"))

            vmpop.prglog_mgr.info("=== ACTION STAGE 5 ===".format())
            vmpop.actlog_mgr.add(ActionItem(desc="[BEGIN] ACTION STAGE 5", note="APPLICATION Part II"))
            self.action_stage_5(vmpop)
            vmpop.actlog_mgr.add(ActionItem(desc="[ END ] ACTION STAGE 5"))

            vmpop.prglog_mgr.info("=== ACTION STAGE 6 ===".format())
            vmpop.actlog_mgr.add(ActionItem(desc="[BEGIN] ACTION STAGE 6", note="SPECIAL FEATURES Part I"))
            self.action_stage_6(vmpop)
            vmpop.actlog_mgr.add(ActionItem(desc="[ END ] ACTION STAGE 6"))

            vmpop.prglog_mgr.info("=== ACTION STAGE 7 ===".format())
            vmpop.actlog_mgr.add(ActionItem(desc="[BEGIN] ACTION STAGE 7", note="SPECIAL FEATURES Part II"))
            self.action_stage_7(vmpop)
            vmpop.actlog_mgr.add(ActionItem(desc="[ END ] ACTION STAGE 7"))

            vmpop.prglog_mgr.info("=== ACTION STAGE 8 ===".format())
            vmpop.actlog_mgr.add(ActionItem(desc="[BEGIN] ACTION STAGE 8", note="ANTI-FORENSICS"))
            self.action_stage_8(vmpop)
            vmpop.actlog_mgr.add(ActionItem(desc="[ END ] ACTION STAGE 8"))

        except:
            print(traceback.format_exc())
            return False
        return True

    def action_stage_0(self, vmpop):
        """PRE-REQUIREMENT

            The VMs from Microsoft has the default account 'IEUser'
                - https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
                - The automatic logon option is enabled by default in Windows Vista or higher
                - The default password is 'Passw0rd!'

            For your information,
            [PS] means that this action is performed using 'PowerShell' script
            [KM] means that this action is performed using 'Keyboard and Mice'

        Args:
            vmpop (VmPop)
        """
        time.sleep(10)  # Wait 10 seconds

        # Check pre-requirements: Hypervisor's Agent
        if vmpop.hypervisor.get_type() == VmPopHypervisor.VBOX:
            if vmpop.hypervisor.check_guest_additions() is False:
                vmpop.prglog_mgr.debug("{}(): Cannot find Guest Additions".format(GET_MY_NAME()))
                return False

        # -------------------------------------------------------------------------
        # [Disable Time Sync. between the host system and VM]
        # Shutdown the system
        vmpop.hypervisor.stop_vm(VmPopStopMode.SHUT_DOWN)

        # Disable Host to Guest timesync
        if vmpop.hypervisor.get_type() == VmPopHypervisor.VBOX:
            arguments = ['setextradata', vmpop.hypervisor.vm_name,
                         "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled", '1']
            vmpop.hypervisor.run_vbox_manage(arguments)

            # If the below command is executed, Windows 10 RS1 does not operate properly
            # arguments = ['setextradata', vmpop.hypervisor.vm_name,
            #              "VBoxInternal/TM/TSCTiedToExecution", '1']
            # vmpop.hypervisor.run_vbox_manage(arguments)

        # Start the system
        vmpop.hypervisor.start_vm()
        # -------------------------------------------------------------------------

        # Wait the system until logon processes are completed
        if VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.restore_user_session()
            vmpop.automation.wait_for_idle(timeout_ms=120000)  # 2m

        # Switch to Desktop
        if VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows8_64.code:
            vmpop.hypervisor.send_event_keyboard('d', ['LWIN'], delay_s=1.0, note="Go to Desktop")

        # Logon the default account (Windows XP or lower)
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN'], note="Select 'IEUser' account")
            vmpop.automation.logon_account(self.default_id, self.default_pw)    # Logon  'IEUser' account

        # Set the resolution
        vmpop.hypervisor.set_resolution(width=1024, height=768)

        # Check pre-requirements: PowerShell & Resource-Kits (Windows XP or lower)
        if vmpop.hypervisor.file_exists(vmpop.automation.path_powershell) is False:
            # Install .NET 2.0 (executable file in the shared directory)
            vmpop.prglog_mgr.info("{}(): Start installing .Net 2.0".format(GET_MY_NAME()))
            path = vmpop.shared_dir_vm + "\\windows\\pre-requirements\\NetFx20SP2_x86.exe"
            args = "/q /norestart"  # MSI
            if vmpop.automation.install_program(
                    path_installer=path, arguments=args, evtlog_off=True
            ) is False:
                return False
            time.sleep(10)

            # Install PowerShell 2.0 (executable file in the shared directory)
            vmpop.prglog_mgr.info("{}(): Start installing PowerShell 2.0".format(GET_MY_NAME()))
            path = vmpop.shared_dir_vm + "\\windows\\pre-requirements\\WindowsXP-KB968930-x86-ENG.exe"
            args = "/quiet /passive /norestart"  # MSI
            if vmpop.automation.install_program(
                    path_installer=path, arguments=args,
                    path_executable=vmpop.automation.path_powershell, evtlog_off=True
            ) is False:
                return False
            time.sleep(10)

            # Install resource kits (executable file in the shared directory)
            vmpop.prglog_mgr.info("{}(): Start installing resource kits".format(GET_MY_NAME()))
            path = vmpop.shared_dir_vm + "\\windows\\pre-requirements\\rktools.msi"
            args = "/q /norestart"  # MSI
            if vmpop.automation.install_program(
                    path_installer=path, arguments=args, evtlog_off=True
            ) is False:
                return False

            # Restart the system
            vmpop.automation.restart(mode=VmPopFunctionMode.HV)

            # Logon the default account
            if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
                vmpop.hypervisor.send_event_keyboard(['DOWN'], note="Select 'IEUser' account")
                vmpop.automation.logon_account(self.default_id, self.default_pw)  # Logon  'IEUser' account
            else:
                vmpop.hypervisor.restore_user_session()
                vmpop.automation.wait_for_idle(timeout_ms=120000)  # 2m

        # Disable UAC (only Vista or higher)
        if VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code:

            if VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
                vmpop.automation.disable_uac(wait_s_for_window=5)
            else:
                vmpop.automation.disable_uac(wait_s_for_window=15)
                vmpop.hypervisor.send_event_keyboard(['ESC'], delay_s=1.0)
                vmpop.automation.disable_uac(wait_s_for_window=10)  # Double-check

            # Restart the system & Restore the user session
            vmpop.automation.restart(mode=VmPopFunctionMode.HV)
            vmpop.hypervisor.restore_user_session()
            vmpop.automation.wait_for_idle(timeout_ms=120000)  # 2m

            # Switch to Desktop
            if VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows8_64.code:
                vmpop.hypervisor.send_event_keyboard('d', ['LWIN'], delay_s=1.0, note="Go to Desktop")

        # Speed up Powershell startup
        vmpop.automation.speed_up_powershell()

        # Disable Windows update
        vmpop.automation.disable_windows_update()

        # Check pre-requirements: tzutil (Windows Vista)
        if VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            if vmpop.hypervisor.file_exists(vmpop.automation.path_tzutil) is False:
                # Install KB2556308 (executable file in the shared directory)
                vmpop.prglog_mgr.info("{}(): Start installing KB2556308 (for tzutil.exe)".format(GET_MY_NAME()))
                if vmpop.vm_os_type.code % 2 == 0:
                    filename = "Windows6.0-KB2556308-v3-x86.msu"
                else:
                    filename = "Windows6.0-KB2556308-v3-x64.msu"
                path = vmpop.shared_dir_vm + "\\windows\\pre-requirements\\" + filename
                # args = "/quiet /norestart"  # MSI
                args = "\"{}\" /quiet /norestart".format(path)
                if vmpop.automation.install_program(
                        path_installer="wusa.exe", arguments=args,
                        path_executable=vmpop.automation.path_tzutil, evtlog_off=True
                ) is False:
                    return False

        # Restart the system & Restore the user session (if necessary)
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.automation.restart(mode=VmPopFunctionMode.HV)
            vmpop.hypervisor.send_event_keyboard(['DOWN'], note="Select 'IEUser' account")
            vmpop.automation.logon_account(self.default_id, self.default_pw)    # Logon  "IEUser" account
        else:
            vmpop.automation.restart(mode=VmPopFunctionMode.HV)
            vmpop.hypervisor.restore_user_session()
            vmpop.automation.wait_for_idle(timeout_ms=120000)  # 2m

        # Switch to Desktop
        if VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows8_64.code:
            vmpop.hypervisor.send_event_keyboard('d', ['LWIN'], delay_s=1.0, note="Go to Desktop")

        # Speed up Powershell startup
        vmpop.automation.speed_up_powershell()

        # Turn off the automatic logon option
        vmpop.automation.disable_auto_logon()

        # create an account "CFTT"
        #   - PASSW: cftt@nist
        #            (in Windows XP or lower, max password length is 14)
        #   - GROUP: Administrators
        vmpop.automation.add_local_account("CFTT", "cftt@nist")

        # logoff the current session
        vmpop.automation.logoff_account()

        # Select "CFTT" account
        if vmpop.vm_os_type.code <= VmPopOSType.WindowsXP_64.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN'], note="Select 'CFTT' account")
        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_DEL'], ['CTRL', 'ALT'])
            vmpop.hypervisor.send_event_keyboard(['ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows7.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")
        elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
            vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['TAB'], note="To the second account")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")

        # Logon "CFTT" account
        vmpop.automation.logon_account("CFTT", "cftt@nist")

        # Disable default runs (Vista only)
        if VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.automation.disable_vista_misc()

        return

    def action_stage_1(self, vmpop):
        """OS CONFIGURATION: Timezone, NIC, EventLog

        Args:
            vmpop (VmPop)
        """
        '''Start with 'CFTT' account'''
        # [PS] change the timezone
        #   - [ORIGINAL] (UTC-08) Pacific Standard Time
        #   - [NEW]      (UTC-05) Eastern Time
        vmpop.automation.change_timezone("Eastern Standard Time", VmPopActionMethod.WIN_PS)

        # [PS] configure IP address to the network adapter "Local Area Connection"
        #   - Name    : if empty (""), the default adapter is selected automatically
        #               (normally, "Local Area Connection #" or "Ethernet #"
        #   - IP      : 10.11.11.77
        #   - Mask    : 255.255.255.0
        #   - Gateway : 10.11.11.1
        ip = "10.11.11.77"
        mk = "255.255.255.0"
        gw = "10.11.11.1"
        vmpop.automation.configure_nic_ip(name="", mode=VmPopNICMode.STATIC,
                                          address=ip, mask=mk, gateway=gw)

        # [PS] configure DNS servers to the network adapter
        dns = ["8.8.8.8", "8.8.4.4"]
        vmpop.automation.configure_nic_dns(name="", mode=VmPopNICMode.STATIC,
                                           address=dns)

        # # Disable the network and enable it again (use it if necessary)
        # nic = vmpop.automation.disable_nic()
        # vmpop.automation.enable_nic(name=nic)

        # Restart the system & Restore the user session
        vmpop.automation.restart(mode=VmPopFunctionMode.HV)

        # Select "CFTT" account
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN'], note="Select 'CFTT' account")
        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_DEL'], ['CTRL', 'ALT'])
            vmpop.hypervisor.send_event_keyboard(['ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows7.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows8.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="Select 'CFTT' account")

        # Logon "CFTT" account with a valid password
        vmpop.automation.logon_account("CFTT", "cftt@nist")

        # [KM] update audit policy (secpol.msc)
        #   - 'ON' audit account logon event
        #   - 'ON' audit system events
        vmpop.automation.configure_audit_policy_using_km()

        # [PS] update Eventlog configuration (eventvwr.msc)
        #   - set maximum log size of 'Security' log file to 80MB (81920KB)
        log_name = 'Security'
        max_size = '80MB'
        retention_days = 90  # just valid for XP or lower
        vmpop.automation.configure_eventlog(log_name, max_size, retention_days)

        # == Windows 8 or higher  ==
        if VmPopOSType.Windows8.code <= vmpop.vm_os_type.code:
            # Turn on 'File History' feature with a shared directory
            #  - Save copies of files: 10 min
            vmpop.automation.enable_file_history()
            vmpop.automation.configure_file_history()  # Setting 'DPFrequency' to 10 min

        # == Windows 10 ==
        if VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            # Check messages in 'Notification Center'
            vmpop.automation.check_notification_center()

        return

    def action_stage_2(self, vmpop):
        """ACCOUNT

        Args:
            vmpop (VmPop)
        """
        '''Start with 'CFTT' account'''
        # Create an account "Forensics"
        #   - PASSW: forensics@nist
        #            (in Windows XP or lower, max password length is 14)
        #   - GROUP: Administrators
        vmpop.automation.add_local_account("Forensics", "forensics@nist")

        # Create an account "Temporary"
        #   - PASSW: 12321
        #            (in Windows XP or lower, max password length is 14)
        #   - GROUP: Administrators
        vmpop.automation.add_local_account("Temporary", "12321")

        # Change settings of the "Temporary" account
        #   - Remove the password
        #   - Change the full name
        vmpop.automation.change_account("Temporary", "", "test")

        # Logoff the current session "CFTT"
        vmpop.automation.logoff_account()

        # Select "Forensics" account
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN', 'DOWN'], note="Select 'Forensics' account")
        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_DEL'], ['CTRL', 'ALT'])
            vmpop.hypervisor.send_event_keyboard(['E_RIGHT', 'ENTER'], note="Select 'Forensics' account")
        elif VmPopOSType.Windows7.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_RIGHT', 'ENTER'], note="Select 'Forensics' account")
        elif VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['TAB'], note="To the second account")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'Forensics' account")
        elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
            vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['TAB'], note="To the second account")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'Forensics' account")

        # Logon "Forensics" account with a valid password
        vmpop.automation.logon_account("Forensics", "forensics@nist")

        # Disable default runs (Vista only)
        if VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.automation.disable_vista_misc()

        # Logoff the current session "Forensics"
        vmpop.automation.logoff_account()

        # Select "CFTT" account
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN'], note="Select 'CFTT' account")
        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_DEL'], ['CTRL', 'ALT'])
            vmpop.hypervisor.send_event_keyboard(['ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows7.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")
        elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
            vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['TAB'], note="To the second account")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")

        # Logon "CFTT" account with a valid password
        vmpop.automation.logon_account("CFTT", "cftt@nist")

        # Create an account "CFReDS"
        #   - PASSW: cfreds@nist
        #            (in Windows XP or lower, max password length is 14)
        #   - GROUP: Administrators
        vmpop.automation.add_local_account("CFReDS", "cfreds@nist")

        # Logoff the current session "CFTT"
        vmpop.automation.logoff_account()

        # Select "Forensics" account
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN', 'DOWN', 'DOWN'], note="Select 'Forensics' account")
        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_DEL'], ['CTRL', 'ALT'])
            vmpop.hypervisor.send_event_keyboard(['E_RIGHT', 'E_RIGHT', 'ENTER'], note="Select 'Forensics' account")
        elif VmPopOSType.Windows7.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_RIGHT', 'E_RIGHT', 'ENTER'])
        elif VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the third account")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'Forensics' account")
        elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
            vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the third account")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'Forensics' account")

        # Logon "Forensics" account with an invalid password
        vmpop.automation.logon_account("Forensics", "invalid-password", invalid_pw=True)

        # Select "CFTT" account
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN', 'DOWN'], note="Select 'CFTT' account")
        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_LEFT', 'ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows7.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_LEFT', 'ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            vmpop.hypervisor.send_event_keyboard(['TAB'], note="To the second account")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")
        elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB', 'TAB'], note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")

        # Logon "CFTT" account with an invalid password
        vmpop.automation.logon_account("CFTT", "invalid-password", invalid_pw=True)

        # Select "CFReDS" account
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN'], note="Select 'CFReDS' account")
        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_LEFT', 'ENTER'], note="Select 'CFReDS' account")
        elif VmPopOSType.Windows7.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_LEFT', 'ENTER'], note="Select 'CFReDS' account")
        elif VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFReDS' account")
        elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB', 'TAB'], note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['TAB'], note="To the second account")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFReDS' account")

        # Logon "CFReDS" account with a valid password
        vmpop.automation.logon_account("CFReDS", "cfreds@nist")

        # Disable default runs (Vista only)
        if VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.automation.disable_vista_misc()

        # == Windows 8 or higher ==
        if VmPopOSType.Windows8.code <= vmpop.vm_os_type.code:
            # Add two microsoft accounts
            vmpop.automation.add_email_account("cftt.user1@outlook.com")
            vmpop.automation.add_email_account("cftt.user2@outlook.com")

            # Logoff the current session "CFReDS"
            vmpop.automation.logoff_account()

            # Select "cftt.user1@outlook.com" account
            if VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="To the first item of account list")
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the third account")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'cftt.user1@outlook.com' account")
            elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the first item of account list")
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the third account")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'cftt.user1@outlook.com' account")

            # Logon "cftt.user1@outlook.com" account with a valid password
            vmpop.automation.logon_account("cftt.user1@outlook.com", "tkdydwk.Tldpvmxlxl1#%0", clear_desktop=False)

            # Configure some features
            if VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows8_64.code:
                vmpop.automation.wait_for_idle(default_wait_s=120)
            elif VmPopOSType.Windows81.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
                # Skip 'phone protection'
                vmpop.hypervisor.send_event_keyboard(['TAB']*3, delay_s=0.5)
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=15, note="Skip 'phone protection'")
                # Set 'OneDrive'
                vmpop.hypervisor.send_event_keyboard(['ENTER', 'ENTER'], press_delay_ms=3000, note="Set 'OneDrive'")
                vmpop.automation.wait_for_idle(default_wait_s=90)
            elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
                # Set up a PIN (if Windows 10)
                pin = '1234321'
                vmpop.hypervisor.click_mouse_left_button_at_center()
                vmpop.hypervisor.send_event_keyboard(['TAB'], ['LSHIFT'], delay_s=2.0)
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=3.0)
                vmpop.hypervisor.send_event_keyboard(pin, delay_s=1.0, note="PIN")
                vmpop.hypervisor.send_event_keyboard(['TAB'], delay_s=1.0)
                vmpop.hypervisor.send_event_keyboard(pin, delay_s=1.0, note="PIN")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=5.0, note="Set up a PIN")
                # Close the current window
                vmpop.automation.close_window()

            # Logoff the current session
            vmpop.automation.logoff_account(delay_s=40)

            # Select "CFReDS" account
            if VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="To the first item of account list")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFReDS' account")
            elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the first item of account list")
                vmpop.hypervisor.send_event_keyboard(['TAB'], note="To the second account")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFReDS' account")

            # Logon "CFReDS" account with a valid password
            vmpop.automation.logon_account("CFReDS", "cfreds@nist")

        return

    def action_stage_3(self, vmpop):
        """BASIC ACTIONS with EXTERNAL DEVICE
            : Traversing directories and files stored in an external devices

        Args:
            vmpop (VmPop)
        """
        '''Start with 'CFReDS' account'''
        # Attach a USB device
        serial_number = self.rm1
        usb_drive_letter = vmpop.automation.attach_usb(serial_number)

        path_base = usb_drive_letter
        if path_base is not None:
            # Open a directory (explorer.exe)
            vmpop.automation.open_shell(path_base)

            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"        .format(path_base, "RM1+Samples"))
            dirs.append("{}\\{}\\{}"    .format(path_base, "RM1+Samples", "dir-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, "RM1+Samples", "dir-1", "dir-1-1"))
            dirs.append("{}\\{}\\{}"    .format(path_base, "RM1+Samples", "dir-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, "RM1+Samples", "dir-1", "dir-1-2"))
            dirs.append("{}\\{}\\{}"    .format(path_base, "RM1+Samples", "dir-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, "RM1+Samples", "dir-1", "dir-1-3"))
            vmpop.automation.change_dirs(dirs)

            # Open a file in the current directory
            path = "{}\\{}\\{}\\{}".format(path_base, "RM1+Samples", "dir-1", "dir-1-3")
            path += "\\{}".format("text1.txt")
            vmpop.automation.launch_program(path, focus_to_pid=True, terminate_after_time_s=3)

            # Open a file in the current directory
            path = "{}\\{}\\{}\\{}".format(path_base, "RM1+Samples", "dir-1", "dir-1-3")
            path += "\\{}".format("text2.txt")
            vmpop.automation.launch_program(path, focus_to_pid=True, terminate_after_time_s=3)

            # Focus on Windows Explorer
            vmpop.automation.set_foreground_window(window_title="dir-1-3")

            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}\\{}".format(path_base, "RM1+Samples", "dir-1"))
            dirs.append("{}\\{}"    .format(path_base, "RM1+Samples"))
            dirs.append("{}"        .format(path_base))
            vmpop.automation.change_dirs(dirs)

            # Copy a directory ("RM1+Samples") to Desktop ("%UserProfile%\Desktop")
            src_path = "{}\\{}".format(path_base, "RM1+Samples")
            dst_path = "%UserProfile%\\Desktop\\RM1+Samples"
            vmpop.automation.copy_files(src_path, dst_path)

            # Close the current directory (terminate explorer.exe)
            vmpop.automation.close_window(evtlog_off=False)

            # Open a directory (explorer.exe)
            path_base = "%UserProfile%\\Desktop\\RM1+Samples"
            vmpop.automation.open_shell(path_base)

            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"        .format(path_base, "dir-1"))
            dirs.append("{}\\{}\\{}"    .format(path_base, "dir-1", "dir-1-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, "dir-1", "dir-1-1", "dir-1-1-1"))
            vmpop.automation.change_dirs(dirs)

            # Close the current directory (terminate explorer.exe)
            vmpop.automation.close_window(evtlog_off=False)

            # Detach a USB device
            vmpop.automation.detach_usb(serial_number)

        # Logoff the current session "CFReDS"
        vmpop.automation.logoff_account()

        # Select "CFTT" account
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN', 'DOWN'], note="Select 'CFTT' account")
        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_DEL'], ['CTRL', 'ALT'])
            vmpop.hypervisor.send_event_keyboard(['E_RIGHT', 'ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows7.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_RIGHT', 'ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['TAB'], note="To the second account")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")
        elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
            vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the first item of account list")
            vmpop.hypervisor.send_event_keyboard(['TAB'], note="To the second account")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")

        # Logon "CFTT" account with an invalid password
        vmpop.automation.logon_account("CFTT", "invalid-password", invalid_pw=True)

        # Select "CFTT" account
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN', 'DOWN'], note="Select 'CFTT' account")
        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows7.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            vmpop.hypervisor.send_event_keyboard(['TAB'], note="To the second account")
            vmpop.hypervisor.send_event_keyboard(['ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.send_event_keyboard(['ESC'], note="Select 'CFTT' account")

        # Logon "CFTT" account with a valid password
        vmpop.automation.logon_account("CFTT", "cftt@nist")
        return

    def action_stage_4(self, vmpop):
        """APPLICATION related ACTIONS Part I with EXTERNAL DEVICE
            : Installing and/or launching applications stored in an external device

            [I]: Install application
            [L]: Launch application
            [T]: Terminate application

        Args:
            vmpop (VmPop)
        """
        '''Start with 'CFTT' account'''
        # Attach a USB device
        serial_number = self.rm2
        usb_drive_letter = vmpop.automation.attach_usb(serial_number)

        path_base = usb_drive_letter
        # path_base = usb_drive_letter = "G:"
        if path_base is not None:
            # Open a directory (explorer.exe)
            vmpop.automation.open_shell(path_base)

            '''---WEB-BROWSER----------'''
            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"    .format(path_base, "RM2+Apps"))
            dirs.append("{}\\{}\\{}".format(path_base, "RM2+Apps", "#1_web-browser"))
            vmpop.automation.change_dirs(dirs)

            # [I] Google Chrome (Windows 7 or higher only)
            if vmpop.vm_os_type.code % 2 == 0:  # 32 bits
                target = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
            else:
                target = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"

            if vmpop.hypervisor.file_exists(target) is False:
                path = "{}\\{}".format(path_base, "RM2+Apps\\#1_web-browser\\ChromeStandaloneSetup.exe")
                args = "/Silent /Install"
                vmpop.automation.install_program(path_installer=path, arguments=args, path_executable=target)
                # vmpop.automation.terminate_process(name="chrome")  # Terminate this app if it does exist

            # # [L]&[T] Google Chrome (Windows 7 or higher only)
            # if vmpop.hypervisor.file_exists(target) is True:
            #     vmpop.automation.launch_program(path_file=target, focus_to_pid=True, terminate_after_time_s=2)

            # Get the version of IE
            ie_version = vmpop.automation.check_ie_version()
            if ie_version < "8.0":
                ie_version = VmPopWebBrowser.IE7
            elif "8.0" <= ie_version < "9.0":
                ie_version = VmPopWebBrowser.IE8
            elif "9.0" <= ie_version < "9.10":
                ie_version = VmPopWebBrowser.IE9
            elif "9.10" <= ie_version < "9.11":
                ie_version = VmPopWebBrowser.IE10
            elif "9.11" <= ie_version:
                ie_version = VmPopWebBrowser.IE11

            # [L]&[T] Internet Explorer, Edge, and Google Chrome
            apps = list()

            # Set the configuration for Internet Explorer
            apps.append(("",
                         "C:\\Program Files\\Internet Explorer\\iexplore.exe",
                         ie_version,
                         False))

            # Set the configuration for Edge
            apps.append(("shell:AppsFolder\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge",
                         "C:\\Windows\\SystemApps\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\MicrosoftEdge.exe",
                         VmPopWebBrowser.EDGE,
                         False))

            # Set the configuration for Chrome
            if vmpop.vm_os_type.code % 2 == 0:  # 32 bits
                target = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
            else:
                target = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"

            apps.append(("",
                         target,
                         VmPopWebBrowser.CHROME,
                         False))

            for shortcut, target, browser, maximize in apps:
                if vmpop.hypervisor.file_exists(target) is False:
                    continue

                shortcut = target if shortcut == "" else shortcut

                # [L]&[T] Launch a browser and just terminate it for initializing the program environment
                vmpop.automation.launch_program(
                    path_file=shortcut, path_target=target, focus_to_pid=True, terminate_after_time_s=3
                )

                if browser == VmPopWebBrowser.EDGE:
                    vmpop.automation.disable_edge_save_prompt()

                # Launch a browser again and use it
                ret, pid = vmpop.automation.launch_program(path_file=shortcut, path_target=target, focus_to_pid=True)
                if ret is False:
                    continue

                if browser == VmPopWebBrowser.EDGE:
                    # vmpop.automation.set_foreground_window(pname="ApplicationFrameHost")  # Same effect
                    vmpop.automation.set_foreground_window(window_title="Edge")
                    vmpop.automation.maximize_window()
                else:
                    if VmPopWebBrowser.IE7 <= browser <= VmPopWebBrowser.IE11:
                        vmpop.automation.set_foreground_window(pid=pid)
                        vmpop.hypervisor.send_event_keyboard(['ESC'], delay_s=10)
                        vmpop.automation.set_foreground_window(pid=pid)
                    if browser == VmPopWebBrowser.CHROME:
                        vmpop.hypervisor.click_mouse_left_button_at_center()
                        vmpop.hypervisor.send_event_keyboard(['ESC'], delay_s=5)
                    vmpop.automation.maximize_window()

                # Create a new tab
                vmpop.automation.control_web_browser(action=VmPopWebAction.NEW_TAB, browser=browser, evtlog_off=True)

                # Visit a web-site
                vmpop.automation.control_web_browser(
                    action=VmPopWebAction.VISIT_URL, browser=browser, argument1="www.cftt.nist.gov"
                )

                # Bookmark the current site
                vmpop.automation.control_web_browser(action=VmPopWebAction.ADD_BOOKMARK, browser=browser)

                # Create a new tab
                vmpop.automation.control_web_browser(action=VmPopWebAction.NEW_TAB, browser=browser, evtlog_off=True)

                # Visit a web-site
                vmpop.automation.control_web_browser(
                    action=VmPopWebAction.VISIT_URL, browser=browser, argument1="www.cfreds.nist.gov"
                )

                # Bookmark the current site
                vmpop.automation.control_web_browser(action=VmPopWebAction.ADD_BOOKMARK, browser=browser)

                # Close the active tab
                vmpop.automation.control_web_browser(action=VmPopWebAction.CLOSE_TAB, browser=browser, evtlog_off=True)

                # Create a new tab
                vmpop.automation.control_web_browser(action=VmPopWebAction.NEW_TAB, browser=browser, evtlog_off=True)

                # Download a file
                vmpop.automation.control_web_browser(
                    action=VmPopWebAction.DOWNLOAD, browser=browser,
                    argument1="http://www.cfreds.nist.gov/data_leakage_case/images/rm%233/cfreds_2015_data_leakage_rm%233_type2.7z",
                    delay_s=2  # Based on the file size
                )

                # Close the active tab
                vmpop.automation.control_web_browser(action=VmPopWebAction.CLOSE_TAB, browser=browser, evtlog_off=True)

                # Create a new tab
                vmpop.automation.control_web_browser(action=VmPopWebAction.NEW_TAB, browser=browser, evtlog_off=True)

                # Visit a web-site
                vmpop.automation.control_web_browser(
                    action=VmPopWebAction.VISIT_URL, browser=browser, argument1="www.google.com"
                )

                # Search keywords
                if VmPopWebBrowser.IE7 < browser:
                    keywords = list()
                    keywords.append("NIST CFTT")
                    keywords.append("NIST CFReDS")
                    # keywords.append("NIST Data Leakage Case")
                    for keyword in keywords:
                        vmpop.automation.control_web_browser(
                            action=VmPopWebAction.SEARCH_KEYWORD, browser=browser,
                            site=VmPopWebSite.GOOGLE, argument1=keyword
                        )

                # Close the active tab
                vmpop.automation.control_web_browser(action=VmPopWebAction.CLOSE_TAB, browser=browser, evtlog_off=True)

                # # Create a new tab
                vmpop.automation.control_web_browser(action=VmPopWebAction.NEW_TAB, browser=browser, evtlog_off=True)

                # Visit a web-site
                vmpop.automation.control_web_browser(
                    action=VmPopWebAction.VISIT_URL, browser=browser, argument1="www.bing.com"
                )

                if VmPopWebBrowser.IE7 == browser:
                    vmpop.hypervisor.send_event_keyboard(['ESC'], delay_s=1.0)

                # Search keywords
                if VmPopWebBrowser.IE7 <= browser:
                    keywords = list()
                    keywords.append("NIST CFTT")
                    keywords.append("NIST CFReDS")
                    # keywords.append("NIST Data Leakage Case")
                    for keyword in keywords:
                        vmpop.automation.control_web_browser(
                            action=VmPopWebAction.SEARCH_KEYWORD, browser=browser,
                            site=VmPopWebSite.BING, argument1=keyword
                        )

                # Close the active tab
                vmpop.automation.control_web_browser(action=VmPopWebAction.CLOSE_TAB, browser=browser, evtlog_off=True)

                # This is because EDGE and IE shares the credential information
                if VmPopWebBrowser.IE9 < browser and browser is not VmPopWebBrowser.EDGE:
                    # Create a new tab
                    vmpop.automation.control_web_browser(action=VmPopWebAction.NEW_TAB, browser=browser, evtlog_off=True)

                    # Login a web-site (and then click a button for saving credentials)
                    vmpop.automation.control_web_browser(
                        action=VmPopWebAction.LOGIN, browser=browser,
                        argument1="cftt.user1@outlook.com", argument2="tkdydwk.Tldpvmxlxl1#%0",
                        site=VmPopWebSite.LIVE,
                    )

                    # Close the active tab
                    vmpop.automation.control_web_browser(action=VmPopWebAction.CLOSE_TAB, browser=browser, evtlog_off=True)

                # Create a new tab
                vmpop.automation.control_web_browser(action=VmPopWebAction.NEW_TAB, browser=browser, evtlog_off=True)

                # Visit a web-site
                vmpop.automation.control_web_browser(
                    action=VmPopWebAction.VISIT_URL, browser=browser, argument1="toolcatalog.nist.gov"
                )

                # Bookmark the current site
                vmpop.automation.control_web_browser(action=VmPopWebAction.ADD_BOOKMARK, browser=browser)

                # # Close the active tab
                # vmpop.automation.control_web_browser(action=VmPopWebAction.CLOSE_TAB, browser=browser, evtlog_off=True)
                #
                # # Create a new tab
                # vmpop.automation.control_web_browser(action=VmPopWebAction.NEW_TAB, browser=browser, evtlog_off=True)
                #
                # # Download a file
                # vmpop.automation.control_web_browser(
                #     action=VmPopWebAction.DOWNLOAD, browser=browser,
                #     # argument1="http://www.cfreds.nist.gov/data_leakage_case/leakage-answers.docx",
                #     argument1="http://www.cfreds.nist.gov/FileCarving/Images/L5_Video.dd.bz2",
                #     delay_s=5  # Based on the file size
                # )

                # Terminate this application
                vmpop.automation.terminate_process(pid=pid)  # It is possible to be terminated with 'Force' option

            vmpop.automation.set_foreground_window(window_title="#1_web-browser")

            '''---DOCUMENT----------'''
            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"    .format(path_base, "RM2+Apps"))
            dirs.append("{}\\{}\\{}".format(path_base, "RM2+Apps", "#2_document"))
            vmpop.automation.change_dirs(dirs)

            # == MS Office 2016 does not support Windows XP and Vista
            if VmPopOSType.Windows7.code <= vmpop.vm_os_type.code:
                # [I] MS Office 2016 Public Preview
                # (Word, Excel, PowerPoint, OneNote, Outlook, Publisher, Access, OneDrive)
                targets = list()
                targets.append("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")
                targets.append("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE")
                targets.append("C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE")
                if vmpop.hypervisor.file_exists(targets[0]) is False:
                    if vmpop.vm_os_type.code % 2 == 0:  # 32 bits
                        path = "{}\\{}".format(path_base, "RM2+Apps\\#2_document\\Setup.x86.en-us_ProfessionalRetail_NKGG6-WBPCC-HXWMY-6DQGJ-CPQVG_act_1_.exe")
                    else:
                        path = "{}\\{}".format(path_base, "RM2+Apps\\#2_document\\Setup.x64.en-us_ProfessionalRetail_NKGG6-WBPCC-HXWMY-6DQGJ-CPQVG_act_1_.exe")
                    vmpop.automation.install_program(
                        path_installer=path, path_executable=targets[0],
                        timeout_ms=1800000, evtlog_off=True  # because this installation produces a lot of events
                    )
                    vmpop.hypervisor.send_event_keyboard(['E_RIGHT'], delay_s=2)
                    if vmpop.automation.set_foreground_window(pname="OfficeC2RClient") is True:
                        vmpop.hypervisor.click_mouse_left_button_at_center()
                        vmpop.automation.close_window()
                        # vmpop.hypervisor.send_event_keyboard(['c'], delay_s=1.5, note="Click 'Close'")

                # [L]&[T] MS Office 2016 Public Preview
                first = True
                for target in targets:
                    if vmpop.hypervisor.file_exists(target) is False:
                        continue
                    ret, pid = vmpop.automation.launch_program(path_file=target, maximize=True, focus_to_pid=True)
                    if ret is True:
                        time.sleep(3)
                        if first is True:
                            time.sleep(2)
                            vmpop.hypervisor.click_mouse_left_button_at_center()
                            vmpop.hypervisor.send_event_keyboard(['ESC'], delay_s=15)
                            vmpop.hypervisor.click_mouse_left_button_at_center()
                            vmpop.hypervisor.send_event_keyboard(['a'], delay_s=1.5, note="Click 'Accept'")
                            first = False
                        vmpop.hypervisor.send_event_keyboard(
                            ['ESC'], delay_s=1.5, note="Close the MS Office Activation Wizard"
                        )
                        vmpop.automation.terminate_process(pid=pid)

            # [I] Adobe Reader (v11)
            if vmpop.vm_os_type.code % 2 == 0:  # 32 bits
                target = "C:\\Program Files\\Adobe\\Reader 11.0\\Reader\\AcroRd32.exe"
            else:
                target = "C:\\Program Files (x86)\\Adobe\\Reader 11.0\\Reader\\AcroRd32.exe"

            if vmpop.hypervisor.file_exists(target) is False:
                path = "{}\\{}".format(path_base, "RM2+Apps\\#2_document\\AdbeRdr11000_mui_Std\\AcroRead.msi")
                args = "/passive /norestart disable_arm_service_install=\"1\""  # MSI
                vmpop.automation.install_program(path_installer=path, arguments=args, path_executable=target)

            # [L]&[T] Adobe Reader
            if vmpop.hypervisor.file_exists(target) is True:
                ret, pid = vmpop.automation.launch_program(path_file=target)
                if ret is True:
                    time.sleep(2)
                    # vmpop.automation.set_foreground_window(pname="Eula")
                    if vmpop.automation.set_foreground_window(
                            window_title="Adobe Reader XI - Distribution License"
                    ) is True:
                        vmpop.hypervisor.click_mouse_left_button_at_center()
                        vmpop.hypervisor.send_event_keyboard(['TAB'], ['LSHIFT'], delay_s=1.0, note="Go to 'Accept'")
                        vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=3.0, note="Click 'Accept'")
                        vmpop.automation.terminate_process(pid=pid)

                # Disable Adobe Reader v11 Updater
                reg_path = "HKLM\\SOFTWARE\\Policies\\Adobe\\Acrobat Reader\\11.0\\FeatureLockDown"
                reg_data = "00000000"
                vmpop.automation.set_reg_value(
                    path=reg_path, value="bUpdater", reg_type=VmPopRegType.REG_DWORD, data=reg_data
                )

            # [I] Notepad++
            if vmpop.vm_os_type.code % 2 == 0:  # 32 bits
                target = "C:\\Program Files\\Notepad++\\notepad++.exe"
            else:
                target = "C:\\Program Files (x86)\\Notepad++\\notepad++.exe"

            if vmpop.hypervisor.file_exists(target) is False:
                path = "{}\\{}".format(path_base, "RM2+Apps\\#2_document\\npp.7.1.Installer.exe")
                args = "/S"  # /NSIS
                vmpop.automation.install_program(path_installer=path, arguments=args, path_executable=target)

            # [L]&[T] Notepad++
            if vmpop.hypervisor.file_exists(target) is True:
                vmpop.automation.launch_program(path_file=target, focus_to_pid=True, terminate_after_time_s=3)

            vmpop.automation.set_foreground_window(window_title="#2_document")

            '''---ARCHIVE----------'''
            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"    .format(path_base, "RM2+Apps"))
            dirs.append("{}\\{}\\{}".format(path_base, "RM2+Apps", "#3_archive"))
            vmpop.automation.change_dirs(dirs)

            # [I] 7-zip
            if vmpop.vm_os_type.code % 2 == 0:  # 32 bits
                target = "C:\\Program Files\\7-Zip\\7zFM.exe"
            else:
                target = "C:\\Program Files (x86)\\7-Zip\\7zFM.exe"

            if vmpop.hypervisor.file_exists(target) is False:
                path = "{}\\{}".format(path_base, "RM2+Apps\\#3_archive\\7z1604.msi")
                args = "/passive /norestart"  # MSI
                vmpop.automation.install_program(path_installer=path, arguments=args, path_executable=target)

            # [L]&[T] 7-Zip
            if vmpop.hypervisor.file_exists(target) is True:
                vmpop.automation.launch_program(path_file=target, maximize=True, terminate_after_time_s=3)

            # [L] PeaZip (portable) & [T] the process after 5 seconds
            path = "{}\\{}\\{}\\{}".format(path_base, "RM2+Apps", "#3_archive", "peazip_portable-6.1.1.WINDOWS")
            path += "\\{}".format("peazip.exe")
            vmpop.automation.launch_program(path_file=path, focus_to_pid=True, terminate_after_time_s=3)

            vmpop.automation.set_foreground_window(window_title="#3_archive")

            '''---MULTIMEDIA----------'''
            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"    .format(path_base, "RM2+Apps"))
            dirs.append("{}\\{}\\{}".format(path_base, "RM2+Apps", "#4_multimedia"))
            vmpop.automation.change_dirs(dirs)

            # [L]&[T] Windows Media Player
            target = "C:\\Program Files\\Windows Media Player\\wmplayer.exe"
            if vmpop.hypervisor.file_exists(target) is True:
                ret, pid = vmpop.automation.launch_program(path_file=target)
                if ret is True:
                    time.sleep(2)
                    if vmpop.automation.set_foreground_window(window_title="Windows Media Player") is True:
                        vmpop.hypervisor.click_mouse_left_button_at_center()
                        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
                            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0)
                            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0)
                            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=3.0, note="Click 'Finish'")
                        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code < VmPopOSType.WindowsVista_64.code:
                            vmpop.hypervisor.send_event_keyboard('e', delay_s=1.0, note="Check 'express Settings'")
                            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=3.0, note="Click 'Finish'")
                        else:
                            vmpop.hypervisor.send_event_keyboard('r', delay_s=1.0, note="Check 'Recommended Settings'")
                            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=3.0, note="Click 'Finish'")
                    vmpop.automation.terminate_process(name="wmplayer")

            # [I] VLC media player
            if vmpop.vm_os_type.code % 2 == 0:  # 32 bits
                target = "C:\\Program Files\\VideoLAN\\VLC\\vlc.exe"
            else:
                target = "C:\\Program Files (x86)\\VideoLAN\\VLC\\vlc.exe"

            if vmpop.hypervisor.file_exists(target) is False:
                path = "{}\\{}".format(path_base, "RM2+Apps\\#4_multimedia\\vlc-2.2.4-win32.exe")
                args = "/S"  # NSIS
                vmpop.automation.install_program(path_installer=path, arguments=args, path_executable=target)

            # [L]&[T] VLC media player
            if vmpop.hypervisor.file_exists(target) is True:
                ret, pid = vmpop.automation.launch_program(
                    path_file=target, focus_to_pid=True, keystrokes=[['ENTER'], [], 85, "Click 'Continue'"],
                    terminate_after_time_s=3
                )
                # if ret is True:  # Alternative of the above line
                #     vmpop.automation.set_foreground_window(pid=pid)
                #     # vmpop.automation.set_foreground_window(pname="vlc")
                #     # vmpop.automation.set_foreground_window(window_title="VLC media player")
                #     # vmpop.automation.set_foreground_window(window_title="Privacy and Network")
                #     vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0)  # Click 'Continue' button
                #     vmpop.automation.terminate_process(pid=pid)

            # [I] Potplayer
            if vmpop.vm_os_type.code % 2 == 0:  # 32 bits
                target = "C:\\Program Files\\DAUM\\PotPlayer\\PotPlayerMini.exe"
            else:
                target = "C:\\Program Files (x86)\\DAUM\\PotPlayer\\PotPlayerMini.exe"

            if vmpop.hypervisor.file_exists(target) is False:
                path = "{}\\{}".format(path_base, "RM2+Apps\\#4_multimedia\\PotPlayerSetup.exe")
                args = "/S"  # NSIS
                vmpop.automation.install_program(path_installer=path, arguments=args, path_executable=target)

            # [L]&[T] Potplayer
            if vmpop.hypervisor.file_exists(target) is True:
                vmpop.automation.launch_program(path_file=target, focus_to_pid=True, terminate_after_time_s=3)

            vmpop.automation.set_foreground_window(window_title="#4_multimedia")

            '''---CLOUD-SERVICE----------'''
            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"    .format(path_base, "RM2+Apps"))
            dirs.append("{}\\{}\\{}".format(path_base, "RM2+Apps", "#5_cloud-service"))
            vmpop.automation.change_dirs(dirs)

            # [I] Google Drive Sync
            if vmpop.vm_os_type.code % 2 == 0:  # 32 bits
                target = "C:\\Program Files\\Google\\Drive\\googledrivesync.exe"
            else:
                target = "C:\\Program Files (x86)\\Google\\Drive\\googledrivesync.exe"

            if vmpop.hypervisor.file_exists(target) is False:
                path = "{}\\{}".format(path_base, "RM2+Apps\\#5_cloud-service\\gsync_enterprise.msi")
                args = "/passive /norestart"  # MSI
                vmpop.automation.install_program(path_installer=path, arguments=args, path_executable=target)
                vmpop.automation.terminate_process(name="googledrivesync")

            # [L]&[T] Google Drive Sync
            if vmpop.hypervisor.file_exists(target) is True:
                vmpop.automation.launch_program(
                    path_file=target, focus_to_pid=True, terminate_after_time_s=3
                )
                # if ret is True:  # Alternative of the above line
                #     time.sleep(3)
                #     vmpop.automation.terminate_process(pid=pid)
                #     # vmpop.automation.terminate_process(name="googledrivesync")

            # [I] Evernote
            if vmpop.vm_os_type.code % 2 == 0:  # 32 bits
                target = "C:\\Program Files\\Evernote\\Evernote\\Evernote.exe"
            else:
                target = "C:\\Program Files (x86)\\Evernote\\Evernote\\Evernote.exe"

            if vmpop.hypervisor.file_exists(target) is False:
                path = "{}\\{}".format(path_base, "RM2+Apps\\#5_cloud-service\\Evernote_6.4.2.3773.exe")
                args = "/passive /norestart"  # MSI (because the installer creates an MSI file in %Temp%)
                vmpop.automation.install_program(path_installer=path, arguments=args, path_executable=target)
                vmpop.automation.terminate_process(name="evernote")

            # [L]&[T] Evernote
            if vmpop.hypervisor.file_exists(target) is True:
                vmpop.automation.launch_program(path_file=target, focus_to_pid=True)
                vmpop.automation.terminate_process(name="evernote")

            vmpop.automation.set_foreground_window(window_title="#5_cloud-service")

            '''---P2P----------'''
            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"    .format(path_base, "RM2+Apps"))
            dirs.append("{}\\{}\\{}".format(path_base, "RM2+Apps", "#6_p2p"))
            vmpop.automation.change_dirs(dirs)

            # [I] qBittorrent
            if vmpop.vm_os_type.code % 2 == 0:  # 32 bits
                target = "C:\\Program Files\\qBittorrent\\qbittorrent.exe"
            else:
                target = "C:\\Program Files (x86)\\qBittorrent\\qbittorrent.exe"

            if vmpop.hypervisor.file_exists(target) is False:
                path = "{}\\{}".format(path_base, "RM2+Apps\\#6_p2p\\qbittorrent_3.3.7_setup.exe")
                args = "/S"  # NSIS
                vmpop.automation.install_program(path_installer=path, arguments=args, path_executable=target)

            # [L]&[T] qBittorrent
            if vmpop.hypervisor.file_exists(target) is True:
                ret, pid = vmpop.automation.launch_program(
                    path_file=target,
                    focus_to_pid=True, keystrokes=[['ENTER'], [], 85, "Click 'I Agree'"],
                    terminate_after_time_s=4
                )
                # if ret is True:  # Alternative of the above line
                #     time.sleep(4)
                #     vmpop.automation.set_foreground_window(pid=pid)
                #     # vmpop.automation.set_foreground_window(pname="qbittorrent")
                #     vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0)  # Click 'I Agree' button
                #     vmpop.automation.terminate_process(pid=pid)

            vmpop.automation.set_foreground_window(window_title="#6_p2p")

            '''---ANTI-FORENSICS----------'''
            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"    .format(path_base, "RM2+Apps"))
            dirs.append("{}\\{}\\{}".format(path_base, "RM2+Apps", "#7_anti-forensics"))
            vmpop.automation.change_dirs(dirs)

            # [I] CCleaner
            target = "C:\\Program Files\\CCleaner\\CCleaner.exe"

            if vmpop.hypervisor.file_exists(target) is False:
                path = "{}\\{}".format(path_base, "RM2+Apps\\#7_anti-forensics\\ccsetup523.exe")  # 32 & 64 bits
                args = "/S"  # NSIS
                vmpop.automation.install_program(path_installer=path, arguments=args, path_executable=target)

            # [L]&[T] CCleaner
            if vmpop.hypervisor.file_exists(target) is True:
                ret, pid = vmpop.automation.launch_program(path_file=target, focus_to_pid=True)
                if ret is True:
                    time.sleep(2)
                    vmpop.automation.terminate_process(name="ccleaner*", run_as_admin=True)

            # [L] Eraser (portable) & [T] the process after 5 seconds
            path = "{}\\{}".format(path_base, "RM2+Apps\\#7_anti-forensics\\Eraser 5.8.8 Portable")
            path += "\\{}".format("Eraser.exe")
            vmpop.automation.launch_program(path_file=path, focus_to_pid=True, terminate_after_time_s=3)

            vmpop.automation.set_foreground_window(window_title="#7_anti-forensics")

            # Close the current directory (terminate explorer.exe)
            vmpop.automation.close_window(evtlog_off=False)

            # Detach a USB device
            vmpop.automation.detach_usb(serial_number)

        '''---ETC----------'''
        # [L]&[T] Default Windows Metro App
        # == Windows 8 or higher == (using Keyboard strokes - search feature)
        if VmPopOSType.Windows8.code <= vmpop.vm_os_type.code:
            apps = list()
            apps.append("Weather")
            # apps.append("News")  # it does not exist in Windows 10RS1
            for name in apps:
                vmpop.automation.launch_win_store_app(name, terminate_after_time_s=2)

        # == Windows 10 == (creating a new process with the registered shortcut)
        if VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            # C:\Windows\SystemApps\
            apps = list()
            apps.append(("shell:AppsFolder\Microsoft.Windows.Photos_8wekyb3d8bbwe!App", "8wekyb3d8bbwe\\Microsoft.Photos.exe"))
            apps.append(("shell:AppsFolder\Microsoft.WindowsCalculator_8wekyb3d8bbwe!App", "8wekyb3d8bbwe\\Calculator.exe"))
            for shortcut, target in apps:
                vmpop.automation.launch_program(
                    path_file=shortcut, path_target=target, terminate_after_time_s=3
                )

        # == Windows 10 ==
        if VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            # Check messages in 'Notification Center'
            vmpop.automation.check_notification_center()

        # == Windows 8.1 or higher == (-> Most apps support 8.1 or higher)
        # Install Metro-style apps though 'Store' app
        if VmPopOSType.Windows81.code <= vmpop.vm_os_type.code:
            # Logoff the current session "CFTT"
            vmpop.automation.logoff_account(delay_s=60)

            # Select "cftt.user1@outlook.com" account
            if VmPopOSType.Windows81.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB', 'TAB', 'TAB', 'TAB'], note="To the 6th account")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'cftt.user1@outlook.com' account")
            elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the first item of account list")
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB', 'TAB', 'TAB', 'TAB'], note="To the 6th account")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'cftt.user1@outlook.com' account")

            # Logon "cftt.user1@outlook.com" account
            if VmPopOSType.Windows8.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
                vmpop.automation.logon_account("cftt.user1@outlook.com", "tkdydwk.Tldpvmxlxl1#%0")
            elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
                vmpop.automation.logon_account("cftt.user1@outlook.com", "tkdydwk.Tldpvmxlxl1#%0", pin="1234321")

            '''---ARCHIVE----------'''
            # [I] ZIP Opener (Windows Store App)
            app_name = "ZIP Opener"
            vmpop.automation.install_win_store_app(app_name)
            # [L]&[T]
            vmpop.automation.launch_win_store_app(app_name, terminate_after_time_s=2)

            '''---CLOUD-SERVICE----------'''
            # [I] Dropbox (Windows Store App)
            app_name = "Dropbox"
            vmpop.automation.install_win_store_app(app_name)
            # [L]&[T]
            vmpop.automation.launch_win_store_app(app_name, terminate_after_time_s=2)

            '''---SOCIAL MEDIA----------'''
            # [I] Facebook (Windows Store App)
            app_name = "Facebook"
            vmpop.automation.install_win_store_app(app_name)
            # [L]&[T]
            vmpop.automation.launch_win_store_app(app_name, terminate_after_time_s=2)

            # '''---ETC----------'''
            # # [I] Teamviewer (Windows Store App)
            # app_name = "TeamViewer"
            # vmpop.automation.install_win_store_app(app_name)
            # # [L]&[T]
            # vmpop.automation.launch_win_store_app(app_name, terminate_after_time_s=2)

            # Logoff the current session "cftt.user1@outlook.com"
            vmpop.automation.logoff_account(delay_s=40)

            # Select "CFTT" account
            if VmPopOSType.Windows81.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
                vmpop.hypervisor.send_event_keyboard(['TAB'], note="To the second account")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")
            elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the first item of account list")
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the third account")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")

            # Logon "CFTT" account with a valid password
            vmpop.automation.logon_account("CFTT", "cftt@nist")

        # Create a backup (Restore Point or Volume Shadow Copy)
        vmpop.automation.create_restore_point(
            drive="C:\\", description="1st manual restore point",
            rp_type=VmPopRPType.APPLICATION_INSTALL
        )
        return

    def action_stage_5(self, vmpop):
        """APPLICATION related ACTIONS Part II with EXTERNAL DEVICE
            : Launching(Opening) files with specific applications
        
            - [I]: Install  [L]: Launch  [T]: Terminate

        Args:
            vmpop (VmPop)
        """
        if VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code < VmPopOSType.Windows7.code:
            vmpop.hypervisor.send_event_keyboard('d', ['LWIN'], delay_s=1.0, note="Go to Desktop")

        # Attach a USB device
        serial_number = self.rm2
        usb_drive_letter = vmpop.automation.attach_usb(serial_number)
        path_base = usb_drive_letter

        if path_base is not None:
            # Open a directory (explorer.exe)
            vmpop.automation.open_shell(path_base)

            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"        .format(path_base, "RM2+Samples"))
            dirs.append("{}\\{}\\{}"    .format(path_base, "RM2+Samples", "dir-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, "RM2+Samples", "dir-1", "dir-1-1"))
            dirs.append("{}\\{}\\{}"    .format(path_base, "RM2+Samples", "dir-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, "RM2+Samples", "dir-1", "dir-1-2"))
            dirs.append("{}\\{}\\{}"    .format(path_base, "RM2+Samples", "dir-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, "RM2+Samples", "dir-1", "dir-1-3"))
            dirs.append("{}\\{}\\{}"    .format(path_base, "RM2+Samples", "dir-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, "RM2+Samples", "dir-1", "dir-1-4"))
            dirs.append("{}\\{}\\{}"    .format(path_base, "RM2+Samples", "dir-1"))
            vmpop.automation.change_dirs(dirs)

            # Open a file in the current directory
            path = "{}\\{}".format(path_base, "RM2+Samples\\dir-1\\executable1.exe")
            ret, pid = vmpop.automation.launch_program(path, focus_to_pid=True)
            if ret is True:
                vmpop.automation.terminate_process(name="executable1")

            # Open a file in the current directory
            path = "{}\\{}".format(path_base, "RM2+Samples\\dir-1\\executable2.exe")
            vmpop.automation.launch_program(path, arguments="/AcceptEula", terminate_after_time_s=1)

            # Traverse directories (back to the drive directory)
            dirs = list()
            dirs.append("{}\\{}".format(path_base, "RM2+Samples"))
            dirs.append("{}"    .format(path_base))
            vmpop.automation.change_dirs(dirs)

            # Copy a directory ("RM2+Samples") to Desktop ("%UserProfile%\Desktop")
            src_path = "{}\\{}".format(path_base, "RM2+Samples")
            dst_path = "%UserProfile%\\Desktop\\RM2+Samples"
            vmpop.automation.copy_files(src_path, dst_path)

            # Focus on Windows Explorer
            vmpop.automation.set_foreground_window(window_title=path_base)

            # Close the current directory (terminate explorer.exe)
            vmpop.automation.close_window(evtlog_off=False)

            # Detach a USB device
            vmpop.automation.detach_usb(serial_number)

            # Open a directory (explorer.exe)
            path_base = "%UserProfile%\\Desktop\\RM2+Samples"
            vmpop.automation.open_shell(path_base)

            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}".format(path_base, "dir-1"))
            vmpop.automation.change_dirs(dirs)

            # Open files in the current directory
            path_base_ps = "$Env:UserProfile\\Desktop\\RM2+Samples"  # for launching program, use PowerShell style path
            path_app = list()
            path_app.append("C:\\Program Files\\qBittorrent\\qbittorrent.exe")
            path_app.append("C:\\Program Files (x86)\\qBittorrent\\qbittorrent.exe")

            for app in path_app:
                if vmpop.hypervisor.file_exists(app) is False:
                    continue
                for idx in range(2):
                    path_file = "`\"{}\\{}`\"".format(path_base_ps, "dir-1\\p{}.torrent".format(idx+1))
                    vmpop.automation.launch_program(
                        path_file=path_file,
                        focus_to_pid=True, keystrokes=[['ENTER', 'ENTER'], [], 1000, "Click 'I agree' and 'Okay'"],
                        terminate_after_time_s=1
                    )
                    # if ret is True:  # Alternative of 'keystrokes' and 'terminate_after_time_s' parameters
                    #     vmpop.automation.set_foreground_window(pid=pid)
                    #     vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0)  # 'I agree' button
                    #     vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0)  # 'Okay'
                    #     vmpop.automation.terminate_process(pid=pid)

            # Focus on Windows Explorer
            vmpop.automation.set_foreground_window(window_title="dir-1")

            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}\\{}"    .format(path_base, "dir-1", "dir-1-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, "dir-1", "dir-1-1", "dir-1-1-1"))
            vmpop.automation.change_dirs(dirs)

            # Open files in the current directory
            path_base_ps = "$Env:UserProfile\\Desktop\\RM2+Samples\\dir-1\\dir-1-1\\dir-1-1-1"
            ext = ['mp4']*2 + ['avi']*2 + ['mov']*2 + ['wmv']*2 + ['3gp']*2
            path_app = list()
            path_app.append("C:\\Program Files\\Windows Media Player\\wmplayer.exe")
            path_app.append("C:\\Program Files\\VideoLAN\\VLC\\vlc.exe")
            path_app.append("C:\\Program Files (x86)\\VideoLAN\\VLC\\vlc.exe")
            path_app.append("C:\\Program Files\\DAUM\\PotPlayer\\PotPlayerMini.exe")
            path_app.append("C:\\Program Files (x86)\\DAUM\\PotPlayer\\PotPlayerMini.exe")

            for app in path_app:
                if vmpop.hypervisor.file_exists(app) is False:
                    continue

                keys = [[], [], 85]
                if app.find("PotPlayerMini.exe") > 0:
                    keys = [['SPACE'], [], 85, "Pause"]

                for idx in range(10):
                    path_file = "`\"{}\\{}`\"".format(path_base_ps, "video{}.{}".format(idx+1, ext[idx]))
                    vmpop.automation.launch_program(
                        path_file=app, arguments=path_file,
                        focus_to_pid=True, keystrokes=keys, terminate_after_time_s=1
                    )

            # Focus on Windows Explorer
            vmpop.automation.set_foreground_window(window_title="dir-1-1-1")

            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}\\{}"    .format(path_base, "dir-1", "dir-1-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, "dir-1", "dir-1-1", "dir-1-1-2"))
            vmpop.automation.change_dirs(dirs)

            # Open files in the current directory
            path_base_ps = "$Env:UserProfile\\Desktop\\RM2+Samples\\dir-1\\dir-1-1\\dir-1-1-2"
            ext = ['png']*2 + ['tiff']*2 + ['gif']*2 + ['jpg']*2 + ['bmp']*2
            path_app = "C:\\Windows\\System32\\mspaint.exe"
            if vmpop.hypervisor.file_exists(path_app) is True:
                for idx in range(10):
                    path_file = "`\"{}\\{}`\"".format(path_base_ps, "image{}.{}".format(idx+1, ext[idx]))
                    vmpop.automation.launch_program(
                        path_file=path_app, arguments=path_file,
                        focus_to_pid=True, terminate_after_time_s=1
                    )

            path_app = "C:\\Windows\\System32\\rundll32.exe"
            if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
                path_dll = "$Env:SystemRoot\\System32\\shimgvw.dll"  # Windows Picture and Fax Viewer
            elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
                path_dll = "$Env:ProgramFiles\\Windows Photo Gallery\\PhotoViewer.dll"  # Windows Photo Gallery
            else:
                path_dll = "$Env:ProgramFiles\\Windows Photo Viewer\\PhotoViewer.dll"  # Windows Photo Viewer
            if vmpop.hypervisor.file_exists(path_app) is True:
                for idx in range(10):
                    path_file = "{}\\{}".format(path_base_ps, "image{}.{}".format(idx+1, ext[idx]))
                    arguments = "`\"{}`\", ImageView_Fullscreen {}".format(path_dll, path_file)
                    vmpop.automation.launch_program(
                        path_file=path_app, arguments=arguments,
                        focus_to_pid=True, terminate_after_time_s=1
                    )

            # Focus on Windows Explorer
            vmpop.automation.set_foreground_window(window_title="dir-1-1-2")

            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}\\{}".format(path_base, "dir-1", "dir-1-1"))
            vmpop.automation.change_dirs(dirs)

            # Open files in the current directory
            path_base_ps = "$Env:UserProfile\\Desktop\\RM2+Samples\\dir-1\\dir-1-1"
            ext = ['mp3']*2 + ['wav']*2
            path_app = list()
            path_app.append("C:\\Program Files\\Windows Media Player\\wmplayer.exe")
            path_app.append("C:\\Program Files\\VideoLAN\\VLC\\vlc.exe")
            path_app.append("C:\\Program Files (x86)\\VideoLAN\\VLC\\vlc.exe")
            path_app.append("C:\\Program Files\\DAUM\\PotPlayer\\PotPlayerMini.exe")
            path_app.append("C:\\Program Files (x86)\\DAUM\\PotPlayer\\PotPlayerMini.exe")

            for app in path_app:
                if vmpop.hypervisor.file_exists(app) is False:
                    continue

                keys = [[], [], 85]
                if app.find("PotPlayerMini.exe") > 0:
                    keys = [['SPACE'], [], 85, "Pause"]

                for idx in range(4):
                    path_file = "`\"{}\\{}`\"".format(path_base_ps, "audio{}.{}".format(idx+1, ext[idx]))
                    vmpop.automation.launch_program(
                        path_file=app, arguments=path_file,
                        focus_to_pid=True, keystrokes=keys, terminate_after_time_s=1
                    )

            # Focus on Windows Explorer
            vmpop.automation.set_foreground_window(window_title="dir-1-1")

            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"    .format(path_base, "dir-1"))
            dirs.append("{}\\{}\\{}".format(path_base, "dir-1", "dir-1-2"))
            vmpop.automation.change_dirs(dirs)

            # Open files in the current directory
            path_base_ps = "$Env:UserProfile\\Desktop\\RM2+Samples\\dir-1\\dir-1-2"

            # Open PDF files
            pf = "Program Files" if vmpop.vm_os_type.code % 2 == 0 else "Program Files (x86)"
            targets = list()
            targets.append(("$Env:SystemDrive\\{}\\Adobe\\Reader 11.0\\Reader\\AcroRd32.exe", "document1.pdf"))
            targets.append(("$Env:SystemDrive\\{}\\Adobe\\Reader 11.0\\Reader\\AcroRd32.exe", "document2.pdf"))

            for path_exe, filename in targets:
                arguments = "`\"{}\\{}`\"".format(path_base_ps, filename)
                vmpop.automation.launch_program(
                    path_file=path_exe.format(pf), arguments=arguments,
                    focus_to_pid=True, terminate_after_time_s=2
                )

            # Open office files
            if VmPopOSType.Windows7.code <= vmpop.vm_os_type.code:
                # == MS Office 2016 does not support Windows XP and Vista
                pf = "$Env:SystemDrive\\Program Files"
                targets = list()
                targets.append(("{}\\Microsoft Office\\root\\Office16\\POWERPNT.EXE", "document3.pptx"))
                targets.append(("{}\\Microsoft Office\\root\\Office16\\POWERPNT.EXE", "document4.pptx"))
                targets.append(("{}\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "document5.docx"))
                targets.append(("{}\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "document6.docx"))
                targets.append(("{}\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "document7.xlsx"))
                targets.append(("{}\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "document8.xlsx"))

                for path_exe, filename in targets:
                    arguments = "`\"{}\\{}`\"".format(path_base_ps, filename)
                    vmpop.automation.launch_program(
                        path_file=path_exe.format(pf), arguments=arguments, maximize=True, wait_s=3,
                        focus_to_pid=True, keystrokes=[['ESC'], [], 85, "Close the MS Office Activation Wizard"],
                        terminate_after_time_s=2
                    )
                    # if ret is True:  # Alternative of 'keystrokes' and 'terminate_after_time_s' parameters
                    #     time.sleep(2)
                    #     vmpop.hypervisor.click_mouse_left_button_at_center()
                    #     vmpop.hypervisor.send_event_keyboard(['ESC'], delay_s=2.0)
                    #     vmpop.automation.terminate_process(pid=pid)

            # Focus on Windows Explorer
            vmpop.automation.set_foreground_window(window_title="dir-1-2")

            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"    .format(path_base, "dir-1"))
            dirs.append("{}\\{}\\{}".format(path_base, "dir-1", "dir-1-3"))
            vmpop.automation.change_dirs(dirs)

            # Open files in the current directory
            path_base_ps = "$Env:UserProfile\\Desktop\\RM2+Samples\\dir-1\\dir-1-3"
            ext = ['txt']*2 + ['html']*2 + ['xml']*2
            path_app = list()
            path_app.append("C:\\Windows\\System32\\notepad.exe")
            path_app.append("C:\\Program Files\\Notepad++\\notepad++.exe")
            path_app.append("C:\\Program Files (x86)\\Notepad++\\notepad++.exe")
            path_app.append("C:\\Program Files\\Internet Explorer\\iexplore.exe")
            path_app.append("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
            path_app.append("C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe")

            for app in path_app:
                if vmpop.hypervisor.file_exists(app) is False:
                    continue
                for idx in range(6):
                    path_file = "{}\\{}".format(path_base_ps, "text{}.{}".format(idx+1, ext[idx]))
                    vmpop.automation.launch_program(
                        path_file=app, arguments=path_file,
                        focus_to_pid=True, terminate_after_time_s=1
                    )

            # Focus on Windows Explorer
            vmpop.automation.set_foreground_window(window_title="dir-1-3")

            # Traverse directories
            dirs = list()
            dirs.append("{}\\{}"    .format(path_base, "dir-1"))
            dirs.append("{}\\{}\\{}".format(path_base, "dir-1", "dir-1-4"))
            vmpop.automation.change_dirs(dirs)

            # Open files & extract compressed items in the current directory
            path_base_ps = "$Env:UserProfile\\Desktop\\RM2+Samples\\dir-1\\dir-1-4"
            ext = ['7z'] + ['bz2'] + ['gz'] + ['tar'] + ['rar'] + ['zip']
            path_app = list()
            path_app.append("C:\\Program Files\\7-Zip\\7zFM.exe")
            path_app.append("C:\\Program Files (x86)\\7-Zip\\7zFM.exe")

            for app in path_app:
                if vmpop.hypervisor.file_exists(app) is False:
                    continue
                for idx in range(6):
                    path_file = "`\"{}\\{}`\"".format(path_base_ps, "archive{}.{}".format(idx+1, ext[idx]))
                    vmpop.automation.launch_program(
                        path_file=app, arguments=path_file,
                        focus_to_pid=True, keystrokes=[['F5', 'ENTER'], [], 1500, "Extract files here"],
                        terminate_after_time_s=2
                    )

            # Focus on Windows Explorer
            vmpop.automation.set_foreground_window(window_title="dir-1-4")

            # Close the current directory (terminate explorer.exe)
            vmpop.automation.close_window(evtlog_off=False)

        # if the system does not support GPT, then return
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            return

        # Attach a USB device
        serial_number = self.rm3  # GPT & NTFS
        usb_drive_letter = vmpop.automation.attach_usb(serial_number)

        path_base = usb_drive_letter
        if path_base is not None:
            # Open a directory (explorer.exe)
            vmpop.automation.open_shell(path_base)

            # Traverse directories
            root_dir = "RM3+Samples"
            dirs = list()
            dirs.append("{}\\{}"        .format(path_base, root_dir))
            dirs.append("{}\\{}\\{}"    .format(path_base, root_dir, "dir-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, root_dir, "dir-1", "dir-1-1"))
            dirs.append("{}\\{}\\{}"    .format(path_base, root_dir, "dir-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, root_dir, "dir-1", "dir-1-2"))
            dirs.append("{}\\{}\\{}"    .format(path_base, root_dir, "dir-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, root_dir, "dir-1", "dir-1-3"))
            dirs.append("{}\\{}\\{}"    .format(path_base, root_dir, "dir-1"))
            dirs.append("{}\\{}\\{}\\{}".format(path_base, root_dir, "dir-1", "dir-1-4"))
            dirs.append("{}\\{}\\{}"    .format(path_base, root_dir, "dir-1"))
            vmpop.automation.change_dirs(dirs)

            # Open a file in the current directory
            path = "{}\\{}".format(path_base, root_dir + "\\dir-1\\executable1.exe")
            ret, pid = vmpop.automation.launch_program(path, focus_to_pid=True)
            if ret is True:
                vmpop.automation.terminate_process(name="executable1")

            # Open a file in the current directory
            path = "{}\\{}".format(path_base, root_dir + "\\dir-1\\executable2.exe")
            vmpop.automation.launch_program(path, arguments="/AcceptEula", terminate_after_time_s=1)

            # Focus on Windows Explorer
            vmpop.automation.set_foreground_window(window_title="dir-1")

            # Traverse directories (back to the drive directory)
            dirs = list()
            dirs.append("{}\\{}".format(path_base, root_dir))
            dirs.append("{}".format(path_base))
            vmpop.automation.change_dirs(dirs)

            # Copy a directory ("RM3+Samples") to Desktop ("%UserProfile%\Desktop")
            src_path = "{}\\{}".format(path_base, root_dir)
            dst_path = "%UserProfile%\\Desktop\\" + root_dir
            vmpop.automation.copy_files(src_path, dst_path)

            # Focus on Windows Explorer
            vmpop.automation.set_foreground_window(window_title=path_base)

            # Close the current directory (terminate explorer.exe)
            vmpop.automation.close_window(evtlog_off=False)

            # Detach a USB device
            vmpop.automation.detach_usb(serial_number)

        return

    def action_stage_6(self, vmpop):
        """ACTIONS with special features Part I
            : Searching keywords and Sharing directories in Windows

        Args:
            vmpop (VmPop)
        """
        '''Start with 'CFTT' account'''
        # Search keywords through Windows Search feature
        #    (English)  hello
        #    (Spanish)  ¡Hola!
        #    (Korean)   안녕하세요
        #    (Russia)   Здравствуйте!
        #    (Chinese)  你好
        #    (Japanese) 今日は
        #    (Hindi)    नमस्ते
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            keywords = ['hello', '¡Hola!', 'Здравствуйте!']  # XP or lower
        else:
            keywords = ['hello', '¡Hola!', '안녕하세요', 'Здравствуйте!', '你好', '今日は', 'नमस्ते']

        for k in keywords:
            vmpop.automation.search_keyword(k)
            if VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
                # Restart 'Cortana' process (it's for Windows 10 RS1 -> bug?)
                vmpop.automation.terminate_process(name="SearchUI", evtlog_off=True)
                time.sleep(3.5)

        # Share a directory ("c:\\welcome")
        path = "c:\\welcome"  # (English) welcome == 환영합니다 (Korean)
        name = "welcome"
        vmpop.automation.share_directory(path, name)

        # Share a directory ("c:\\¡Hola!")
        path = "c:\\¡Hola!"
        name = "¡Hola!"
        vmpop.automation.share_directory(path, name)

        if VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code:
            # Share a directory ("c:\\환영합니다")
            path = "c:\\환영합니다"
            name = "환영합니다"
            vmpop.automation.share_directory(path, name)

        # == Windows 10 ==
        if VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            # Check messages in 'Notification Center'
            vmpop.automation.check_notification_center()

            # Actions relating to Virtual Desktop
            names = ['1st', '2nd', '3rd']
            for idx in range(3):
                # Create a new virtual desktop
                vmpop.automation.create_virtual_desktop()

                # Start of the event monitor
                vmpop.automation.evtmon.start("Creating the {} text file in a new virtual desktop".format(names[idx]))

                # Launch 'Notepad.exe' through Windows Run
                vmpop.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.5, note="Windows Run")
                vmpop.hypervisor.send_event_keyboard("notepad", delay_s=1.0)
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Launch Notepad.exe")

                # Write something
                msg = "This is the {} virtual desktop.\n\n\nLet's save this file.".format(names[idx])
                vmpop.hypervisor.send_event_keyboard(msg, delay_s=2.0)

                # Save it and close the process
                vmpop.hypervisor.send_event_keyboard('s', ['CTRL'], delay_s=1.5, note="Save As")
                vmpop.hypervisor.send_event_keyboard("{}_virtual_desktop".format(names[idx]), delay_s=1.0)
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Save a text file")
                vmpop.automation.close_window()

                # End of the event monitor
                vmpop.automation.evtmon.stop()

            for idx in range(3):
                # Close all three virtual desktops
                vmpop.automation.close_virtual_desktop()

        return

    def action_stage_7(self, vmpop):
        """ACTIONS with special features Part II
            : Connecting network drive and remote desktop in Windows

        Args:
            vmpop (VmPop)
        """
        '''Start with 'CFTT' account'''
        # Connect a network drive
        url = "\\\\10.11.11.127\\NETWORK_DIR"
        id = "cfreds-server1"
        pw = "cs1nist"
        vmpop.automation.connect_network_drive(url, id, pw)

        # Traverse directories
        dirs = list()
        dirs.append("{}\\{}"        .format(url, "ND+Samples"))
        dirs.append("{}\\{}\\{}"    .format(url, "ND+Samples", "dir-1"))
        dirs.append("{}\\{}\\{}\\{}".format(url, "ND+Samples", "dir-1", "dir-1-1"))
        dirs.append("{}\\{}\\{}"    .format(url, "ND+Samples", "dir-1"))
        dirs.append("{}\\{}\\{}\\{}".format(url, "ND+Samples", "dir-1", "dir-1-2"))
        dirs.append("{}\\{}\\{}"    .format(url, "ND+Samples", "dir-1"))
        dirs.append("{}\\{}\\{}\\{}".format(url, "ND+Samples", "dir-1", "dir-1-3"))
        dirs.append("{}\\{}\\{}"    .format(url, "ND+Samples", "dir-1"))
        dirs.append("{}\\{}\\{}\\{}".format(url, "ND+Samples", "dir-1", "dir-1-4"))
        vmpop.automation.change_dirs(dirs)

        # Open files in the current directory
        path_base_ps = "{}\\ND+Samples\\dir-1\\dir-1-4".format(url)
        ext = ['7z'] + ['bz2'] + ['gz'] + ['tar'] + ['rar'] + ['zip']
        path_app = list()
        path_app.append("C:\\Program Files\\7-Zip\\7zFM.exe")
        path_app.append("C:\\Program Files (x86)\\7-Zip\\7zFM.exe")

        for app in path_app:
            if vmpop.hypervisor.file_exists(app) is False:
                continue
            for idx in range(6):
                path_file = "`\"{}\\{}`\"".format(path_base_ps, "archive{}.{}".format(idx+1, ext[idx]))
                vmpop.automation.launch_program(
                    path_file=app, arguments=path_file,
                    focus_to_pid=True, terminate_after_time_s=1
                )

        # Focus on Windows Explorer
        vmpop.automation.set_foreground_window(window_title="dir-1-4")

        # Close the current window
        vmpop.automation.close_window(evtlog_off=False)

        # Restart the system & Restore the user session
        vmpop.automation.restart(mode=VmPopFunctionMode.HV)

        # Select "CFTT" account
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN', 'DOWN'], note="Select 'CFTT' account")
        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_DEL'], ['CTRL', 'ALT'])
            vmpop.hypervisor.send_event_keyboard(['E_RIGHT', 'ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows7.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_RIGHT', 'ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows8.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="Select 'CFTT' account")

        # Logon "CFTT" account with a valid password
        vmpop.automation.logon_account("CFTT", "cftt@nist")

        # Map a network drive
        drive = "w"
        url = "\\\\10.11.11.127\\NETWORK_DIR"
        id = "cfreds-server1"
        pw = "cs1nist"
        vmpop.automation.map_network_drive(drive, url, id, pw)

        # Open a directory (explorer.exe)
        path_base = "{}:".format(drive)
        vmpop.automation.open_shell(path_base)

        # Traverse directories
        dirs = list()
        dirs.append("{}\\{}"        .format(path_base, "ND+Samples"))
        dirs.append("{}\\{}\\{}"    .format(path_base, "ND+Samples", "dir-1"))
        dirs.append("{}\\{}\\{}\\{}".format(path_base, "ND+Samples", "dir-1", "dir-1-1"))
        dirs.append("{}\\{}\\{}"    .format(path_base, "ND+Samples", "dir-1"))
        dirs.append("{}\\{}\\{}\\{}".format(path_base, "ND+Samples", "dir-1", "dir-1-2"))
        vmpop.automation.change_dirs(dirs)

        # Open files in the current directory
        path_base_ps = "{}:\\ND+Samples\\dir-1\\dir-1-2".format(drive)

        # Open PDF files
        pf = "Program Files" if vmpop.vm_os_type.code % 2 == 0 else "Program Files (x86)"
        targets = list()
        targets.append(("$Env:SystemDrive\\{}\\Adobe\\Reader 11.0\\Reader\\AcroRd32.exe", "document1.pdf"))
        targets.append(("$Env:SystemDrive\\{}\\Adobe\\Reader 11.0\\Reader\\AcroRd32.exe", "document2.pdf"))

        for path_exe, filename in targets:
            arguments = "`\"{}\\{}`\"".format(path_base_ps, filename)
            vmpop.automation.launch_program(
                path_file=path_exe.format(pf), arguments=arguments,
                focus_to_pid=True, terminate_after_time_s=2
            )

        # Open office files
        if VmPopOSType.Windows7.code <= vmpop.vm_os_type.code:
            # == MS Office 2016 does not support Windows XP and Vista
            pf = "$Env:SystemDrive\\Program Files"
            targets = list()
            targets.append(("{}\\Microsoft Office\\root\\Office16\\POWERPNT.EXE", "document3.pptx"))
            targets.append(("{}\\Microsoft Office\\root\\Office16\\POWERPNT.EXE", "document4.pptx"))
            targets.append(("{}\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "document5.docx"))
            targets.append(("{}\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "document6.docx"))
            targets.append(("{}\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "document7.xlsx"))
            targets.append(("{}\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "document8.xlsx"))

            for path_exe, filename in targets:
                arguments = "`\"{}\\{}`\"".format(path_base_ps, filename)
                vmpop.automation.launch_program(
                    path_file=path_exe.format(pf), arguments=arguments, maximize=True, wait_s=3,
                    focus_to_pid=True, keystrokes=[['ESC'], [], 85, "Close the MS Office Activation Wizard"],
                    terminate_after_time_s=2
                )

        # Focus on Windows Explorer
        vmpop.automation.set_foreground_window(window_title="dir-1-2")

        # Close the current window
        vmpop.automation.close_window(evtlog_off=False)

        # Connect a remote desktop using ' mstsc.exe'
        url = "10.11.11.127"
        id = "cfreds-server1"
        pw = "cs1nist"
        vmpop.automation.connect_remote_desktop(url=url, account_id=id, account_pw=pw)

        # Disconnect it
        time.sleep(20)
        vmpop.automation.disconnect_remote_desktop()
        return

    def action_stage_8(self, vmpop):
        """ACTIONS for Anti-Forensics
            : Deleting registry data and Uninstalling applications

        Args:
            vmpop (VmPop)
        """
        '''Start with 'CFTT' account'''
        # == Windows 8.1 or higher  ==
        if VmPopOSType.Windows81.code <= vmpop.vm_os_type.code:
            # Logoff the current session "CFTT"
            vmpop.automation.logoff_account(delay_s=60)

            # Select "cftt.user1@outlook.com" account
            if VmPopOSType.Windows81.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
                vmpop.hypervisor.send_event_keyboard(['ESC'], delay_s=1.0)
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB', 'TAB', 'TAB', 'TAB'], note="To the 6th account")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'cftt.user1@outlook.com' account")
            elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the first item of account list")
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB', 'TAB', 'TAB', 'TAB'], note="To the 6th account")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'cftt.user1@outlook.com' account")

            # Logon "cftt.user1@outlook.com" account
            if VmPopOSType.Windows81.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
                vmpop.automation.logon_account("cftt.user1@outlook.com", "tkdydwk.Tldpvmxlxl1#%0")
            elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
                vmpop.automation.logon_account("cftt.user1@outlook.com", "tkdydwk.Tldpvmxlxl1#%0", pin="1234321")

            # [U] Dropbox and Facebook
            app_names = ["Dropbox", "Facebook"]
            for name in app_names:
                vmpop.automation.uninstall_win_store_app(name)

            # Logoff the current session "cftt.user1@outlook.com"
            vmpop.automation.logoff_account(delay_s=40)

            # Select "CFTT" account
            if VmPopOSType.Windows81.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows81_64.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
                vmpop.hypervisor.send_event_keyboard(['TAB'])
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")
            elif VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the first item of account list")
                vmpop.hypervisor.send_event_keyboard(['TAB', 'TAB'], note="To the third account")
                vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Select 'CFTT' account")

            # Logon "CFTT" account with a valid password
            vmpop.automation.logon_account("CFTT", "cftt@nist")

        # Disable the network
        vmpop.automation.disable_nic()

        # Restart the system & Restore the user session
        vmpop.automation.restart(mode=VmPopFunctionMode.HV)

        # Select "CFTT" account
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            vmpop.hypervisor.send_event_keyboard(['DOWN', 'DOWN'], note="Select 'CFTT' account")
        elif VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_DEL'], ['CTRL', 'ALT'])
            vmpop.hypervisor.send_event_keyboard(['E_RIGHT', 'ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows7.code <= vmpop.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            vmpop.hypervisor.send_event_keyboard(['E_RIGHT', 'ENTER'], note="Select 'CFTT' account")
        elif VmPopOSType.Windows8.code <= vmpop.vm_os_type.code:
            vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="Select 'CFTT' account")

        # Logon "CFTT" account with a valid password
        vmpop.automation.logon_account("CFTT", "cftt@nist")

        # Set the system time (+ 24h)
        vmpop.automation.set_date_time(offset=86400)

        # Create a backup (Restore Point or Volume Shadow Copy)
        vmpop.automation.create_restore_point(
            drive="C:\\", description="2nd manual restore point",
            rp_type=VmPopRPType.MODIFY_SETTINGS
        )

        # Delete 'Temporary' account
        vmpop.automation.delete_account("Temporary")

        # [U] qBittorrent (NSIS)
        vmpop.automation.uninstall_program(program_name="qBittorrent", arguments="/S")

        # [U] Evernote (MSI)
        vmpop.automation.uninstall_program(program_name="evernote", arguments="/qb", timeout_ms=180000)

        # Set the system time (+ 24h)
        vmpop.automation.set_date_time(offset=86400)

        # Create a backup (Restore Point or Volume Shadow Copy)
        vmpop.automation.create_restore_point(
            drive="C:\\", description="3rd manual restore point",
            rp_type=VmPopRPType.APPLICATION_UNINSTALL
        )

        # [L]&[T] CCleaner --> Clear artifacts using CCleaner (with default settings)
        target = "C:\\Program Files\\CCleaner\\CCleaner.exe"
        if vmpop.hypervisor.file_exists(target) is True:
            arguments = "/AUTO"
            ret, pid = vmpop.automation.launch_program(
                path_file=target, arguments=arguments)
            if ret is True:
                time.sleep(3)
                vmpop.automation.terminate_process(name="ccleaner")

        # Set the default path of 'RegEdit.exe' which is related to 'CCleaner'
        if vmpop.vm_os_type.code < VmPopOSType.WindowsVista.code:
            reg_data = "My Computer\\HKEY_CURRENT_USER\\Software\\Piriform"
        else:
            reg_data = "Computer\\HKEY_CURRENT_USER\\Software\\Piriform"
        reg_path = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit"
        vmpop.automation.set_reg_value(path=reg_path, value="LastKey", data=reg_data)

        # [L] 'RegEdit.exe' through [Win + R]
        vmpop.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.5, note="Windows Run")
        vmpop.hypervisor.send_event_keyboard('regedit', delay_s=1.5)
        vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="Launch RegEdit.exe")

        # Delete a registry key manually
        vmpop.hypervisor.send_event_keyboard(['E_DEL'], delay_s=2.0)
        vmpop.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="Delete a key")

        # [T] 'RegEdit.exe' (the current window)
        vmpop.automation.close_window(evtlog_off=False)

        # == Windows 10 ==
        if VmPopOSType.Windows10.code <= vmpop.vm_os_type.code:
            # Check messages in 'Notification Center'
            vmpop.automation.check_notification_center()

        # Set the system time (- 48h) : Reset the time to normal
        vmpop.automation.set_date_time(offset=(86400 * -2))

        # Shutdown the system
        vmpop.automation.shutdown(VmPopFunctionMode.HV)
        return

    def set_common_preferences(self):
        """Set common VirtualBox preferences (just for test)
            - This is sample codes for users, so it's not called in this class
            - Sample codes for setting VirtualBox preferences
                (1) Add a new NAT network to VirtualBox
                (2) Enable USB 2.0

        Return:
            True or False
        """
        import virtualbox

        try:
            vbox = virtualbox.VirtualBox()
        except:
            print("Cannot load 'vboxapi'")
            return False

        # Add a new NAT network to VirtualBox
        nat_name = "NatCFReDS"
        network = "10.11.11.0/24"

        try:
            nat = vbox.find_nat_network_by_name(nat_name)
        except:
            nat = vbox.create_nat_network(nat_name)
            nat.network = network
            pass

        # Config to enable USB 2.0 on all VMs
        for machine in vbox.machines:
            try:
                session = machine.create_session()
                session.machine.add_usb_controller(
                    "EHCI", virtualbox.library.USBControllerType.ehci  # Enable USB 2.0
                )
                session.machine.save_settings()  # Should be called for saving settings
            except:
                pass
                # adapter = session.machine.get_network_adapter(0)
                # adapter.enabled = True
                # adapter.attachment_type = virtualbox.library.NetworkAttachmentType.host_only
                # adapter.nat_network = name
                # adapter.promisc_mode_policy = virtualbox.library.NetworkAdapterPromiscModePolicy.allow_network
        return True


def main():
    t1 = time.clock()
    print('[VMPOP][START] \'cfreds-2017-winreg\'')

    try:
        vs = VmPopScenarioCFReDS2017WinReg()
        vs.start()
    except:
        print(traceback.format_exc())

    t2 = time.clock()
    print('[VMPOP][END] Operation took %0.2f sec' % (t2-t1))


if __name__ == "__main__":
    main()
