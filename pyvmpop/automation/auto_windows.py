# -*- coding: utf-8 -*-

"""AutoWindows (subclass of AutoBase)

    * Description
        Core class for Windows automation
"""

import os
import time
import base64
import logging
from pyvmpop.common_defines import *
from pyvmpop.logging.actlog_manager import ActionItem
from pyvmpop.monitoring.evtmon_windows import EvtMonWindows
from .auto_base import AutoBase


class AutoWindows(AutoBase):
    """AutoWindows class

    Attributes:
        Refer to AutoBase on the common attributes

        path_cmd (str): The full path of cmd.exe
        path_powershell (str): The full path of powershell.exe
        path_tzutil (str): The full path of tzutil.exe
        path_ga (str): The full path of an executable file in Guest Additions
        uac_off (bool): If True, UAC is turned off
    """

    def __init__(self, vmpop):
        """The constructor

        Args:
            vmpop (VmPop): The active VmPop instance
        """
        super(AutoWindows, self).__init__(vmpop)

        # Default file paths for automating actions in Windows
        self.path_cmd = "C:\\Windows\\System32\\cmd.exe"
        self.path_powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        self.path_tzutil = "C:\\Windows\\System32\\tzutil.exe"
        self.path_ga = "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxControl.exe"
        self.uac_off = False

        # Logging and event manager
        self.prglog_mgr = logging.getLogger(__name__)

        if self.vm_os_type.code % 2 == 0:  # 32 bits
            self.evtmon = EvtMonWindows(vmpop, VmPopEvtMonType.WIN_PROCMON_32)
        else:
            self.evtmon = EvtMonWindows(vmpop, VmPopEvtMonType.WIN_PROCMON_64)
        return

    '''
    #-----------------------------------------------------------------------------------
    # Pre-requirements for Windows
    #-----------------------------------------------------------------------------------
    '''
    def pre_requirements(self):
        """Check pre requirements

            1. Common scripts
                - get_date_time_windows.bat
                - check_process_exist_windows.bat
                - wait_for_idle_windows.bat

            2. Packages for XP, Vista

            3. Agent program
                - //monitor//procmon.exe
                - //monitor//procmon_vmpop.pmc

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): Check pre-requirements".format(GET_MY_NAME()))

        paths = list()
        paths.append(self.shared_dir_host + "\\windows\\get_date_time_windows.bat")
        paths.append(self.shared_dir_host + "\\windows\\check_process_exist_windows.bat")
        paths.append(self.shared_dir_host + "\\windows\\wait_for_idle_windows.bat")
        paths.append(self.shared_dir_host + "\\windows\\monitor\\procmon.exe")
        # paths.append(self.shared_dir_host + "\\windows\\monitor\\procmon_vmpop.pmc")
        paths.append(self.shared_dir_host + "\\windows\\pre-requirements\\Windows6.0-KB2556308-v3-x86.msu")  # Vista
        paths.append(self.shared_dir_host + "\\windows\\pre-requirements\\Windows6.0-KB2556308-v3-x64.msu")  # Vista
        # paths.append(self.shared_dir_host + "\\windows\\pre-requirements\\NetFx20SP2_x86.exe")  # XP
        # paths.append(self.shared_dir_host + "\\windows\\pre-requirements\\WindowsXP-KB968930-x86-ENG.exe")  # XP
        # paths.append(self.shared_dir_host + "\\windows\\pre-requirements\\rktools.msi")  # XP

        count = 0
        for path in paths:
            if os.path.exists(path) is False:
                self.prglog_mgr.debug("{}(): A required file does not exist ({})".format(GET_MY_NAME(), path))
                continue
            count += 1

        if count == len(paths):
            return True
        return False

    '''
    #-----------------------------------------------------------------------------------
    # Basic functions for Windows
    #-----------------------------------------------------------------------------------
    '''
    @staticmethod
    def encode_powershell_script(script):
        """Encode a powershell script

        Args:
            script (str): PowerShell script

        Returns:
            Based 64 encoded script (str)
        """
        unicode = script.encode("UTF-16LE")
        encoded = base64.b64encode(unicode)
        return encoded

    def execute_powershell_script(self, script, do_not_wait=False, timeout_ms=60000, delay_s=0.1,
                                  filemode=False, handling_uac=False, run_as_admin=False):
        """Execute a powershell script in the Guest VM

        This function is revised from the internal function of pyvbox

        Args:
            script (str): PowerShell script to execute
            do_not_wait (bool): if True, then do not wait after executing the process
            timeout_ms (int): Timeout (ms)
            delay_s (float): Delay (second) after completing the execution (default: 0.1)
            filemode (bool): if True, 'filemode' is on
            handling_uac (bool): if True, handling the UAC window
            run_as_admin (bool): if True, run the script as administrator privileges

        Returns:
            True (or False), output (str)
        """
        if self.vm_os_type.code < VmPopOSType.Windows8.code and self.uac_off is True:
            run_as_admin = False  # do not need to set this because UAC is turned off

        self.prglog_mgr.info(
            "{}(): TIMEOUT_MS({}), DELAY_S({}), RUN_AS_ADMIN({})".format(
                GET_MY_NAME(), timeout_ms, delay_s, run_as_admin
            )
        )

        if filemode is False:
            if run_as_admin is True:
                script = self.encode_powershell_script(WIN_PS_RUN_ADMIN + script + WIN_PS_SELF_TERMINATION)
            else:
                script = self.encode_powershell_script(script + WIN_PS_SELF_TERMINATION)
            arguments = WIN_PS_BASE_ARGUMENTS_FOR_ENC + [script]
        else:
            '''FILEMODE is necessary because of PowerShell's -enc length issue
                - maximum 915 bytes ? -> Why ? ...
                - http://stackoverflow.com/questions/33375528/powershell-encodedcommand-length-issue
            '''
            # Save the script to a file in the shared directory
            path_script_host = self.shared_dir_host_temp + "\\{}".format(WIN_PS_SCRIPT_NAME)
            f = open(path_script_host, 'wb')
            f.write(b'\xff\xfe')
            if run_as_admin is True:
                f.write(WIN_PS_RUN_ADMIN.encode('UTF-16LE'))
            f.write(script.encode('UTF-16LE'))
            if run_as_admin is False:
                f.write(WIN_PS_SELF_TERMINATION.encode('UTF-16LE'))
            f.close()

            path_script_vm = self.shared_dir_vm_temp + "\\{}".format(WIN_PS_SCRIPT_NAME)
            arguments = WIN_PS_BASE_ARGUMENTS_FOR_FILE + [path_script_vm]

        if 0 < timeout_ms:
            timeout_ms = 5000 if timeout_ms < 5000 else timeout_ms
        elif timeout_ms <= 0:
            timeout_ms = 0

        env = ["SEE_MASK_NOZONECHECKS=1"]  # To disable 'Open File Security Warning'

        try:
            process, stdout, stderr = self.hypervisor.execute_process(
                    self.path_powershell, arguments,
                    environment=env,
                    do_not_wait=do_not_wait,
                    timeout_ms=timeout_ms, delay_s=delay_s,
                    handling_uac=handling_uac
            )
        except:
            self.prglog_mgr.debug("{}(): Exception occurs".format(GET_MY_NAME()))
            return False, None

        if process is None:
            return False, None

        # Process the error message4
        if stderr != "" and len(stderr) > 16:
            ignore = False

            for msg in IGNORED_ERROR_MESSAGE_PS:
                if stderr.find(msg) >= 0:
                    ignore = True
                    break

            if ignore is False:
                stderr = stderr.strip().replace('\r\n', ' ')
                stderr = stderr[:120] + "..." if len(stderr) > 120 else stderr
                self.prglog_mgr.debug("{}(): [stderr] {}".format(GET_MY_NAME(), stderr))

        # Get the output (string)
        output = "" if stdout == "" else stdout
        return True, output

    def execute_batch_script(self, script, do_not_wait=False, timeout_ms=60000, delay_s=0.1,
                             run_as_admin=False):
        """Execute a batch script in the Guest VM

        Args:
            script (str): PowerShell script to execute
            do_not_wait (bool): if True, then do not wait after executing the process
            timeout_ms (int): Timeout (ms) (default: 2000)
            delay_s (float): Delay (second) after completing the execution (default: 0.1)
            run_as_admin (bool): if True, run the script as administrator privileges

        Returns:
            True (or False)
        """
        if self.vm_os_type.code < VmPopOSType.Windows8.code:
            run_as_admin = False  # do not need to set this because UAC is turned off

        self.prglog_mgr.info(
            "{}(): TIMEOUT_MS({}), DELAY_S({}), RUN_AS_ADMIN({})".format(
                GET_MY_NAME(), timeout_ms, delay_s, run_as_admin
            )
        )

        # Save the script to a file in the shared directory
        path_script_host = self.shared_dir_host_temp + "\\{}".format(WIN_BAT_SCRIPT_NAME)
        f = open(path_script_host, 'w')
        if run_as_admin is True:
            f.write(WIN_BAT_RUN_ADMIN)
        f.write(script)
        if run_as_admin is True:
            f.write(WIN_BAT_END_PROCESS)
        f.close()

        path_script_vm = self.shared_dir_vm_temp + "\\{}".format(WIN_BAT_SCRIPT_NAME)
        arguments = ['/C'] + [path_script_vm]

        if 0 < timeout_ms:
            timeout_ms = 5000 if timeout_ms < 5000 else timeout_ms
        elif timeout_ms <= 0:
            timeout_ms = 0

        env = ["SEE_MASK_NOZONECHECKS=1"]  # To disable 'Open File Security Warning'

        try:
            process, stdout, stderr = self.hypervisor.execute_process(
                    self.path_cmd, arguments,
                    environment=env,
                    hidden=True,
                    do_not_wait=do_not_wait,
                    timeout_ms=timeout_ms,
                    delay_s=delay_s
            )
        except Exception as e:
            self.prglog_mgr.debug("{}(): Exception occurs ({})".format(GET_MY_NAME(), e))
            return False, None

        if process is None:
            return None, "", ""

        # Process the error message4
        if stderr != "" and len(stderr) > 16:
            ignore = False

            for msg in IGNORED_ERROR_MESSAGE_BAT:
                if stderr.find(msg) >= 0:
                    ignore = True
                    break

            if ignore is False:
                stderr = stderr.strip().replace('\r\n', ' ')
                stderr = stderr[:120] + "..." if len(stderr) > 120 else stderr
                self.prglog_mgr.debug("{}(): [stderr] {}".format(GET_MY_NAME(), stderr))

        # Get the output (string)
        output = None if stdout == "" else stdout
        return True, output

    def close_window(self, evtlog_off=True):
        """Close the current window

            - ALT + F4

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_COMMON,
                       action=T_ACTION_CLOSE_WINDOW,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="ALT + F4")
        )

        if evtlog_off is False:
            self.evtmon.start(T_ACTION_CLOSE_WINDOW)

        ret = self.hypervisor.send_event_keyboard(['F4'], ['ALT'], delay_s=2.0, note="Close the current window")

        if evtlog_off is False:
            self.evtmon.stop()
        return ret

    def maximize_window(self):
        """Maximize the current window

            - ALT + SPACE, and then X

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_COMMON,
                       action=T_ACTION_MAXIMIZE_WINDOW,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="ALT + SPACE, and then 'X'")
        )

        self.hypervisor.send_event_keyboard(['SPACE'], ['ALT'], delay_s=1.0, note="Open the menu")
        ret = self.hypervisor.send_event_keyboard('x', delay_s=2.5, note="Click 'Maximize'")
        return ret

    def check_os_version(self):
        """Check the version of Windows

        Returns:
            version (string) or None
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        script = \
            '''
            (Get-CimInstance Win32_OperatingSystem).version
            '''

        ret, output = self.execute_powershell_script(script)
        if output is None:
            return None

        version = ""
        if len(output) > 0:
            version = output.replace("\r\n", "")
        return version

    def check_ie_version(self):
        """Check the version of the default IE

        Returns:
            version (string) or None
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        script = \
            '''
            (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer').Version
            '''

        ret, output = self.execute_powershell_script(script)
        if output is None:
            return None

        version = ""
        if len(output) > 0:
            version = output.replace("\r\n", "")

        self.prglog_mgr.info("{}(): IE version is {}".format(GET_MY_NAME(), version))
        return version

    def get_date_time(self, actlog_off=False):
        """Get the operating system date & time

        Args:
            actlog_off (bool): If True, do not write an action log

        Returns:
            d (str): Date (local time)
            t (str): Time (local time)
            z (str): Timezone
        """
        path_script_vm = self.shared_dir_vm + "\\windows\\get_date_time_windows.bat"
        arguments = ['/C'] + [path_script_vm]

        if self.hypervisor.shared_dir_vm_is_valid is False:
            self.prglog_mgr.debug("{}(): Shared directory is invalid (not found)".format(GET_MY_NAME()))
            return None, "", ""

        try:
            process, stdout, stderr = self.hypervisor.execute_process(
                self.path_cmd, arguments, hidden=True,
                timeout_ms=3500, actlog_off=actlog_off
            )
        except Exception as e:
            self.prglog_mgr.debug("{}(): Exception occurs ({})".format(GET_MY_NAME(), e))
            return None, "", ""

        if process is None:
            return None, "", ""

        if stdout is "":
            self.prglog_mgr.debug("{}(): No output".format(GET_MY_NAME()))
            return "", "", ""

        lines = stdout.split('\r\n')
        if len(lines) - 1 != 2:
            self.prglog_mgr.debug("{}(): No timezone (Date&Time only)".format(GET_MY_NAME()))
            return "", "", ""

        d, t, *rest = lines[0].split(' ')
        z = lines[1]
        return d, t, z

    def get_date_time_bak(self):
        """Get the operating system date & time (experimental)

            - Powershell scripts (it works, but too slow for logging)
                - Get local time
                    > Get-Date -format "yyyy-MM-dd HH:mm:ss"
                    > Get-Date -format "yyyy-MM-dd hh:mm:ss tt"
                - Get UTC time
                    > [System.DateTime]::UtcNow
                    > ((get-date).ToUniversalTime()).ToString("yyyy-MM-ddTHH:mm:ssZ")
                - Get the current timezone (old)
                    > $timezone = Get-WMIObject -class Win32_TimeZone
                    > $timezone.Description
                - Get the current timezone (new versions)
                    > [TimeZoneInfo]::Local.DisplayName

        Returns:
            d (str): Date (local time)
            t (str): Time (local time)
            z (str): Timezone
        """
        script = \
            '''
            Get-Date -format "yyyy-MM-dd HH:mm:ss"
            $timezone = Get-WMIObject -class Win32_TimeZone
            $timezone.Description
            '''

        ret, output = self.execute_powershell_script(script, timeout_ms=15000)
        if ret is False or output is None:
            return "", "", ""

        lines = output.split('\r\n')
        if len(lines) - 1 != 2:
            return "", "", ""

        d, t = lines[0].split(' ')
        z = lines[1]
        return d, t, z

    def check_process_exist(self, pid):
        """Check if a process with pid exists or nor

            wmic process where "ProcessID = {0}" get ProcessId | findstr /i {0} > NUL & echo %ERRORLEVEL%

        Args:
            pid (int): The target process ID

        Returns:
            True (exist) or False (non-exist) or None (exception)
        """
        path_script_vm = self.shared_dir_vm + "\\windows\\check_process_exist_windows.bat"
        arguments = ['/C'] + [path_script_vm] + [str(pid)]

        try:
            process, stdout, stderr = self.hypervisor.execute_process(
                self.path_cmd, arguments, timeout_ms=5000, actlog_off=True
            )
        except Exception as e:
            self.prglog_mgr.debug("{}(): Exception occurs ({})".format(GET_MY_NAME(), e))
            return None

        if process is None:
            return None, "", ""

        if stdout is "":
            return None

        lines = stdout.split('\r\n')
        if len(lines) != 2:
            return None

        if str(lines[0]) == '0':
            return True
        return False

    def speed_up_powershell(self):
        """Speed up the startup of Powershell

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        script = \
            '''
            $env:path = [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
            [AppDomain]::CurrentDomain.GetAssemblies() | % {
                if (! $_.location) { continue }
                $Name = Split-Path $_.location -leaf
                Write-Host -ForegroundColor Yellow "NGENing: $Name"  # Installing Dlls into Global Assembly Cache (GAC)
                ngen install $_.location | % {"`t$_"}
            }'''

        ret, output = self.execute_powershell_script(
            script, timeout_ms=60000, filemode=True, run_as_admin=True
        )
        if ret is False:
            return False
        return True

    def wait_for_idle(self, default_wait_s=0, timeout_ms=600000):
        """Wait until the system is idle

            1) Check the IDLE process: 75%+ for 5 seconds

        Args:
            default_wait_s (int): wait 'this value' at least
            timeout_ms (int): The timeout (the default is 10 minutes)

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): DEFAULT_WAIT_S({}), TIMEOUT_MS({})".format(
            GET_MY_NAME(), default_wait_s, timeout_ms)
        )

        if default_wait_s > 0:
            time.sleep(default_wait_s)

        path_script_vm = self.shared_dir_vm + "\\windows\\wait_for_idle_windows.bat"
        arguments = ['/C'] + [path_script_vm]

        try:
            process, stdout, stderr = \
                self.hypervisor.execute_process(self.path_cmd, arguments,
                                                timeout_ms=timeout_ms, actlog_off=True)
        except Exception as e:
            self.prglog_mgr.debug("{}(): Exception occurs ({})".format(GET_MY_NAME(), e))
            return False

        if process is None:
            return None, "", ""

        if stdout == '':
            return False

        lines = stdout.split('\r\n')
        if len(lines) < 3:
            return False

        if lines[-2] != "[VmPop] The system is idle":
            self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), lines[:-2]))
            self.prglog_mgr.debug("{}(): Entering IDLE status failed".format(GET_MY_NAME()))
            return False

        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), lines[:-2]))
        self.prglog_mgr.info("{}(): The system is ready to use (IDLE status)".format(GET_MY_NAME()))
        time.sleep(3)  # additional sleep for making sure
        return True

    '''
    #-----------------------------------------------------------------------------------
    # Common Actions
    #-----------------------------------------------------------------------------------
    '''
    def shutdown(self, mode=VmPopFunctionMode.HV, after_a_certain_time_s=3):
        """Shutdown the current VM using the OS event

        Args:
            mode (VmPopFunctionMode): OS or HV
            after_a_certain_time_s (int): default is 3 sec.

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if not isinstance(mode, VmPopFunctionMode):
            msg = "Invalid 'mode'"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        time.sleep(after_a_certain_time_s)
        ret = True

        if mode == VmPopFunctionMode.OS:
            # script = '''Stop-Computer'''
            script = \
                '''
                shutdown.exe -s
                '''

            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_COMMON,
                           action=T_ACTION_SHUTDOWN_OS,
                           method=T_ACTION_METHOD_PS,
                           user=self.hypervisor.user_name,
                           desc="",
                           note=script.strip())
            )

            ret, output = self.execute_powershell_script(script, do_not_wait=True, delay_s=2)

        elif mode == VmPopFunctionMode.HV:
            # Shutdown the system (method 2: using Hypervisor features)
            ret = self.hypervisor.stop_vm(VmPopStopMode.SHUT_DOWN)

        return ret

    def restart(self, mode=VmPopFunctionMode.HV, bios_time_offset=None, after_a_certain_time_s=3):
        """Restart the current VM using the OS event

        Args:
            mode (VmPopFunctionMode): OS or HV
            bios_time_offset (int): If it is an integer value, call set_bios_time() of the hypervisor module
            after_a_certain_time_s (int): default is 3 sec.

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if not isinstance(mode, VmPopFunctionMode):
            msg = "Invalid 'mode'"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        time.sleep(after_a_certain_time_s)

        if mode == VmPopFunctionMode.OS:  # (not completed)
            # Restart the system (method 1: using Hypervisor features)
            script = '''Restart-Computer'''
            # script = '''shutdown.exe -r'''

            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_COMMON,
                           action=T_ACTION_RESTART_OS,
                           method=T_ACTION_METHOD_PS,
                           user=self.hypervisor.user_name,
                           desc="",
                           note=script)
            )

            ret, output = self.execute_powershell_script(script, do_not_wait=True, delay_s=5)
            if ret is False:
                return False

            if isinstance(bios_time_offset, int):
                time.sleep(2)
                self.hypervisor.set_bios_time(bios_time_offset)

            # Wait until completing booting processes
            if self.hypervisor.wait_vm_for_booting(VmPopOSRunLevel.USERLAND) is False:
                msg = "Exception occurred in the booting process"
                self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
                return False

        elif mode == VmPopFunctionMode.HV:
            # Restart the system (method 2: using Hypervisor features)
            self.hypervisor.stop_vm(VmPopStopMode.SHUT_DOWN)

            if isinstance(bios_time_offset, int):
                self.hypervisor.set_bios_time(bios_time_offset)

            self.hypervisor.start_vm()

        return True

    def set_date_time(self, datetime="", offset=0):
        """Set the operating system date & time

            - Setting date and time: 'Set-Date' CmdLet
            - Syncing with NPT: W32tm.exe /resync /force

        Args:
            datetime (str): Date & Time (yyyy-MM-dd HH:mm:ss)
            offset (int): The length of the time span in seconds

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): DATETIME({}), OFFSET({})".format(GET_MY_NAME(), datetime, offset))

        if datetime != "":
            script = \
                '''
                function Set-Time([string]$datetime) {{
                    $newDate = Get-Date -format "yyyy-MM-dd HH:mm:ss" $datetime
                    Set-Date $newDate
                }}
                Set-Time "{}"
                '''.format(datetime)
        elif offset != 0:
            script = \
                '''
                Set-Date -Adjust (New-TimeSpan -Seconds {})
                '''.format(offset)
        else:
            msg = "Invalid 'datetime' or 'offset'"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        self.evtmon.start(T_ACTION_SET_DATETIME)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_SET_DATETIME,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="DATETIME({}) OFFSET({})".format(datetime, offset),
                       note="Set-Date")
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)

        self.evtmon.stop()
        return ret

    def configure_guest_addition_time_sync(self, off=False):
        """Configure Guest Addition (of VirtualBox) time synchronization (experimental)

            Not working?

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if off is True:
            action = T_ACTION_DISABLE_TIME_SYNC_GA
            script = \
                '''
                $vbox = "HKLM:SYSTEM\CurrentControlSet\Services\VBoxService"
                Set-ItemProperty -path $vbox -name ImagePath -value "system32\VBoxService.exe --disable-timesync"
                '''
        else:
            action = T_ACTION_ENABLE_TIME_SYNC_GA
            script = \
                '''
                $vbox = "HKLM:SYSTEM\CurrentControlSet\Services\VBoxService"
                Set-ItemProperty -path $vbox -name ImagePath -value "system32\VBoxService.exe"
                '''

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=action,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="HKLM:SYSTEM\CurrentControlSet\Services\VBoxService")
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)
        return ret

    def configure_time_sync(self, off=False):
        """Configure time synchronization (experimental)

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if off is True:
            action = T_ACTION_DISABLE_TIME_SYNC
            script = \
                '''
                $path = "HKLM:SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
                Set-ItemProperty -path $path -name Type -value "NoSync"
                '''
        else:
            action = T_ACTION_ENABLE_TIME_SYNC
            script = \
                '''
                $path = "HKLM:SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
                Set-ItemProperty -path $path -name Type -value "NTP"
                '''

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=action,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="",
                       note=script.strip())
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)
        return ret

    def change_timezone(self, timezone, method=VmPopActionMethod.WIN_PS):
        """Change timezone information

            - tzutil.exe is available on Windows 7 or higher

        Args:
            timezone (str): The name of timezones
                - In Windows, you can display the list of all timezones using 'tzutil /l'.
            method (VmPopActionMethod): Action method (WIN_PS = 1, WIN_KM = 2)

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), timezone))

        ret = True

        if method == VmPopActionMethod.WIN_PS:
            # PowerShell -enc length issue
            #   - maximum 915 bytes???? -> strange...
            #   - http://stackoverflow.com/questions/33375528/powershell-encodedcommand-length-issue
            script = \
                '''
                $timeZone = "{0}"
                $WinOSVerReg = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                $WinOSVer = $WinOSVerReg.GetValue("CurrentVersion")
                if ($WinOSVer -GE 6) {{
                    tzutil.exe /s $timeZone
                }} Else {{
                    $params = "/c Start `"Change timeZone`" /MIN %WINDIR%\System32\Control.exe TIMEDATE.CPL,,/Z "
                    $params += $timeZone
                    $proc = [System.Diagnostics.Process]::Start("CMD.exe", $params)
                }}
                '''.format(timezone)

            self.evtmon.start(T_ACTION_CHANGE_TIMEZONE)

            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_CONFIGURATION,
                           action=T_ACTION_CHANGE_TIMEZONE,
                           method=T_ACTION_METHOD_PS,
                           user=self.hypervisor.user_name,
                           desc="{}".format(timezone),
                           note="")
            )

            ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)

            self.evtmon.stop()

        elif method == VmPopActionMethod.WIN_KM:  # Not completed
            self.evtmon.start(T_ACTION_CHANGE_TIMEZONE)

            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_CONFIGURATION,
                           action=T_ACTION_CHANGE_TIMEZONE,
                           method=T_ACTION_METHOD_K,
                           user=self.hypervisor.user_name,
                           desc="Execute 'timedate.cpl' and then just terminate it",
                           note="")
            )

            # WIN + R
            hold_keys = ['LWIN']
            press_keys = 'r'
            self.hypervisor.send_event_keyboard(press_keys, hold_keys, delay_s=1.0, note="Windows Run")

            # timedate.cpl
            press_keys = 'timedate.cpl'
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.0)

            # ENTER
            press_keys = ['ENTER']
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

            # SHIFT + Tab
            hold_keys = ['LSHIFT']
            press_keys = ['TAB']
            self.hypervisor.send_event_keyboard(press_keys, hold_keys, delay_s=1.0)

            # RIGHT
            press_keys = ['E_RIGHT']
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.0)

            # Hard to select a 'timezone' item in the combobox control
            # so.......
            # ESC
            press_keys = ['ESC']
            ret = self.hypervisor.send_event_keyboard(press_keys, delay_s=1.0)

            self.evtmon.stop()

        return ret

    def disable_nic(self, name=""):
        """Disable network adapter(s)

            - Windows XP
                > devcon find *> list.txt
                > devcon disable *DEV_ID*

            - All Windows (but not working in XP)
                > netsh interface set interface name="Local Area Connection" admin=DISABLED

            - Windows 8 or higher
                > Get-NetAdapter -Name "NIC NAME" | ? status -eq up | Disable-NetAdapter -Confirm:$false
                > Get-NetAdapter | ? status -eq up | Disable-NetAdapter -Confirm:$false

        Args:
            name (str): The name of the target network adapter
                - In Windows, the default is usually "Local Area Connection".
                - If it is "", find an enabled (connected) NIC and disable it

        Returns:
            A disabled NIC name (string or None)
                - If all is True, return ""
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        pdid = ""

        if name == "":
            script = \
                '''
                $nic_connected = Get-WmiObject Win32_NetworkAdapter -filter "netconnectionstatus = 2"
                $nic_connected.netconnectionid
                $nic_connected.PNPDeviceID
                # ($nic_connedted | foreach { $_.netconnectionid })
                '''
            ret, output = self.execute_powershell_script(script, filemode=False)
            if ret is False:
                return None

            if output is not None and output.find('\n') > 0:
                name = output.splitlines()[0]
                pdid = output.splitlines()[1]
        else:
            if self.vm_os_type.code < VmPopOSType.Vista.code:
                script = \
                    '''
                    $nic_connected = Get-WmiObject Win32_NetworkAdapter -filter "netconnectionid = '{}'"
                    $nic_connected.PNPDeviceID
                    '''.format(name)
                ret, output = self.execute_powershell_script(script, filemode=False)
                if ret is False:
                    return None

                if output is not None and output.find('\n') > 0:
                    pdid = output.splitlines()[0]

        if self.vm_os_type.code < VmPopOSType.WindowsVista.code:
            if pdid == "":
                msg = "No 'PNPDeviceID' found"
                self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
                return None

            pdid = pdid.split('&')[1]
            script = \
                '''
                $devcon = "{}\\windows\\pre-requirements\\support_tools\\devcon.exe"
                & "$devcon" disable *{}*
                '''.format(self.shared_dir_vm, pdid)
        elif VmPopOSType.WindowsVista.code <= self.vm_os_type.code < VmPopOSType.Windows8.code:
            if name == "":
                msg = "No 'NetConnectionID' found"
                self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
                return None

            script = \
                '''
                netsh interface set interface name="{}" admin=DISABLED
                '''.format(name)
        else:
            if name == "":
                msg = "No 'NetConnectionID' found"
                self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
                return None

            script = \
                '''
                Get-NetAdapter -Name "{}" | ? status -eq up | Disable-NetAdapter -Confirm:$false
                '''.format(name)

        self.evtmon.start(T_ACTION_DISABLE_NIC)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_DISABLE_NIC,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="name({}) DEV_ID({})".format(name, pdid),
                       note="")
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)

        self.evtmon.stop()

        if ret is False:
            return None

        if self.vm_os_type.code < VmPopOSType.WindowsVista.code:
            name = pdid
        return name

    def enable_nic(self, name="", all_of_them=False):
        """Enable network adapter(s)

            - Windows XP
                > devcon find *> list.txt
                > devcon enable *DEV_ID*

            - All Windows (but not working in XP)
                > netsh interface set interface name="Local Area Connection" admin=ENABLED

            - Windows 8 or higher
                > Get-NetAdapter -Name "NIC NAME" | ? status -ne up | Enable-NetAdapter -Confirm:$false
                > Get-NetAdapter | ? status -ne up | Enable-NetAdapter -Confirm:$false

        Args:
            name (str): The name or DEV_ID of the target network adapter
                - In Windows, the default is usually "Local Area Connection".
                - If it is "", find a connected NIC and disable it
            all_of_them (bool): If True, enable all network adapters

        Returns:
            A disabled NIC name (string) or None
                - If all is True, return ""
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if all_of_them is True:
            script = \
                '''
                Get-NetAdapter | ? status -ne up | Enable-NetAdapter -Confirm:$false
                '''
        else:
            if self.vm_os_type.code < VmPopOSType.WindowsVista.code:
                script = \
                    '''
                    $devcon = "{}\\windows\\pre-requirements\\support_tools\\devcon.exe"
                    & "$devcon" enable *{}*
                    '''.format(self.shared_dir_vm, name)
            elif VmPopOSType.WindowsVista.code <= self.vm_os_type.code < VmPopOSType.Windows8.code:
                script = \
                    '''
                    netsh interface set interface name="{}" admin=ENABLED
                    '''.format(name)
            else:
                script = \
                    '''
                    Get-NetAdapter -Name {} | ? status -ne up | Enable-NetAdapter -Confirm:$false
                    '''.format(name)

        self.evtmon.start(T_ACTION_ENABLE_NIC)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_ENABLE_NIC,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="name({})".format(name),
                       note="")
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)

        self.evtmon.stop()

        if ret is False:
            return None
        return name

    def configure_nic_ip(self, name, mode, address, mask, gateway):
        """Configure the network adapter information

            netsh interface ip set address name="Local Area Connection" dhcp
            netsh interface ip set address name="Local Area Connection" \
                    source=static addr=10.0.2.77 mask=255.255.255.0 gateway=10.0.2.1 1

        Args:
            name (str): The name of the target network adapter
                - In Windows, the default is usually "Local Area Connection".
            mode (VmPopNICMode): Configuration mode (DHCP = 1, STATIC = 2)
            address (str): IP Address for this adapter
            mask (str): Subnet mask for this adapter
            gateway (str): IP Address of the gateway

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if not isinstance(mode, VmPopNICMode):
            msg = "Invalid 'mode'"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        if mode == VmPopNICMode.DHCP:
            if name == "":
                script = \
                    '''
                    $filter = "netconnectionstatus = 2"
                    $default = Get-WmiObject Win32_NetworkAdapter -filter $filter | foreach { $_.netconnectionid }
                    netsh interface ip set address name="$default" source=dhcp
                    '''
            else:
                script = \
                    '''
                    netsh interface ip set address name="{0}" source=dhcp
                    '''.format(name)
        else:
            if name == "":
                script = \
                    '''
                    $filter = "netconnectionstatus = 2"
                    $default = Get-WmiObject Win32_NetworkAdapter -filter $filter | foreach {{ $_.netconnectionid }}
                    netsh interface ip set address name="$default" source=static {} {} {} 1
                    '''.format("" if address == "" else "addr={0}".format(address),
                               "" if mask == "" else "mask={0}".format(mask),
                               "" if gateway == "" else "gateway={0}".format(gateway))
            else:
                script = \
                    '''
                    netsh interface ip set address name="{}" source=static {} {} {} 1
                    '''.format(name,
                               "" if address == "" else "addr={0}".format(address),
                               "" if mask == "" else "mask={0}".format(mask),
                               "" if gateway == "" else "gateway={0}".format(gateway))

        self.evtmon.start(T_ACTION_CONFIG_NIC_IP)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_CONFIG_NIC_IP,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="name({}) mode({}) address({}) mask({}) gateway({})".format(
                           name, mode, address, mask, gateway),
                       note="")
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)

        self.evtmon.stop()
        return ret

    def configure_nic_dns(self, name, mode, address=[]):
        """Configure the network adapter's DNS information

            netsh interface ip set dns name="Local Area Connection" source=dhcp
            netsh interface ip add dns name="Local Area Connection" addr=129.6.16.1 index=1
            netsh interface ip add dns name="Local Area Connection" addr=129.6.16.2 index=2

        Args:
            name (str): The name of the target network adapter
                - In Windows, the default is usually "Local Area Connection".
            mode (VmPopNICMode): Configuration mode (DHCP = 1, STATIC = 2)
            address (list): List of IP Addresses (maximum 2) for this adapter

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if not isinstance(mode, VmPopNICMode):
            msg = "Invalid 'mode'"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        ret = True

        if mode == VmPopNICMode.DHCP:
            if name == "":
                script = \
                    '''
                    $filter = "netconnectionstatus = 2"
                    $default = get-wmiobject win32_networkadapter -filter $filter | foreach { $_.netconnectionid }
                    netsh interface ip set dns name="$default" source=dhcp
                    '''
            else:
                script = \
                    '''
                    netsh interface ip set dns name="{}" source=dhcp
                    '''.format(name)

            self.evtmon.start(T_ACTION_CONFIG_NIC_DNS)

            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_CONFIGURATION,
                           action=T_ACTION_CONFIG_NIC_DNS,
                           method=T_ACTION_METHOD_PS,
                           user=self.hypervisor.user_name,
                           desc="name({}) mode({}) address({})".format(name, mode, address),
                           note="")
            )

            ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)

            self.evtmon.stop()
        else:
            for idx in range(len(address)):
                if name == "":
                    script = \
                        '''
                        $filter = "netconnectionstatus = 2"
                        $default = get-wmiobject win32_networkadapter -filter $filter | foreach {{ $_.netconnectionid }}
                        netsh interface ip add dns name="$default" {} {}
                        '''.format("" if address == "" else "addr={0}".format(address[idx]),
                                   "index={0}".format(idx+1))
                else:
                    script = \
                        '''
                        netsh interface ip add dns name="{}" {} {}
                        '''.format(name,
                                   "" if address == "" else "addr={0}".format(address[idx]),
                                   "index={0}".format(idx+1))

                self.evtmon.start(T_ACTION_CONFIG_NIC_DNS)

                self.actlog_mgr.add(
                    ActionItem(aclass=T_CLASS_CONFIGURATION,
                               action=T_ACTION_CONFIG_NIC_DNS,
                               method=T_ACTION_METHOD_PS,
                               user=self.hypervisor.user_name,
                               desc="name({}) mode({}) address({})".format(name, mode, address),
                               note="")
                )

                ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True, delay_s=0.1)

                self.evtmon.stop()

        return ret

    def configure_audit_policy_using_km(self):
        """Configure the audit policy
            -> an example using KM (keyboard and mice mode)

            < Operations >
                - launch 'secpol.msc'
                - [ON:success/failure] Audit account logon event
                - [ON:success/failure] Audit system events

            FYI, there are tools for changing audit policies,
            but the settings configured by these tools
            are not correctly applied to Windows registry.
                - AuditPol.exe (Windows Vista ~)
                - AuditUsr.exe (Windows 2000/2003/XP)
                (https://technet.microsoft.com/en-us/library/cc766468(v=WS.10).aspx)

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        self.evtmon.start(T_ACTION_CONFIG_AUDIT_POLICY)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_CONFIG_AUDIT_POLICY,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="secpol.msc")
        )

        hold_keys = ['LWIN']
        press_keys = 'r'
        self.hypervisor.send_event_keyboard(press_keys, hold_keys, delay_s=1.0, note="Windows Run")

        press_keys = 'secpol.msc'
        self.hypervisor.send_event_keyboard(press_keys, delay_s=1.0)

        press_keys = ['ENTER']
        self.hypervisor.send_event_keyboard(press_keys, delay_s=15)

        press_keys = ['ENTER', 'E_DOWN', 'E_DOWN', 'E_RIGHT', 'E_DOWN']
        self.hypervisor.send_event_keyboard(press_keys, delay_s=1.0, press_delay_ms=150,
                                            note="Traverse tree nodes")

        press_keys = ['TAB', 'ENTER']
        self.hypervisor.send_event_keyboard(press_keys, delay_s=1.0, press_delay_ms=150,
                                            note="Audit account logon event")

        press_keys = ['SPACE', 'TAB', 'SPACE', 'ENTER']
        self.hypervisor.send_event_keyboard(press_keys, delay_s=1.0, press_delay_ms=150,
                                            note="Success(ON) & Failure(ON)")

        press_keys = ['E_END', 'ENTER']
        self.hypervisor.send_event_keyboard(press_keys, delay_s=1.0, press_delay_ms=150,
                                            note="Audit system events")

        press_keys = ['SPACE', 'TAB', 'SPACE', 'ENTER']
        self.hypervisor.send_event_keyboard(press_keys, delay_s=1.0, press_delay_ms=150,
                                            note="Success(ON) & Failure(ON)")

        ret = self.hypervisor.send_event_keyboard(['F4'], ['ALT'], delay_s=1.0, note="Close the window")

        self.evtmon.stop()
        return ret

    def configure_eventlog(self, log_name, max_size, retention_days=7):
        """Configure the eventlog settings

            Limit-EventLog -LogName Security -MaximumSize 80MB -RetentionDays 21

        Args:
            log_name (str): The name of the target eventlog
                - In Windows, for example, 'system', 'security', 'system' and so on
            max_size (str): Maximum size of this eventlog (e.g., 80MB, 512KB...)
            retention_days (int): Retention days of this eventlog (default: 7 days)

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        rd = ""
        if self.vm_os_type.code < VmPopOSType.WindowsVista.code:
            rd = "-RetentionDays {}".format(retention_days)

        script = \
            '''
            Limit-EventLog -LogName {0} -MaximumSize {1} {2}
            '''.format(log_name, max_size, rd)

        self.evtmon.start(T_ACTION_CONFIG_EVENTLOG)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_CONFIG_EVENTLOG,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="log_name({}) max_size({}) retention_days({})".format(log_name, max_size, retention_days),
                       note=script.strip())
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)

        self.evtmon.stop()
        return ret

    def configure_eventlog_using_km(self):
        """Configure the eventlog settings (not used)
            -> an example using KM (keyboard and mice mode)

            1. Windows XP
                - launch 'eventvwr.msc'
                - Go to 'Security'
                - Open 'Properties' window
                - Set the maximum log size to 81920
                - Set the retention days to 90
            2. Windows Vista or higher
                - launch 'eventvwr.msc'
                - Go to 'Security'
                - Open 'Properties' window
                - Set the maximum log size to 81920

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        self.evtmon.start(T_ACTION_CONFIG_EVENTLOG)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_CONFIG_EVENTLOG,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="log_name({}), max_size({}), retention_days({})".format("Security", "81920", "90"),
                       note="eventvwr.msc")
        )

        hold_keys = ['LWIN']
        press_keys = 'r'
        self.hypervisor.send_event_keyboard(press_keys, hold_keys, delay_s=1.5)

        press_keys = 'eventvwr.msc'
        self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

        press_keys = ['ENTER']
        self.hypervisor.send_event_keyboard(press_keys, delay_s=3)

        if self.vm_os_type.code < VmPopOSType.WindowsVista.code:
            press_keys = ['E_DOWN', 'E_DOWN']
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

            press_keys = ['ALT', 'E_RIGHT', 'E_UP', 'E_UP', 'E_UP', 'ENTER']
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

            press_keys = ['TAB', 'TAB']
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

            press_keys = '81920'
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

            press_keys = ['TAB', 'TAB']
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

            press_keys = '90'
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)
        else:
            press_keys = ['E_DOWN', 'E_DOWN', 'E_RIGHT', 'E_DOWN', 'E_DOWN']
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

            press_keys = ['ALT', 'E_RIGHT', 'E_UP', 'P']
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

            press_keys = ['TAB', 'TAB', 'TAB']
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

            hold_keys = ['LSHIFT']
            press_keys = ['E_END']
            self.hypervisor.send_event_keyboard(press_keys, hold_keys, delay_s=1.5)

            press_keys = '81920'
            self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

        press_keys = ['ENTER']
        self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

        hold_keys = ['ALT']
        press_keys = ['F4']
        ret = self.hypervisor.send_event_keyboard(press_keys, hold_keys, delay_s=1.5)

        self.evtmon.stop()
        return ret

    def disable_windows_update(self):
        """Disable the windows update function

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vm_os_type.code < VmPopOSType.Windows8.code:
            script = \
                '''
                $WUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
                $WUSettings.NotificationLevel=1
                $WUSettings.save()
                '''
        else:
            script = \
                '''
                $policies = "HKLM:\SOFTWARE\Policies\Microsoft\Windows"
                New-Item -Path $policies -Name WindowsUpdate
                New-Item -Path $policies\WindowsUpdate -Name AU
                Set-ItemProperty -Path $policies\WindowsUpdate\AU -Name NoAutoUpdate -Value 1

                $policies = "HKLM:\SOFTWARE\Policies\Microsoft"
                New-Item -Path $policies -Name WindowsStore
                Set-ItemProperty -Path $policies\WindowsStore -Name AutoDownload -Value 2

                $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate"
                Set-ItemProperty -Path $path -Name AutoDownload -Value 2
                '''

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_DISABLE_WINDOWS_UPDATE,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="Never check for updates",
                       note="")
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)
        return ret

    def disable_uac(self, wait_s_for_window=10):
        """Disable UAC (Vista or higher only)

        Args:
            wait_s_for_window (int): It is necessary to wait until the UAC window pops up

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vm_os_type.code < VmPopOSType.WindowsVista.code:
            return False

        if self.vm_os_type.code < VmPopOSType.Windows8.code:
            script = \
                '''
                $system_policy = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Set-ItemProperty -path $system_policy -name EnableLUA -value 0
                '''
        else:  # Windows 8 or higher
            script = \
                '''
                $system_policy = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                #Set-ItemProperty -path $system_policy -name FilterAdministratorToken -value 1
                #Set-ItemProperty -path $system_policy\\UIPI -name "(Default)" -value "0x00000001(1)"
                Set-ItemProperty -path $system_policy -name ConsentPromptBehaviorAdmin -value 0
                Set-ItemProperty -path $system_policy -name ConsentPromptBehaviorUser -value 0
                Set-ItemProperty -path $system_policy -name PromptOnSecureDesktop -value 0
                Set-ItemProperty -path $system_policy -name EnableLUA -value 1
                '''

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_DISABLE_UAC,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        )

        ret, output = self.execute_powershell_script(
            script, filemode=True, handling_uac=True, run_as_admin=True,
            timeout_ms=30000, delay_s=wait_s_for_window
        )

        self.uac_off = True
        return ret

    def enable_uac(self):
        """Enable UAC (Vista or higher only)

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vm_os_type.code < VmPopOSType.WindowsVista.code:
            return False

        if self.vm_os_type.code < VmPopOSType.Windows8.code:
            script = \
                '''
                $system_policy = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Set-ItemProperty -path $system_policy -name EnableLUA -value 1
                '''
        else:  # Windows 8 or higher
            script = \
                '''
                $system_policy = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                Set-ItemProperty -path $system_policy -name ConsentPromptBehaviorAdmin -value 5
                Set-ItemProperty -path $system_policy -name ConsentPromptBehaviorUser -value 3
                Set-ItemProperty -path $system_policy -name PromptOnSecureDesktop -value 1
                Set-ItemProperty -path $system_policy -name EnableLUA -value 1
                '''

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_ENABLE_UAC,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="",
                       note=script.strip())
        )

        ret, output = self.execute_powershell_script(
            script, filemode=True, run_as_admin=True, delay_s=3.0
        )
        return ret

    def enable_file_history(self):
        """Enable File History (8 or higher only)

            - As far as we know, there is no command line method for doing this.
            - So, this function tries to enable FH using keyboard strokes.

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vm_os_type.code < VmPopOSType.Windows8.code:
            return False

        if self.vm_os_version is None:
            self.vm_os_version = self.check_os_version()
            if self.vm_os_version is None:
                msg = "Cannot verify the OS version"
                self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
                return False

        self.evtmon.start(T_ACTION_ENABLE_FILE_HISTORY)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_ENABLE_FILE_HISTORY,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="")
        )

        self.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.5, note="Windows Run")
        self.hypervisor.send_event_keyboard('control.exe /name \"Microsoft.FileHistory\"', delay_s=1.5)
        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=5.0, note="Launch FileHistory in control.exe")

        self.hypervisor.send_event_keyboard('d', ['ALT'], delay_s=1.5, note="Move the focus to the address bar")

        # count = 1 if self.vm_os_version < "10.0.14366" else 2
        if "6.2" <= self.vm_os_version < "6.4":
            count = 1
        elif "10.0" <= self.vm_os_version < "10.0.14366":
            count = 1
        else:
            count = 2

        for idx in range(count):
            self.hypervisor.send_event_keyboard(['TAB'], ['LSHIFT'], delay_s=1.5)

        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=20, note="Click 'Turn On'")
        ret = self.close_window()

        self.evtmon.stop()
        return ret

    def configure_file_history(self):
        """Configure File History feature (8 or higher only)

            - Experimental function for setting 'save copies of files' to 'Every 10 minutes'

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vm_os_type.code < VmPopOSType.Windows8.code:
            return False

        if self.vm_os_version is None:
            self.vm_os_version = self.check_os_version()
            if self.vm_os_version is None:
                msg = "Cannot verify the OS version"
                self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
                return False

        self.evtmon.start(T_ACTION_CONFIG_FILE_HISTORY)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_CONFIG_FILE_HISTORY,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="")
        )

        self.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.5, note="Windows Run")
        self.hypervisor.send_event_keyboard('control.exe /name \"Microsoft.FileHistory\" /page \"AdvancedSettings\"',
                                            delay_s=1.5)
        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=5.0, note="Launch FileHistory in control.exe")

        self.hypervisor.send_event_keyboard(['E_PGUP'], delay_s=1.5, note="Set 'Every 10 minutes'")

        # count = 4 if self.vm_os_version < "10.0.14366" else 5
        if "6.2" <= self.vm_os_version < "6.4":
            count = 4
        elif "10.0" <= self.vm_os_version < "10.0.14366":
            count = 4
        else:
            count = 5

        for idx in range(count):
            self.hypervisor.send_event_keyboard(['TAB'], ['LSHIFT'], delay_s=1.5)

        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=5, note="Click 'Save Changes'")
        ret = self.close_window()

        self.evtmon.stop()
        return ret

    def disable_auto_logon(self):
        """Turn off the automatic logon option

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vm_os_type.code < VmPopOSType.WindowsVista.code:
            self.prglog_mgr.debug("{}(): The running OS is not Windows Vista or higher".format(GET_MY_NAME()))
            return False

        self.evtmon.start(T_ACTION_DISABLE_AUTO_LOGON)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_DISABLE_AUTO_LOGON,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="netplwiz")
        )

        self.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.5, note="Windows Run")
        self.hypervisor.send_event_keyboard('netplwiz', delay_s=1.5)
        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=5.0, note="Run 'User Account'")

        self.hypervisor.send_event_keyboard(['SPACE'], delay_s=2.0, note="Uncheck the option")
        ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)

        self.evtmon.stop()
        return ret

    def disable_vista_misc(self):
        """Disable two default auto runs in Vista

            - Sidebar
                # [T] sidebar.exe (Windows Vista only)
                if VmPopOSType.WindowsVista.code <= vmpop.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
                    vmpop.automation.terminate_process(name="sidebar", force=True)

            - Windows Welcome Center

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if not (VmPopOSType.WindowsVista.code <= self.vm_os_type.code <= VmPopOSType.WindowsVista_64.code):
            return False

        script = \
            '''
            $run = "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            Remove-ItemProperty -path $run -name Sidebar
            Remove-ItemProperty -path $run -name WindowsWelcomeCenter
            '''

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_ENABLE_METRO_APPS,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="Sidebar and Windows Welcome Center",
                       note="HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Run (Sidebar & WindowsWelcomeCenter)")
        )

        ret, output = self.execute_powershell_script(script, filemode=True)
        return ret

    def disable_edge_save_prompt(self):
        """Disable the save prompt of the Edge browser

            In Windows 10 RS1, this function should be called after launching the Edge browser at least once

            $value = (Get-ItemProperty -path $edge\download).EnableSavePrompt
            if (!$value) {
                Write-Host "1st attempt failed, try one more time"
                New-Item -Path $edge -Name Download
                Set-ItemProperty -path $edge\Download -name EnableSavePrompt -value 0
            }

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if not (VmPopOSType.Windows10.code <= self.vm_os_type.code):
            return False

        script = \
            '''
            $base = "HKCU:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion"
            $edge = "$base\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge"

            New-Item -Path $edge -Name Download
            Set-ItemProperty -path $edge\Download -name EnableSavePrompt -value 0
            '''

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_CONFIGURATION,
                       action=T_ACTION_DISABLE_EDGE_SAVE_PROMPT,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="")
        )

        ret, output = self.execute_powershell_script(script, filemode=True)
        return ret

    # def manage_storage_device(self):
    #     """Manage storage devices (not completed)
    #
    #         - PowerShell example 1
    #             $size = (Get-PartitionSupportedSize -DiskNumber 0 -PartitionNumber 1)
    #             Resize-Partition -DiskNumber 0 -PartitionNumber 1 -Size ($size.SizeMax-5368709120)
    #             $format_volume = Format-Volume -FileSystem NTFS -NewFileSystemLabel File-History
    #             New-Partition -DiskNumber 0 -UseMaximumSize -IsActive -DriveLetter H | $format_volume
    #
    #     Returns:
    #         True or False
    #     """
    #     return True

    '''
    #-----------------------------------------------------------------------------------
    # Account related Actions
    #-----------------------------------------------------------------------------------
    '''
    def add_local_account(self, user_id, password, group="Administrators"):
        """Add a new local account

        Args:
            user_id (str): User ID
            password (str): User password
                - In Windows XP or lower, max password length is 14.
            group (str): Group name (e.g., 'Administrators')

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), user_id))

        # add an account
        script = \
            '''
            net user {0} {1} /add
            '''.format(user_id, password)

        self.evtmon.start(T_ACTION_ADD_LOCAL_ACCOUNT)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_ACCOUNT,
                       action=T_ACTION_ADD_LOCAL_ACCOUNT,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="ID({}), PW({})".format(user_id, password),
                       note=script.strip())
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True, delay_s=10)

        # add the created account to a group
        if ret is True:
            script = \
                '''
                net localgroup {0} {1} /add
                '''.format(group, user_id)

            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_ACCOUNT,
                           action=T_ACTION_ADD_LOCAL_ACCOUNT,
                           method=T_ACTION_METHOD_PS,
                           user=self.hypervisor.user_name,
                           desc="GROUP({})".format(group),
                           note=script.strip())
            )

            ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True, delay_s=5)

        self.evtmon.stop()
        return ret

    def add_email_account(self, email, admin=True):
        """Add an existing Microsoft e-mail account

            - As far as we know, there is no command-line method for doing this.

            - Launch 'Account control' - method 1
                - Win + R
                - Type 'netplwiz'
            - Launch 'Account control' - method 2
                - control.exe userpasswords2
            - Launch 'Account control' - method 3
                - 'WIN + s' or 'F3'
                - Type "Allow family members to use this PC"
                - Enter

        Args:
            email (str): Microsoft account
            admin (bool): If False, added account is just 'User'

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), email))

        self.evtmon.start(T_ACTION_ADD_EMAIL_ACCOUNT)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_ACCOUNT,
                       action=T_ACTION_ADD_EMAIL_ACCOUNT,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="EMAIL({})".format(email),
                       note="{}".format('netplwiz'))
        )

        # Add an e-mail account
        self.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.5, note="Windows Run")
        self.hypervisor.send_event_keyboard('netplwiz', delay_s=1.5)
        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=3.0, note="Run 'User Account'")

        self.hypervisor.send_event_keyboard(['d'], delay_s=3.0, note="Click 'Add'")
        self.hypervisor.send_event_keyboard(email, delay_s=3.0)
        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=7.0)
        self.hypervisor.send_event_keyboard(['TAB', 'TAB'], delay_s=1.0)
        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=5.0, note="Add an e-mail account")

        # Add the account to 'Administrator' group
        if admin is True:
            self.hypervisor.send_event_keyboard(['TAB'], delay_s=1.0)
            self.hypervisor.send_event_keyboard(email, delay_s=1.0)
            self.hypervisor.send_event_keyboard(['TAB'], delay_s=1.0)
            self.hypervisor.send_event_keyboard(['o'], delay_s=1.5, note="Click 'Properties'")
            self.hypervisor.send_event_keyboard(['TAB'], ['LSHIFT'], delay_s=1.0)
            self.hypervisor.send_event_keyboard(['E_RIGHT'], delay_s=1.0)
            self.hypervisor.send_event_keyboard(['TAB', 'a'], delay_s=1.0, note="Go to 'Administrator'")
            self.hypervisor.send_event_keyboard(['SPACE'], delay_s=1.0, note="Check 'Administrator'")
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="Add the account to 'Admin' group")

        ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Close the 'User Account' window")

        self.evtmon.stop()
        return ret

    def delete_account(self, user_id):
        """Delete an existing account

        Args:
            user_id (str): User ID

        Returns:
            True or False
        """
        script = \
            '''
            net user {0} /delete
            '''.format(user_id)

        self.evtmon.start(T_ACTION_DELETE_ACCOUNT)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_ACCOUNT,
                       action=T_ACTION_DELETE_ACCOUNT,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="ID({})".format(user_id),
                       note=script.strip())
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True, delay_s=5)
        self.evtmon.stop()
        return ret

    def change_account(self, user_id, password, full_name=""):
        """Change the password and fullname of an existing account

            - Change the password
                > net user ID PASSWORD
            - Change the full name
                > net user ID /fullname:FULLNAME
            - Get local account information using PowerShell
                > Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"

        Args:
            user_id (str): User ID
            password (str): New password
            full_name (str): Net full name

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), user_id))

        script = \
            '''
            net user {0} {1}
            '''.format(user_id,
                       password if password != "" else "\"\"\"\"")  # we need 4 double quotes in PowerShell

        self.evtmon.start(T_ACTION_CHANGE_ACCOUNT)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_ACCOUNT,
                       action=T_ACTION_CHANGE_ACCOUNT,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="ID({}), PW({})".format(user_id, password),
                       note=script.strip())
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True, delay_s=2)

        if full_name != "":
            script = \
                '''
                net user {0} /fullname:"{1}"
                '''.format(user_id, full_name)

            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_ACCOUNT,
                           action=T_ACTION_CHANGE_ACCOUNT,
                           method=T_ACTION_METHOD_PS,
                           user=self.hypervisor.user_name,
                           desc="FULLNAME({})".format(full_name),
                           note=script.strip())
            )

            ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True, delay_s=2)

        self.evtmon.stop()
        return ret

    def logon_account(self, user_id, user_pw, pin="", invalid_pw=False, clear_desktop=True):
        """Logon (entering the user ID and password)

        Args:
            user_id (str): User ID
            user_pw (str): User password
            pin (str): User pin (only Windows 8 or higher)
            invalid_pw (bool): If True, 'user_pw' is invalid password
            clear_desktop (bool): If True, close the default windows and go to desktop

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if pin != "":
            note = "Logon with PIN"
        else:
            note = ""

        if invalid_pw is False:
            action = T_ACTION_LOGON_ACCOUNT
            delay_s = 5
        else:
            action = T_ACTION_LOGON_ACCOUNT_INV_PW
            delay_s = 0

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_ACCOUNT,
                       action=action,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="ID({}) PW({}) PIN({})".format(user_id, user_pw, pin),
                       note=note)
        )

        # Logon through Keyboard strokes
        time.sleep(1)

        if pin != "":
            self.hypervisor.send_event_keyboard(pin, note="PIN")
        else:
            self.hypervisor.send_event_keyboard(user_pw, note="Password")

        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=delay_s, note="Try to Logon")

        # Create a new session in the current connected hypervisor
        if self.hypervisor.create_user_session(user_id, user_pw) is False:
            self.prglog_mgr.info("{}(): Cannot create the session".format(GET_MY_NAME()))
            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_ACCOUNT,
                           action=T_ACTION_LOGON_ACCOUNT,
                           method=T_ACTION_METHOD_K,
                           user=self.hypervisor.user_name,
                           desc="Logon failed",
                           note="")
            )
            time.sleep(1)
            self.hypervisor.send_event_keyboard(['ESC', 'ESC'], delay_s=1.0)
            if VmPopOSType.Windows10.code <= self.vm_os_type.code:
                self.hypervisor.send_event_keyboard(['TAB'], delay_s=0.5)
                self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0)
            return False

        # Wait the system until logon processes are completed
        if VmPopOSType.WindowsVista.code <= self.vm_os_type.code:
            self.wait_for_idle(default_wait_s=10)
        else:
            time.sleep(20)  # Just wait for 20 seconds

        if clear_desktop is True:
            # Close the default windows (Windows 8 and 8.1)
            if VmPopOSType.Windows8.code <= self.vm_os_type.code < VmPopOSType.Windows10.code:
                time.sleep(15)
                self.hypervisor.send_event_keyboard(['ESC'], delay_s=2.0)
                self.hypervisor.send_event_keyboard('d', ['LWIN'], delay_s=2.0, note="Go to Desktop")

            # Close the default windows (All windows)
            if self.vm_os_type.code < VmPopOSType.Windows10.code:
                self.hypervisor.send_event_keyboard(['TAB'], ['ALT'], delay_s=1.5)
                self.hypervisor.send_event_keyboard(['ESC', 'ESC'], delay_s=1.0)
                self.hypervisor.send_event_keyboard('d', ['LWIN'], delay_s=1.0, note="Go to Desktop")

        # Speed up Powershell startup (useful when the current user has admin right)
        # self.speed_up_powershell()
        time.sleep(3)
        return True

    def logoff_account(self, delay_s=30.0):
        """Logoff from the current session

        Args:
            delay_s (float): Waiting time for completing the logoff process (default: 15.0)

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_ACCOUNT,
                       action=T_ACTION_LOGOFF_ACCOUNT,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="shutdown.exe -l")
        )

        # -----------------------------------
        # Method 1: run shutdown.exe
        # script = '''shutdown.exe -l'''
        # ret, output = self.execute_powershell_script(script, do_not_wait=True, delay_s=10)
        # return ret

        # -----------------------------------
        # Method 2: Keyboard strokes
        self.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.0, note="Windows Run")
        self.hypervisor.send_event_keyboard("shutdown.exe -l")

        # Close the current guest session
        self.hypervisor.close_user_session()

        ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=delay_s, note="Try to Logoff")
        return ret

    '''
    #-----------------------------------------------------------------------------------
    # Filesystem related Actions
    #-----------------------------------------------------------------------------------
    '''
    def open_shell(self, default_path=""):
        """Open the default shell

            Windows Explorer (explorer.exe)
                - Win + E
                - Win + R -> explorer.exe "default_path"
                ...

        Args:
            default_path (str): The default path

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), default_path))

        self.evtmon.start(T_ACTION_OPEN_SHELL)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_FILESYSTEM,
                       action=T_ACTION_OPEN_SHELL,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="{}".format(default_path),
                       note="explorer.exe")
        )

        self.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.5, note="Windows Run")

        press_keys = "explorer.exe \"{}\"".format(default_path)
        self.hypervisor.send_event_keyboard(press_keys, delay_s=1.5)

        ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=2, note="Run 'Windows Explorer'")

        self.evtmon.stop()
        return ret

    def change_dirs(self, dirs):
        """Change(traverse) directories in Windows Explorer

            Assume that the active window is Windows Explorer

        Args:
            dirs (list): List of directories (full path)

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        self.evtmon.start(T_ACTION_CHANGE_DIR)
        ret = True  # Another method for checking the directory

        for path in dirs:
            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_FILESYSTEM,
                           action=T_ACTION_CHANGE_DIR,
                           method=T_ACTION_METHOD_K,
                           user=self.hypervisor.user_name,
                           desc=path,
                           note="Windows Explorer (explorer.exe)")
            )

            self.hypervisor.send_event_keyboard('d', ['ALT'], delay_s=1.0, note="Move the focus to the address bar")
            self.hypervisor.send_event_keyboard(['E_END'], ['LSHIFT'], delay_s=1.0)
            self.hypervisor.send_event_keyboard(path, delay_s=1.0)
            ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Change the directory")

        self.evtmon.stop()
        return ret

    def copy_files(self, src_path, dst_path):
        """Copy files or directories in VM

            Method 1 (robocopy)
                - robocopy "src" "dst" /E

            Method 2 (PowerShell)
                - Copy-Item -Path "src" -Destination "dst" -Recurse -Force | Out-Null

        Args:
            src_path (str): The source path
            dst_path (str): The destination path

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {} -> {}".format(GET_MY_NAME(), src_path, dst_path))

        script = \
            '''
            robocopy "{}" "{}" /E
            '''.format(src_path, dst_path)

        self.evtmon.start(T_ACTION_COPY)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_FILESYSTEM,
                       action=T_ACTION_COPY,
                       method=T_ACTION_METHOD_BAT,
                       user=self.hypervisor.user_name,
                       desc="SRC({}) DST({})".format(src_path, dst_path),
                       note=script.strip())
        )

        ret, output = self.execute_batch_script(script, timeout_ms=0)

        self.evtmon.stop()
        return ret

    # def delete_files(self, paths):
    #     """Delete files or directories in VM (not completed)
    #
    #     Args:
    #         paths (str): The target paths for deletion
    #
    #     Returns:
    #         True or False
    #     """
    #     self.prglog_mgr.info("{}()".format(GET_MY_NAME()))
    #     return True
    #
    # def rename_file(self, path, name):
    #     """Rename file or directory in VM (not completed)
    #
    #     Args:
    #         path (str): The target path
    #         name (str): The name to change
    #
    #     Returns:
    #         True or False
    #     """
    #     self.prglog_mgr.info("{}()".format(GET_MY_NAME()))
    #     return True
    #
    # def create_file(self, path, data=None):
    #     """Create a file (not completed)
    #
    #     Args:
    #         path (str): The target path
    #         data (bytes): The data to be stored
    #
    #     Returns:
    #         True or False
    #     """
    #     self.prglog_mgr.info("{}()".format(GET_MY_NAME()))
    #     return True
    #
    # def write_file(self, path, data, option):
    #     """Write data to a file (not completed)
    #
    #     Args:
    #         path (str): The target path
    #         data (bytes): The data to be stored
    #
    #     Returns:
    #         True or False
    #     """
    #     self.prglog_mgr.info("{}()".format(GET_MY_NAME()))
    #     return
    #
    # def create_dir(self, path):
    #     """Create a directory (not completed)
    #
    #     Args:
    #         path (str): The target path
    #
    #     Returns:
    #         True or False
    #     """
    #     self.prglog_mgr.info("{}()".format(GET_MY_NAME()))
    #     return

    '''
    #-----------------------------------------------------------------------------------
    # Registry related Actions
    #-----------------------------------------------------------------------------------
    '''
    def set_reg_value(self, path, value, reg_type=VmPopRegType.REG_SZ, data=""):
        """Set a registry value

            Set-ItemProperty -path "{}" -name {} -value {}

        Args:
            path (str): Key path
            value (str): Value name
            reg_type (VmPopRegType)
            data (any): data

        Returns:
            True or False
        """
        script = \
            '''
            REG ADD "{}" /v "{}" /t {} /d "{}" /f
            '''.format(path, value, reg_type.name, data)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_REGISTRY,
                       action=T_ACTION_SET_REG_VALUE,
                       method=T_ACTION_METHOD_BAT,
                       user=self.hypervisor.user_name,
                       desc="PATH({}) VALUE({}) TYPE({}) DATA({})".format(path, value, reg_type.name, data),
                       note=script.strip())
        )

        ret, output = self.execute_batch_script(script, timeout_ms=5000, run_as_admin=True)
        return ret

    '''
    #-----------------------------------------------------------------------------------
    # Device related Actions
    #-----------------------------------------------------------------------------------
    '''
    def attach_usb(self, serial_number):
        """Attach a USB device

        Args:
            serial_number (str): The serial number of the target USB device

        Returns:
            Drive letter or None
        """
        self.prglog_mgr.info("{}(): SerialNo({})".format(GET_MY_NAME(), serial_number))

        self.evtmon.start(T_ACTION_ATTACH_USB)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_DEVICE,
                       action=T_ACTION_ATTACH_USB,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="SerialNo({})".format(serial_number),
                       note="")
        )

        if self.hypervisor.attach_usb_device(serial_number) is False:
            self.evtmon.stop()
            msg = "Cannot attach the USB device {}".format(serial_number)
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return None

        self.evtmon.stop()

        # Close 'AutoPlay' window
        if self.set_foreground_window(window_title="AutoPlay") is True:
            self.hypervisor.send_event_keyboard(['ESC'], delay_s=1.0)

        # What is the drive letter?
        drive_letter = self.get_drive_letter(serial_number)
        if drive_letter == "":
            time.sleep(5)  # If the second function is also failed, then just return
            drive_letter = self.get_drive_letter(serial_number)
        return drive_letter

    def get_drive_letter(self, serial_number):
        """Get a drive letter of the target USB device

            (This is not an action, but just a sub-function for attach_usb())

        Args:
            serial_number (str): The serial number of the target USB device

        Returns:
            Drive letter or None
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        script = \
            '''
            Function Get-DriveLetter {{
                [CmdLetBinding(DefaultParameterSetName = "SerialNumber")]
                Param(
                    [Parameter(Position = 1, Mandatory = $True, ParameterSetName = "SerialNumber")]
                    [String]$SerialNumber
                )

                $Filter = "PNPDeviceID LIKE '%$SerialNumber%'"
                $PhysicalDisk = Get-WmiObject Win32_DiskDrive -Filter $Filter | Select-Object * -Exclude __*
                $query = "ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='Disk #$($PhysicalDisk.Index), Partition #0'}} WHERE AssocClass = Win32_LogicalDiskToPartition"
                $Partition = Get-WmiObject -Query $query
                $Partition.DeviceID
                $Partition.Description
            }}

            Get-DriveLetter "{}"
            '''.format(serial_number)

        ret, output = self.execute_powershell_script(script, filemode=True)
        if output is None:
            return None

        # What is the drive letter?
        drive_letter = ""
        if output.find(':\r\n') > 0:
            drive_letter = output.split('\r\n', 1)[0]

        self.prglog_mgr.info("{}(): Detected driver letter is '{}'".format(GET_MY_NAME(), drive_letter))
        return drive_letter

    def detach_usb(self, serial_number):
        """Detach a USB device

        Args:
            serial_number (str): The serial number of the target USB device

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): SerialNo({})".format(GET_MY_NAME(), serial_number))

        self.evtmon.start(T_ACTION_DETACH_USB)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_DEVICE,
                       action=T_ACTION_DETACH_USB,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="SerialNo({})".format(serial_number),
                       note="")
        )

        if self.hypervisor.detach_usb_device(serial_number) is False:
            self.evtmon.stop()
            msg = "Cannot detach the USB device {}".format(serial_number)
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        self.evtmon.stop()
        return True

    '''
    #-----------------------------------------------------------------------------------
    # Process related Actions
    #-----------------------------------------------------------------------------------
    '''
    def set_foreground_window(self, pname="", pid=-1, window_title=""):
        """Activate a window to the top

        Args:
            pname (str): The process name
            pid (int): The process ID
            window_title (str): The window bar's title

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): PNAME({}), PID({}), TITLE({})".format(GET_MY_NAME(), pname, pid, window_title))
        if pname == "" and pid <= 0 and window_title == "":
            msg = "Invalid pname, pid or window_title"
            self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), msg))

        tmp_pid = ""
        if pid != -1:
            tmp_pid = " -and $_.Id -eq \"{}\"".format(pid)

        script = \
            '''
            if ("{0}" -ne "" -or ("{1}" -ne -1 -and "{3}" -ne "")) {{
                $app = Get-Process | where {{ $_.Name -match "{0}" -and $_.MainWindowTitle -match "{3}" {2} }}
                if (!$app) {{ Write-Host "False"; exit }}
                $app = $app[0]
                $hwnd = @(Get-Process -ID $app.ID)[0].MainWindowHandle
                $query = $app.Id
            }} else {{
                if ("{1}" -ne -1) {{ $query = {1} }}
                if ("{3}" -ne "") {{ $query = "{3}" }}
            }}

            Add-Type @"
                using System;
                using System.Runtime.InteropServices;
                public class User32Native {{
                    [DllImport("user32.dll")]
                    public static extern void keybd_event(Byte bVk, Byte bScan, UInt32 dwFlags, UInt32 dwExtraInfo);
                }}
"@

            Add-Type -AssemblyName System.Windows.Forms
            $extended = 1; $key_up = 2
            [User32Native]::keybd_event([System.Windows.Forms.Keys]::Menu, 0, $extended, 0) # Press 'ALT'
            $ret = (New-Object -ComObject wscript.shell).AppActivate($query)
            [User32Native]::keybd_event([System.Windows.Forms.Keys]::Menu, 0, $extended + $key_up, 0) # Release 'ALT'
            $ret
            '''.format(pname, pid, tmp_pid, window_title)

        ret, output = self.execute_powershell_script(script, filemode=True)
        if output.find('\n') > 0:
            ret = output.splitlines()[-1]
            if ret == "False":  # we can get 'False' return sometimes if AppActivate() works well (edge browser?)
                return False

        return True

    def get_foreground_window(self):
        """Get information about the active window

        Returns:
            pid (int)
            title (str)
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        script = \
            '''
            Add-Type @"
                using System;
                using System.Runtime.InteropServices;
                public class User32Native {
                    [DllImport("user32.dll")]
                    public static extern IntPtr GetForegroundWindow();
                }
"@
            $fw = [User32Native]::GetForegroundWindow()
            $process = get-process | ? { $_.mainwindowhandle -eq $fw }
            if ($process) {
                $process.Id
                $process.MainWindowTitle
            }
            '''

        ret, output = self.execute_powershell_script(script, filemode=True)
        if output is None:
            self.prglog_mgr.debug("{}(): Cannot identify the target process's PID".format(GET_MY_NAME()))
            return False, None

        if output == "":
            return -1, ""

        lines = output.splitlines()
        pid = int(lines[0])
        title = lines[1]
        return pid, title

    def launch_program(self, path_file, path_target="", arguments="", maximize=False, timeout_ms=20000,
                       wait_s=0, focus_to_pid=False, keystrokes=None, terminate_after_time_s=0):
        """Execute a file (= launch program) with arguments

            ShowWindowAsync
            (https://msdn.microsoft.com/en-us/library/windows/desktop/ms633549(v=vs.85).aspx)
                "Hide"               {$WinStateInt =  0}
                "Normal"             {$WinStateInt =  1}
                "ShowMinimized"      {$WinStateInt =  2}
                "Maximize"           {$WinStateInt =  3}
                "ShowNoActivate"     {$WinStateInt =  4}
                "Show"               {$WinStateInt =  5}
                "Minimize"           {$WinStateInt =  6}
                "ShowMinNoActive"    {$WinStateInt =  7}
                "ShowNA"             {$WinStateInt =  8}
                "Restore"            {$WinStateInt =  9}
                "ShowDefault"        {$WinStateInt = 10}
                "ForceMinimize"      {$WinStateInt = 11}

        Args:
            path_file (str): The 'executable file' or 'shortcut' path
            path_target (str): The actual target file path for finding the process information
            arguments (str): The arguments for the execution
            maximize (bool): If True, do maximize the window using Windows APIs
            timeout_ms (int): Timeout (ms) for execute_process() (default: 20000)
            wait_s (int): Wait for this seconds for initial loading processes
            focus_to_pid (bool): If True, activate the window using 'PID' after launching the program
            keystrokes: Keyboard strokes right after launching program
                        ([[list of press keys], [list of hold keys], press_delay_ms -> default is 85)
            terminate_after_time_s (int): If this value > 0, then terminate the window automatically

        Returns:
            (True or False) & (PID (int) or None)
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), path_file))
        if arguments != "":
            self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), arguments))

        if arguments != "":
            arguments = "-ArgumentList \"{}\"".format(arguments)

        if path_target == "":
            path_target = path_file

        if maximize is True:
            script = \
                '''
                Function Find-ChildProcess {{
                    param($ID = $PID)
                    Get-WmiObject -Class Win32_Process -Filter "ParentProcessID=$ID" |
                    Select-Object -Property ProcessID
                }}

                Add-Type @"
                    using System;
                    using System.Runtime.InteropServices;
                    public class User32Native {{
                        [DllImport("user32.dll")]
                        public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
                        [DllImport("user32.dll")]
                        public static extern bool SetForegroundWindow(IntPtr hWnd);
                    }}
"@

                $app = Start-Process "{0}" {1} -PassThru
                while (!$app) {{
                    Start-Sleep -s 1
                    $app = Get-Process | foreach {{ $_ }} | ? {{ $_.Path -like "*{2}" }}
                }}
                Start-Sleep -s 1

                $hwnd = @(Get-Process -ID $app.ID)[0].MainWindowHandle
                $hwnd
                [User32Native]::ShowWindowAsync($hwnd, 0)
                [User32Native]::ShowWindowAsync($hwnd, 9)
                Start-Sleep -s 1
                $hwnd = @(Get-Process -ID $app.ID)[0].MainWindowHandle
                $hwnd
                Start-Sleep -s 1

                if ($hwnd -eq 0) {{
                    $children = Find-ChildProcess($app.ID)
                    if ($children) {{
                        $hwnd = @(Get-Process -ID $children.ProcessID)[0].MainWindowHandle
                        $hwnd
                        $children.ProcessID
                    }}
                }}

                [User32Native]::ShowWindowAsync($hwnd, 2)
                [User32Native]::ShowWindowAsync($hwnd, 1)
                [User32Native]::ShowWindowAsync($hwnd, 3)
                $app.ID
                '''.format(path_file, arguments, path_target)
        else:
            script = \
                '''
                $app = Start-Process "{0}" {1} -PassThru
                while (!$app) {{
                    Start-Sleep -s 1
                    $app = Get-Process | foreach {{ $_ }} | ? {{ $_.Path -like "*{2}" }}
                }}
                $app.ID
                '''.format(path_file, arguments, path_target)

        self.evtmon.start(T_ACTION_LAUNCH_PROGRAM)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_PROCESS,
                       action=T_ACTION_LAUNCH_PROGRAM,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc=path_file,
                       note=arguments)
        )

        ret, output = self.execute_powershell_script(script, timeout_ms=timeout_ms, filemode=True)
        if output is None:
            self.evtmon.stop()
            self.prglog_mgr.debug("{}(): Cannot identify the target process's PID".format(GET_MY_NAME()))
            return False, None

        pid = -1
        if output.find('\n') > 0:
            pid = output.splitlines()[-1]
            if pid.isdigit() is False:
                self.evtmon.stop()
                return False, None

        msg = "Launched program's PID is {}".format(pid)
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), msg))

        if wait_s > 0:
            time.sleep(wait_s)

        pid = int(pid)
        if focus_to_pid is True:
            self.set_foreground_window(pid=pid)

        if keystrokes is None:
            keystrokes = [[], [], 85, ""]

        if len(keystrokes[0]) > 0 or len(keystrokes[1]):
            time.sleep(2.0)
            self.hypervisor.send_event_keyboard(
                keystrokes[0], keystrokes[1], press_delay_ms=keystrokes[2], note=keystrokes[3]
            )

        self.evtmon.stop()

        if terminate_after_time_s > 0 and pid > 0:
            time.sleep(terminate_after_time_s)
            ret = self.terminate_process(pid=pid)

        return ret, pid

    def launch_win_store_app(self, app_name, terminate_after_time_s=0):
        """Launch a Windows store app

            < Experimental function >
                - Search the 'app_name'
                - Enter

        Args:
            app_name (str): The app name
            terminate_after_time_s (int): If this value > 0, then terminate the window automatically

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), app_name))

        self.evtmon.start(T_ACTION_LAUNCH_STOREAPP)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_PROCESS,
                       action=T_ACTION_LAUNCH_STOREAPP,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc=app_name,
                       note="Windows Search")
        )

        # Search the name of an app
        if VmPopOSType.Windows8.code <= self.vm_os_type.code <= VmPopOSType.Windows8_64.code:
            self.hypervisor.send_event_keyboard('q', ['LWIN'], delay_s=2.0, note="Launch Windows Search")
        elif VmPopOSType.Windows81.code <= self.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            self.hypervisor.send_event_keyboard('s', ['LWIN'], delay_s=2.0, note="Launch Windows Search")
        elif VmPopOSType.Windows10.code <= self.vm_os_type.code:
            self.hypervisor.send_event_keyboard(['LWIN'], delay_s=2.0, note="Launch Windows Search")
            self.hypervisor.send_event_keyboard("apps: ", delay_s=0.1, note="From installed applications")

        # Launch the app
        self.hypervisor.send_event_keyboard(app_name, delay_s=1.0)
        ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=3.0, note="Launch the app")

        self.evtmon.stop()

        if terminate_after_time_s > 0:
            time.sleep(terminate_after_time_s)
            ret = self.close_window(evtlog_off=False)
            if VmPopOSType.Windows8.code <= self.vm_os_type.code <= VmPopOSType.Windows8_64.code:
                ret = self.hypervisor.send_event_keyboard('d', ['LWIN'], delay_s=1.0, note="Go to Desktop")

        return ret

    def terminate_process(self, pid=-1, name="", run_as_admin=False, evtlog_off=False, actlog_off=False):
        """Terminate a process

            Method 1. Get-Process -ID {} | Stop-Process -Force
                --> It may require RUN AS ADMIN (not every time...)

            Method 2. Get-Process -ID {} | %{ $_.closemainwindow() }

        Args:
            pid (int): The target process's ID
            name (str): The target process's Name
            run_as_admin (bool): If True, run 'PowerShell script' as admin
            evtlog_off (bool): if True, do not call event logging functions
            actlog_off (bool): if True, do not call action logging function

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): PID({}), NAME({})".format(GET_MY_NAME(), pid, name))

        if pid > 0:
            script = \
                '''
                Function Find-ChildProcess {{
                    param($ID = $PID)

                    Get-WmiObject -Class Win32_Process -Filter "ParentProcessID=$ID" |
                    Select-Object -Property ProcessID
                }}

                Function Terminate-Process {{
                    param($process = $PARM)

                    if ($process) {{
                        $process.CloseMainWindow()
                        Start-Sleep -Milliseconds 500
                        if (!$process.HasExited) {{
                            Start-Sleep 2
                            if (!$process.HasExited) {{
                                $process | Stop-Process -Force
                            }}
                        }}
                    }}
                }}

                $children = Find-ChildProcess({0})
                if ($children) {{
                    Get-Process -ID $children.ProcessID | foreach {{ Terminate-Process($_) }}
                }}

                Get-Process -ID {0} | foreach {{ Terminate-Process($_) }}
                Start-Sleep -Milliseconds 500
                '''.format(pid)
        elif name != "":
            script = \
                '''
                Function Terminate-Process {{
                    param($process = $PARM)

                    if ($process) {{
                        $process.CloseMainWindow()
                        Start-Sleep -Milliseconds 500
                        if (!$process.HasExited) {{
                            Start-Sleep 2
                            if (!$process.HasExited) {{
                                $process | Stop-Process -Force
                            }}
                        }}
                    }}
                }}

                Get-Process -Name {0} | foreach {{ Terminate-Process($_) }}
                Start-Sleep -Milliseconds 500
                '''.format(name)
        else:
            msg = "Invalid 'pid' or 'name'"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        if evtlog_off is False:
            self.evtmon.start(T_ACTION_TERMINATE_PROCESS)

        if pid != -1 and name != "":
            desc = "PID({}) NAME({})".format(pid, name)
        elif pid != -1 and name == "":
            desc = "PID({})".format(pid)
        elif pid == -1 and name != "":
            desc = "NAME({})".format(name)
        else:
            desc = ""

        if actlog_off is False:
            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_PROCESS,
                           action=T_ACTION_TERMINATE_PROCESS,
                           method=T_ACTION_METHOD_PS,
                           user=self.hypervisor.user_name,
                           desc=desc,
                           note="")
            )

        # if you want to check stdout, set 'run_as_admin' as False
        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=run_as_admin)

        if evtlog_off is False:
            self.evtmon.stop()
        return ret

    def install_program(self, path_installer, arguments="", path_executable="", timeout_ms=600000, evtlog_off=False):
        """Install a program

            Launch an installer file with arguments

            Method 1) Batch script
                START "" /WAIT "%PATH%" {}

            Method 2) PowerShell script -> it has an issue about 'Wait' option
                Start-Process -FilePath "{}" -ArgumentList "{}" -Wait

        Args:
            path_installer (str): The full path of the installer file
            arguments (str): The arguments of the installer
            path_executable (str): The full path of the executable file (for the verification phase)
            timeout_ms (int): The default is 5 minutes
            evtlog_off (bool): if True, do not call event logging functions

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), path_installer))

        script = \
            '''
            REM SET SEE_MASK_NOZONECHECKS=1
            SET "PATH={}"
            START "" /WAIT "%PATH%" {}
            '''.format(path_installer, arguments)

        if evtlog_off is False:
            self.evtmon.start(T_ACTION_INSTALL_PROGRAM, timeout_s=int(timeout_ms / 1000))

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_APPLICATION,
                       action=T_ACTION_INSTALL_PROGRAM,
                       method=T_ACTION_METHOD_BAT,
                       user=self.hypervisor.user_name,
                       desc=path_installer,
                       note="Arguments({})".format(arguments))
        )

        ret, output = self.execute_batch_script(script, timeout_ms=timeout_ms, run_as_admin=True)

        if evtlog_off is False:
            self.evtmon.stop()

        if ret is False:
            return ret

        # Check if the application is successfully installed or not
        if path_executable != "":
            ret = self.hypervisor.file_exists(path_executable)
            if ret is True:
                msg = "The program is Successfully installed"
                self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), msg))

        return ret

    def install_win_store_app(self, app_name, wait_s=20):
        """Install an app from Windows Store (8.1 or higher)

            - As far as we know, there is no command line method for doing this.

            < Experimental function >
                - Launch Windows Store app
                - Search the name of an app
                - Select the app
                - Click 'Install' button using keyboard strokes

        Args:
            app_name (str): The app name
            wait_s (int): Seconds to wait after clicking install button

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), app_name))

        # Launch 'Windows Store' app
        # if VmPopOSType.Windows81.code <= self.vm_os_type.code <= VmPopOSType.Windows81_64.code:
        if VmPopOSType.Windows81.code <= self.vm_os_type.code:
            self.launch_win_store_app("Store")
        # elif VmPopOSType.Windows10.code <= self.vm_os_type.code:
        #     shortcut = "shell:AppsFolder\Microsoft.WindowsStore_8wekyb3d8bbwe!App"
        #     target = "8wekyb3d8bbwe\WinStore.Mobile.exe"
        #     ret, pid = self.launch_program(
        #         path_file=shortcut, path_target=target, maximize=False, run_as_admin=False
        #     )
        #     if ret is False:
        #         return False
        else:
            msg = "Unsupported Windows version"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        # Focus on the 'Windows Store' app
        self.set_foreground_window(window_title="Store")

        if VmPopOSType.Windows10.code <= self.vm_os_type.code:
            self.maximize_window()

        self.evtmon.start(T_ACTION_INSTALL_STOREAPP)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_APPLICATION,
                       action=T_ACTION_INSTALL_STOREAPP,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc=app_name,
                       note="Using 'Windows Store' app")
        )

        ret = True

        # Go to the search bar
        self.hypervisor.send_event_keyboard('e', ['CTRL'], delay_s=1.5, note="Move the focus to the search bar")

        # Search the name of an app
        self.hypervisor.send_event_keyboard(app_name, delay_s=1.0, note="Name of an app to be installed")

        # Select the app
        if VmPopOSType.Windows81.code <= self.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="Click the search button")
            self.hypervisor.send_event_keyboard(['TAB'], delay_s=1.0)
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=5.0, note="Enter the app")
        else:
            self.hypervisor.send_event_keyboard(['E_DOWN'], delay_s=1.0, note="Select the name of an app")
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=5.0, note="Enter the app")

        # Click 'Install' button using keyboard strokes
        if VmPopOSType.Windows81.code <= self.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            self.hypervisor.send_event_keyboard('e', ['CTRL'], delay_s=1.0)
            self.hypervisor.send_event_keyboard(['TAB', 'TAB', 'TAB'], delay_s=1.0)
            # self.hypervisor.send_event_keyboard(['TAB', 'TAB'], delay_s=1.0)

        ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=wait_s, note="Click 'Install'")

        if self.wait_for_idle(timeout_ms=300000) is True:
            msg = "Installation processes are completed"
            self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), msg))

        self.evtmon.stop()

        # Close 'Windows Store'
        self.set_foreground_window(window_title="Store")
        self.close_window(evtlog_off=False)
        return ret

    def uninstall_program(self, program_name="", path_uninstaller="", arguments="", timeout_ms=35000):
        """Uninstall a program

            - It is possible to consider another method (PowerShell)
                $app = Get-WmiObject -Class Win32_Product | Where-Object {
                    $_.Name -like "Software Name*"
                }
                $app.Uninstall()

        Args:
            program_name (str): The target program's name
            path_uninstaller (str): The full path of the uninstaller file
            arguments (str): The arguments of the uninstaller
            timeout_ms (int): The default timeout is 5 minutes

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): PNAME({}), PATH({})".format(GET_MY_NAME(), program_name, path_uninstaller))

        if program_name == "" and path_uninstaller == "":
            msg = "It is necessary to input valid program name or uninstaller's path"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        if program_name != "" and path_uninstaller == "":
            script = \
                '''
                $path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
                $name = UninstallString
                $item = gci $path | foreach {{ gp $_.PSPath }} | ? {{ $_.DisplayName -like "{0}*" }} | select $name

                if (!$item) {{
                    $path = "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
                    $item = gci $path | foreach {{ gp $_.PSPath }} | ? {{ $_.DisplayName -like "{0}*" }} | select $name
                }}

                $item.UninstallString
                '''.format(program_name)

            ret, output = self.execute_powershell_script(script, filemode=True)
            if ret is False or output is None:
                return False

            temp = output.rstrip().replace('\"', '')
            if temp.lower().startswith("msiexec.exe") and len(temp.split(' ')) >= 2:
                path_uninstaller = temp.split(' ')[0]
                arguments += " {}".format(temp.split(' ')[1])
            else:
                path_uninstaller = temp

        if path_uninstaller == "" or self.hypervisor.file_exists(path_uninstaller) is False:
            msg = "No uninstaller's path found"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        script = \
            '''
            SET "PATH={}"
            START "" /WAIT "%PATH%" {}
            '''.format(path_uninstaller, arguments)

        self.evtmon.start(T_ACTION_UNINSTALL_PROGRAM)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_APPLICATION,
                       action=T_ACTION_UNINSTALL_PROGRAM,
                       method=T_ACTION_METHOD_BAT,
                       user=self.hypervisor.user_name,
                       desc=path_uninstaller,
                       note="Arguments({})".format(arguments))
        )

        ret, output = self.execute_batch_script(script, timeout_ms=timeout_ms, run_as_admin=True)

        self.evtmon.stop()
        return ret

    def uninstall_win_store_app(self, app_name):
        """Uninstall a Windows Store app

        Args:
            app_name (str): The target app's name

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), app_name))

        if app_name == "":
            msg = "It is necessary to input valid app name"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        script = \
            '''
            Get-AppxPackage *{}* | Remove-AppxPackage
            '''.format(app_name)

        self.evtmon.start(T_ACTION_UNINSTALL_STOREAPP)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_APPLICATION,
                       action=T_ACTION_UNINSTALL_STOREAPP,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc=app_name,
                       note=script.strip())
        )

        ret, output = self.execute_powershell_script(script, filemode=True)

        self.evtmon.stop()
        return ret

    def control_web_browser(self, action=VmPopWebAction.NEW_TAB, browser=VmPopWebBrowser.ANY,
                            site=VmPopWebSite.ANY, argument1="", argument2="", delay_s=1.0, evtlog_off=False):
        """Control web browsers

            Assume that the active window is web-browsers
            (current implementation supports IE, IE Edge and Chrome as examples)
            * The actions performed here need to be updated according to updates of browsers and web-sites
            * So, we suggest that you will develop your own control function for specific purposes

        Args:
            action  (VmPopWebAction): NEW_TAB, VISIT_URL, ADD_BOOKMARK, LOGIN, LOGOUT, DOWNLOAD, SEARCH_KEYWORD
            browser (VmPopWebBrowser): ANY, IE, EDGE, CHROME, FIREFOX, SAFARI
            site    (VmPopWebSite): DEFAULT, GOOGLE, BING...
            argument1 (str): URL or keyword or ID
            argument2 (str): Additional data (PW...)
            delay_s (float): Additional delay (second) after completing the execution (default: 1.0)
            evtlog_off (bool): if True, do not call event logging functions

        Returns:
            True or False
        """
        if site == VmPopWebSite.ANY:
            self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), action.name))
        else:
            self.prglog_mgr.info("{}(): {} at {}".format(GET_MY_NAME(), action.name, site.name))

        if evtlog_off is False:
            if VmPopWebBrowser.IE7 <= browser <= VmPopWebBrowser.IE11:
                self.evtmon.start(T_ACTION_CONTROL_PROCESS, restore_active_window=True)
                self.hypervisor.send_event_keyboard(['ESC'], delay_s=0.5)  # Release 'ALT'
            else:
                self.evtmon.start(T_ACTION_CONTROL_PROCESS, restore_active_window=False)

        desc = ""
        if argument1 != "" and argument2 != "":
            desc = "ARG1({}) ARG2({})".format(argument1, argument2)
        elif argument1 != "" and argument2 == "":
            desc = "ARG1({})".format(argument1)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_PROCESS,
                       action=T_ACTION_CONTROL_PROCESS,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc=desc,
                       note="ACTION({}) BROWSER({}) SITE({})".format(action.name, browser.name, site.name))
        )

        ret = True

        if (action & VmPopWebAction.NEW_TAB) == VmPopWebAction.NEW_TAB:
            ret = self.hypervisor.send_event_keyboard(['t'], ['CTRL'], delay_s=2.0, note="Create a new tap")

        if (action & VmPopWebAction.CLOSE_TAB) == VmPopWebAction.CLOSE_TAB:
            ret = self.hypervisor.send_event_keyboard(['w'], ['CTRL'], delay_s=2.0, note="Close a tap")

        if ((action & VmPopWebAction.VISIT_URL) == VmPopWebAction.VISIT_URL) or \
           ((action & VmPopWebAction.DOWNLOAD) == VmPopWebAction.DOWNLOAD):
            self.hypervisor.send_event_keyboard(['d'], ['ALT'], delay_s=1.0, note="Move the focus to the address bar")
            self.hypervisor.send_event_keyboard(argument1, delay_s=1.0)
            # self.hypervisor.send_event_keyboard(['E_DEL'], delay_s=0.5)
            ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=3.0, note="Visit the URL")

        if (action & VmPopWebAction.DOWNLOAD) == VmPopWebAction.DOWNLOAD:
            if VmPopWebBrowser.IE7 <= browser <= VmPopWebBrowser.IE8:
                self.set_foreground_window(window_title="File Download")
                self.hypervisor.send_event_keyboard(['s'], delay_s=1.5, note="Click 'Save'")
                self.hypervisor.send_event_keyboard(['ENTER'], delay_s=20)
                ret = self.hypervisor.send_event_keyboard(['ESC'], delay_s=1.0)
                self.set_foreground_window(window_title="Internet Explorer")
                self.hypervisor.send_event_keyboard(['d'], ['ALT'], delay_s=1.5,
                                                    note="Move the focus to the address bar")
            elif VmPopWebBrowser.IE9 <= browser <= VmPopWebBrowser.IE11:
                self.hypervisor.send_event_keyboard(['d'], ['ALT'], delay_s=1.5,
                                                    note="Move the focus to the address bar")
                ret = self.hypervisor.send_event_keyboard(['s'], ['ALT'], delay_s=15, note="Click 'Save'")
            else:
                ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=15)

        if (action & VmPopWebAction.ADD_BOOKMARK) == VmPopWebAction.ADD_BOOKMARK:
            self.hypervisor.send_event_keyboard(['d'], ['CTRL'], delay_s=1.5, note="Launch the bookmark window")
            if VmPopWebBrowser.IE7 <= browser <= VmPopWebBrowser.IE8:
                self.set_foreground_window(window_title="Add a Favorite")
                ret = self.hypervisor.send_event_keyboard(
                    ['ENTER', 'ENTER'], press_delay_ms=1500, delay_s=1.0, note="Add a bookmark"
                )
            elif VmPopWebBrowser.EDGE == browser:
                ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Add a bookmark")
            else:
                ret = self.hypervisor.send_event_keyboard(
                    ['ENTER', 'ENTER'], press_delay_ms=1500, delay_s=1.0, note="Add a bookmark"
                )

        if (action & VmPopWebAction.LOGIN) == VmPopWebAction.LOGIN:
            if site == VmPopWebSite.LIVE:
                self.control_web_browser(
                    action=VmPopWebAction.VISIT_URL, browser=browser,
                    argument1="https://login.live.com/login.srf?nobrowserwrn=1&vv=1600&mkt=EN-US&lc=1033",
                    evtlog_off=True
                )

                # self.hypervisor.send_event_keyboard(['F5'], delay_s=1.0, note="Refresh the current website")
                self.hypervisor.send_event_keyboard(['E_HOME'], ['LSHIFT'], delay_s=1.0)
                self.hypervisor.send_event_keyboard(argument1, delay_s=1.0, note="ID")
                # self.hypervisor.send_event_keyboard(['TAB'], delay_s=1.5)  # Old
                self.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0)  # Updated from Nov 01, 2016
                self.hypervisor.send_event_keyboard(argument2, delay_s=1.0, note="PW")

                self.hypervisor.send_event_keyboard(['TAB'], delay_s=1.5, note="Go to the credential checkbox")
                self.hypervisor.send_event_keyboard(['SPACE'], delay_s=1.0, note="Check the option")

                # Login
                self.hypervisor.send_event_keyboard(['ENTER'], delay_s=10.0, note="Click 'Login'")

                # Save the credential
                self.hypervisor.send_event_keyboard(['d'], ['ALT'], delay_s=1.5, note="Move the focus to the address bar")

                if browser == VmPopWebBrowser.IE11:
                    ret = self.hypervisor.send_event_keyboard(['y'], ['ALT'], delay_s=1.0, note="Click 'Yes' to save PW")
                elif browser == VmPopWebBrowser.EDGE:
                    for idx in range(7):
                        self.hypervisor.send_event_keyboard(['TAB'], ['LSHIFT'], delay_s=0.5)
                    ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=3.0, note="Click 'Yes' to save the PW")
                elif browser == VmPopWebBrowser.CHROME:
                    count = 1
                    if VmPopOSType.Windows8.code <= self.vm_os_type.code:
                        count = 2
                    for idx in range(count):
                        self.hypervisor.send_event_keyboard(['TAB'], delay_s=0.5)
                    self.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.0, note="Click 'Save' to save the PW")
                    ret = self.hypervisor.send_event_keyboard(['ESC'], delay_s=1.0)
                else:  # nothing
                    ret = self.hypervisor.send_event_keyboard(['ESC'], delay_s=1.0)
            else:  # nothing
                ret = self.hypervisor.send_event_keyboard(['ESC'], delay_s=1.0)

        if (action & VmPopWebAction.SEARCH_KEYWORD) == VmPopWebAction.SEARCH_KEYWORD:
            if site == VmPopWebSite.GOOGLE:  # Assume the current page is google.com
                self.control_web_browser(
                    action=VmPopWebAction.VISIT_URL, argument1="www.google.com", evtlog_off=True
                )
                self.hypervisor.send_event_keyboard(argument1, delay_s=1.0)
                ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Search a keyword")
            elif site == VmPopWebSite.BING:  # Assume the current page is bing.com
                self.control_web_browser(
                    action=VmPopWebAction.VISIT_URL, argument1="www.bing.com", evtlog_off=True
                )
                self.hypervisor.send_event_keyboard(argument1, delay_s=1.0)
                ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.0, note="Search a keyword")
            else:  # nothing
                ret = self.hypervisor.send_event_keyboard(['ESC'])

        time.sleep(delay_s)

        if evtlog_off is False:
            self.evtmon.stop()
            if browser == VmPopWebBrowser.EDGE:
                self.set_foreground_window(window_title="Edge")

        return ret

    '''
    #-----------------------------------------------------------------------------------
    # Other Actions
    #-----------------------------------------------------------------------------------
    '''
    def create_restore_point(self, drive="C:\\", description="Restore Point",
                             rp_type=VmPopRPType.APPLICATION_INSTALL):
        """Create a restore point

            - Reference for all Windows
                - https://technet.microsoft.com/en-us/library/hh849822.aspx
                - Checkpoint-Computer
                    > The Checkpoint-Computer creates a system restore point on the local computer.
                    > Beginning in Windows 8, Checkpoint-Computer cannot create more than one checkpoint each day.

            - Reference for Volume Shadow Copy
                - https://msdn.microsoft.com/en-us/library/aa389391(v=vs.85).aspx

        Args:
            drive (str): The target drive
            description (str): The description of restore point
            rp_type (VmPopRPType): The type of restore point

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): DRIVE({}) DESC({})".format(GET_MY_NAME(), drive, description))

        script = \
            '''
            Enable-ComputerRestore -Drive "{0}"

            #$rpoint = Get-ComputerRestorePoint
            #$before = $rpoint.count

            Checkpoint-Computer -Description "{1}" -RestorePointType "{2}"

            #$rpoint = Get-ComputerRestorePoint
            #$after = $rpoint.count

            #if ($after -EQ 1) {{
            #    $before = 0
            #}}
            #$after - $before
            '''.format(drive, description, rp_type.name)

        # [Alternative]
        # if VmPopOSType.WindowsVista.code <= self.vm_os_type.code:
        #     # if Vista or higher, create a Volume Shadow copy
        #     script = \
        #         '''
        #         # Get existing shadow copies
        #         $shadow = Get-WmiObject win32_ShadowCopy
        #         $before = $shadow.count
        #
        #         $class = [WMICLASS]"root\cimv2:win32_ShadowCopy"
        #         $new = $class.create("{}", "ClientAccessible")
        #
        #         # Get existing shadow copies
        #         $shadow = Get-WmiObject win32_ShadowCopy
        #         $after = $shadow.count
        #
        #         # If success, the result will be 1
        #         $after - $before
        #         '''.format(drive)

        self.evtmon.start(T_ACTION_CREATE_RESTORE_POINT)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_SYSTEM_BACKUP,
                       action=T_ACTION_CREATE_RESTORE_POINT,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc="DRIVE({}) DESC({})".format(drive, description),
                       note="Checkpoint-Computer")
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)

        self.evtmon.stop()
        return ret

    def share_directory(self, path, name):
        """Share a directory (after creating the directory if it does not exist)

        Args:
            path (str): The target directory path
            name (str): The sharing name

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), path))

        script = \
            '''
            Function CreateSharedDir([string] $folder_name, [string] $share_name) {{
                if (!(Test-Path $folder_name)) {{
                    New-Item $folder_name -type Directory
                }}

                $type = 0  # Disk Drive
                $shares = [WMICLASS]"WIN32_Share"
                $shares.Create($folder_name, $share_name, $type)
            }}

            CreateSharedDir "{}" "{}"
            '''.format(path, name)

        self.evtmon.start(T_ACTION_SHARE_DIR)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_SHARE,
                       action=T_ACTION_SHARE_DIR,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc=path,
                       note="[WMICLASS]\"WIN32_Share\"")
        )

        ret, output = self.execute_powershell_script(script, filemode=True, run_as_admin=True)

        self.evtmon.stop()
        return ret

    def search_keyword(self, keyword):
        """Search a keyword using Windows Search feature

            - Search for files or folders
                - [WIN + D] --> [F3] --> Type 'keyword' --> [Enter] (ALL)
                - [WIN + D] --> [WIN + F] --> Type 'keyword' --> [Enter] (~ Windows 8.1)

            - Search for apps and settings
                - (Apps)     [WIN + D] --> [WIN + Q] --> Type 'keyword' --> [Enter] (Windows 8)
                - (Settings) [WIN + D] --> [WIN + W] --> Type 'keyword' --> [Enter] (Windows 8 and 8.1)

            - Search for everywhere (including files, folders, apps, settings...)
                - [WIN + D] --> [WIN + S] --> Type 'keyword' --> [Enter] (Windows 8.1 and 10)

            - Search for computers on a network
                - [WIN + D] --> [CTRL + WIN + F] --> Type 'keyword' --> [Enter] (ALL)

            * Although Windows XP- supports other options like search for 'Picture, music, or video' and 'Documents',
              this function performs above search methods only.

            * Although Windows 8.1 supports other options like search for 'Web images' and 'Web videos',
              this function performs above search methods only.

        Args:
            keyword (str)

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), keyword))

        prefix_files = "files"
        prefix_documents = "documents"
        prefix_folders = "folders"
        prefix_apps = "apps"
        prefix_settings = "settings"
        prefix_everywhere = "everywhere"
        # prefix_computers = "computers"

        # Copy the unicode keyword to Clipboard in VM
        script = \
            '''
            function SetClipBoard([string] $text) {{
                Add-Type -AssemblyName System.Windows.Forms
                $tb = New-Object System.Windows.Forms.TextBox
                $tb.Multiline = $true
                $tb.Text = $text
                $tb.SelectAll()
                $tb.Copy()
            }}

            SetClipBoard "{}"
            '''.format(keyword)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_COMMON,
                       action=T_ACTION_SET_CLIPBOARD,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc=keyword,
                       note="")
        )

        ret, output = self.execute_powershell_script(script, filemode=True)
        if ret is False:
            return False

        self.evtmon.start(T_ACTION_SEARCH_KEYWORD)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_SEARCH,
                       action=T_ACTION_SEARCH_KEYWORD,
                       method=T_ACTION_METHOD_PS,
                       user=self.hypervisor.user_name,
                       desc=keyword,
                       note="")
        )

        # Go to Windows Desktop
        self.hypervisor.send_event_keyboard('d', ['LWIN'], delay_s=1.0, note="Go to Desktop")

        if VmPopOSType.WindowsXP.code <= self.vm_os_type.code <= VmPopOSType.WindowsXP_64.code:
            # Search for files or folders
            self.hypervisor.send_event_keyboard(['F3'], delay_s=2.0, note="Launch Windows Search for files or folders")
            self.hypervisor.send_event_keyboard('v', ['CTRL'], delay_s=2.0, note="Paste data from the clipboard")
            keyword_with_pf = " ({})".format(prefix_files)
            self.hypervisor.send_event_keyboard(keyword_with_pf, delay_s=1.5)
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Search")
            self.close_window()

        elif VmPopOSType.WindowsVista.code <= self.vm_os_type.code <= VmPopOSType.WindowsVista_64.code:
            # Search for files or folders
            self.hypervisor.send_event_keyboard(['F3'], delay_s=2.0, note="Launch Windows Search for files or folders")
            self.hypervisor.send_event_keyboard('v', ['CTRL'], delay_s=2.0, note="Paste data from the clipboard")
            keyword_with_pf = " ({})".format(prefix_files)
            self.hypervisor.send_event_keyboard(keyword_with_pf, delay_s=1.5)
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Search")
            self.close_window()

        elif VmPopOSType.Windows7.code <= self.vm_os_type.code <= VmPopOSType.Windows7_64.code:
            # Search for files or folders
            self.hypervisor.send_event_keyboard(['F3'], delay_s=2.0, note="Launch Windows Search for files or folders")
            self.hypervisor.send_event_keyboard('v', ['CTRL'], delay_s=2.0, note="Paste data from the clipboard")
            keyword_with_pf = " ({})".format(prefix_files)
            self.hypervisor.send_event_keyboard(keyword_with_pf, delay_s=1.5)
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Search")
            self.close_window()

        elif VmPopOSType.Windows8.code <= self.vm_os_type.code <= VmPopOSType.Windows8_64.code:
            # Search for files or folders
            self.hypervisor.send_event_keyboard(['F3'], delay_s=2.0, note="Launch Windows Search for files or folders")
            self.hypervisor.send_event_keyboard('v', ['CTRL'], delay_s=2.0, note="Paste data from the clipboard")
            keyword_with_pf = " ({})".format(prefix_files)
            self.hypervisor.send_event_keyboard(keyword_with_pf, delay_s=1.5)
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Search")
            self.hypervisor.send_event_keyboard(['ESC'], delay_s=1.5)
            self.hypervisor.send_event_keyboard('d', ['LWIN'], delay_s=2.0, note="Go to Desktop")

            # Search for apps
            self.hypervisor.send_event_keyboard('q', ['LWIN'], delay_s=2.0, note="Launch Windows Search for apps")
            self.hypervisor.send_event_keyboard('v', ['CTRL'], delay_s=2.0, note="Paste data from the clipboard")
            keyword_with_pf = " ({})".format(prefix_apps)
            self.hypervisor.send_event_keyboard(keyword_with_pf, delay_s=1.5)
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Search")
            self.hypervisor.send_event_keyboard(['ESC'], delay_s=1.5)
            self.hypervisor.send_event_keyboard('d', ['LWIN'], delay_s=2.0, note="Go to Desktop")

            # Search for settings
            self.hypervisor.send_event_keyboard('w', ['LWIN'], delay_s=2.0, note="Launch Windows Search for settings")
            self.hypervisor.send_event_keyboard('v', ['CTRL'], delay_s=2.0, note="Paste data from the clipboard")
            keyword_with_pf = " ({})".format(prefix_settings)
            self.hypervisor.send_event_keyboard(keyword_with_pf, delay_s=1.5)
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Search")
            self.hypervisor.send_event_keyboard(['ESC'], delay_s=1.5)
            self.hypervisor.send_event_keyboard('d', ['LWIN'], delay_s=2.0, note="Go to Desktop")

        elif VmPopOSType.Windows81.code <= self.vm_os_type.code <= VmPopOSType.Windows81_64.code:
            # Search for files or folders
            self.hypervisor.send_event_keyboard(['F3'], delay_s=2.0, note="Launch Windows Search for files or folders")
            self.hypervisor.send_event_keyboard('v', ['CTRL'], delay_s=2.0, note="Paste data from the clipboard")
            keyword_with_pf = " ({})".format(prefix_files)
            self.hypervisor.send_event_keyboard(keyword_with_pf, delay_s=1.5)
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Search")
            self.close_window()

            # Search for settings
            self.hypervisor.send_event_keyboard('w', ['LWIN'], delay_s=2.0, note="Launch Windows Search for settings")
            self.hypervisor.send_event_keyboard('v', ['CTRL'], delay_s=2.0, note="Paste data from the clipboard")
            keyword_with_pf = " ({})".format(prefix_settings)
            self.hypervisor.send_event_keyboard(keyword_with_pf, delay_s=1.5)
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Search")
            self.close_window()

            # Search for everywhere
            self.hypervisor.send_event_keyboard('s', ['LWIN'], delay_s=2.0, note="Launch Windows Search for everywhere")
            self.hypervisor.send_event_keyboard('v', ['CTRL'], delay_s=2.0, note="Paste data from the clipboard")
            keyword_with_pf = " ({})".format(prefix_everywhere)
            self.hypervisor.send_event_keyboard(keyword_with_pf, delay_s=1.5)
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=1.5, note="Search")
            self.close_window()

        elif VmPopOSType.Windows10.code <= self.vm_os_type.code <= VmPopOSType.Windows10_64.code:
            items = [('folders: ', prefix_folders), ('documents: ', prefix_documents),
                     ('apps: ', prefix_apps), ('settings: ', prefix_settings)]

            for item in items:
                self.hypervisor.send_event_keyboard(['LWIN'], delay_s=2.0, note="Launch Windows Search")
                self.hypervisor.send_event_keyboard(item[0], delay_s=1.0)
                self.hypervisor.send_event_keyboard('v', ['CTRL'], delay_s=2.0, note="Paste data from the clipboard")
                keyword_with_pf = " ({})".format(item[1])
                self.hypervisor.send_event_keyboard(keyword_with_pf, delay_s=1.5)
                self.hypervisor.send_event_keyboard(['ENTER'], delay_s=2.5, note="Search")
                self.close_window()

        else:
            self.evtmon.stop()
            self.prglog_mgr.debug("{}(): Unsupported Windows version".format(GET_MY_NAME()))
            return False

        self.evtmon.stop()
        return True

    def connect_network_drive(self, url, account_id="", account_pw=""):
        """Connect a network directory

            - Win + R
            - Type URL
            - Enter
            - Type ID and Password
            - Enter

        Args:
            url (str): The network drive's URL
            account_id (str): The account ID
            account_pw (str): The account password

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), url))

        self.evtmon.start(T_ACTION_CONNECT_NETWORK_DIR)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_NETWORK_DRIVE,
                       action=T_ACTION_CONNECT_NETWORK_DIR,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="URL({})".format(url),
                       note="WIN+R -> URL -> ENTER")
        )

        self.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.5, note="Windows Run")
        self.hypervisor.send_event_keyboard(url, delay_s=1.5)
        ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=3, note="Connect a network drive")

        # We should wait until the window pops up
        # It takes approx. 1m ~ 3m depending on the network environment
        # ex) avg. 1m 47s in XP during our experiments
        time.sleep(150)

        if id != "":
            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_NETWORK_DRIVE,
                           action=T_ACTION_CONNECT_NETWORK_DIR,
                           method=T_ACTION_METHOD_K,
                           user=self.hypervisor.user_name,
                           desc="URL({})".format(url),
                           note="ID({}) PW({})".format(account_id, account_pw))
            )

            self.hypervisor.send_event_keyboard(account_id, delay_s=1.5, note="ID")
            self.hypervisor.send_event_keyboard(['TAB'], delay_s=1.5)
            self.hypervisor.send_event_keyboard(account_pw, delay_s=1.5, note="PW")
            ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=3, note="Connect a network drive")

        self.evtmon.stop()
        return ret

    def map_network_drive(self, drive, url, account_id="", account_pw=""):
        """Map a network directory as a local drive

            - Execute (C:\Windows\System32\rundll32.exe shell32.dll,SHHelpShortcuts_RunDLL Connect)
            - Set the drive letter
            - Type URL
            - Enter
            - Type ID and Password
            - Enter

        Args:
            drive (str): The drive letter
            url(str): The network drive's URL
            account_id (str): The account ID
            account_pw (str): The account password

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), url))

        self.evtmon.start(T_ACTION_MAP_NETWORK_DIR)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_NETWORK_DRIVE,
                       action=T_ACTION_MAP_NETWORK_DIR,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="URL({}) -> Drive({})".format(url, drive),
                       note="Open 'Map Network Drive' control")
        )

        # [Alternative]
        # path_app = "C:\\Windows\\System32\\rundll32.exe"
        # path_dll = "shell32.dll,SHHelpShortcuts_RunDLL"
        # arguments = [path_dll, 'Connect']
        #
        # try:
        #     process, stdout, stderr = self.hypervisor.execute_process(
        #         path_app, arguments, timeout_ms=600000, do_not_wait=True, delay_s=3
        #     )
        # except Exception as e:
        #     self.evtmon.stop()
        #     self.prglog_mgr.debug("{}(): Exception occurs ({})".format(GET_MY_NAME(), e))
        #     return False
        #
        # if process is None:
        #     self.evtmon.stop()
        #     self.prglog_mgr.debug("{}(): Cannot identify the target process's PID".format(GET_MY_NAME()))
        #     return False

        self.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.5, note="Windows Run")
        command = "Rundll32.exe Shell32.dll,SHHelpShortcuts_RunDLL Connect"
        self.hypervisor.send_event_keyboard(command, delay_s=1.5)
        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=3, note="Open 'Map Network Drive' control")

        # Set the drive letter
        self.hypervisor.send_event_keyboard(['TAB'], ['LSHIFT'], delay_s=1.5)
        self.hypervisor.send_event_keyboard(drive, delay_s=1.5, note="Set the drive letter")

        # Type URL
        self.hypervisor.send_event_keyboard(['TAB'], delay_s=1.5)
        self.hypervisor.send_event_keyboard(url, delay_s=1.5, note="Folder's URL")
        ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=8, note="Click 'Finish'")

        if id != "":
            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_NETWORK_DRIVE,
                           action=T_ACTION_MAP_NETWORK_DIR,
                           method=T_ACTION_METHOD_K,
                           user=self.hypervisor.user_name,
                           desc="URL({}) -> Drive({})".format(url, drive),
                           note="ID({}), PW({})".format(account_id, account_pw))
            )

            # Type ID and Password
            self.hypervisor.send_event_keyboard(account_id, delay_s=1.5, note="ID")
            self.hypervisor.send_event_keyboard(['TAB'], delay_s=1.5)
            self.hypervisor.send_event_keyboard(account_pw, delay_s=1.5, note="PW")
            ret = self.hypervisor.send_event_keyboard(['ENTER'], delay_s=3,
                                                      note="Map a network directory as a local drive")

        self.evtmon.stop()
        return ret

    def unmap_network_drive(self, drive):
        """Unmap mapped network drives (experimental)

            Not working?
            Execute (C:\Windows\System32\rundll32.exe shell32.dll,SHHelpShortcuts_RunDLL Disconnect)

        Args:
            drive (str): The drive letter

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        path_app = "C:\\Windows\\System32\\rundll32.exe"
        path_dll = "shell32.dll,SHHelpShortcuts_RunDLL"
        arguments = [path_dll, 'Disconnect']

        self.evtmon.start(T_ACTION_DISCONNECT)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_NETWORK_DRIVE,
                       action=T_ACTION_DISCONNECT,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="{} {}".format(path_app, arguments),
                       note=drive)
        )

        try:
            self.hypervisor.execute_process(
                path_app, arguments, timeout_ms=120000, do_not_wait=True, delay_s=3
            )
        except Exception as e:
            self.evtmon.stop()
            self.prglog_mgr.debug("{}(): Exception occurs ({})".format(GET_MY_NAME(), e))
            return False

        self.evtmon.stop()
        return True

    def connect_remote_desktop(self, url, port=3389, account_id="", account_pw=""):
        """Connect a remote desktop using 'mstsc.exe'

            - Win + R
            - Type 'mstsc'
            - Enter
            - Type IP:Port
            - Type ID and Password
            - Enter

        Args:
            url (str): The target remote desktop's URL
            port (int): The target remote desktop's port
            account_id (str): The account ID
            account_pw (str): The account password

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), url))

        self.evtmon.start(T_ACTION_CONNECT_REMOTE_DESKTOP)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_REMOTE_DESKTOP,
                       action=T_ACTION_CONNECT_REMOTE_DESKTOP,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="URL({}) PORT({})".format(url, port),
                       note="WIN+R -> mstsc -> ENTER")
        )

        self.hypervisor.send_event_keyboard('r', ['LWIN'], delay_s=1.5, note="Windows Run")
        self.hypervisor.send_event_keyboard('mstsc', delay_s=1.5)
        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=3, note="Launch 'mstsc'")

        if port > 0 and port != 3389:
            computer = "{}:{}".format(url, port)
        elif port == 3389:
            computer = url
        else:
            self.evtmon.stop()
            self.prglog_mgr.debug("{}(): Invalid Port number {}".format(GET_MY_NAME(), port))
            return False

        self.hypervisor.send_event_keyboard('o', ['ALT'], delay_s=1.5, note="Click 'Option'")

        if self.vm_os_type.code <= VmPopOSType.WindowsVista.code:
            self.hypervisor.send_event_keyboard(['TAB', 'TAB'], delay_s=1.5, note="Focus on 'Computer' editbox")

        self.hypervisor.send_event_keyboard(['E_END'], ['LSHIFT'], delay_s=1.5)
        self.hypervisor.send_event_keyboard(computer, delay_s=1.5, note="URL")
        self.hypervisor.send_event_keyboard(['TAB'], delay_s=1.5)
        self.hypervisor.send_event_keyboard(['E_END'], ['LSHIFT'], delay_s=1.5)
        self.hypervisor.send_event_keyboard(account_id, delay_s=1.5, note="ID")
        self.hypervisor.send_event_keyboard(['ENTER'], delay_s=3, note="Click 'Connect'")

        if id != "":
            time.sleep(7)
            self.actlog_mgr.add(
                ActionItem(aclass=T_CLASS_REMOTE_DESKTOP,
                           action=T_ACTION_CONNECT_REMOTE_DESKTOP,
                           method=T_ACTION_METHOD_K,
                           user=self.hypervisor.user_name,
                           desc="URL({}) PORT({})".format(url, port),
                           note="ID({}) PW({})".format(account_id, account_pw))
            )

            if self.vm_os_type.code < VmPopOSType.WindowsVista.code:
                self.hypervisor.send_event_keyboard(['TAB'], delay_s=1.5)
            self.hypervisor.send_event_keyboard(account_pw, delay_s=1.5, note="PW")
            self.hypervisor.send_event_keyboard(['ENTER'], delay_s=3, note="Connect a remote desktop")

        ret = self.hypervisor.send_event_keyboard('y', delay_s=3, note="Click 'Yes'")
        self.evtmon.stop()
        return ret

    def disconnect_remote_desktop(self):
        """Disconnect from a connected remote desktop

            - ALT + F4
            - Type 'd'
            - Enter

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        self.evtmon.start(T_ACTION_DISCONNECT)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_REMOTE_DESKTOP,
                       action=T_ACTION_DISCONNECT,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="")
        )

        ret = self.terminate_process(name='mstsc', evtlog_off=True)

        self.evtmon.stop()
        return ret

    def check_notification_center(self):
        """Check the messages of Notification Center (Windows 10 ~)

            - AKA Action Center: WIN + 'a'

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vm_os_type.code < VmPopOSType.Windows10.code:
            self.prglog_mgr.debug("{}(): The running OS is not Windows 10 or higher".format(GET_MY_NAME()))
            return False

        self.evtmon.start(T_ACTION_CHECK_NOTIFICATION)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_COMMON,
                       action=T_ACTION_CHECK_NOTIFICATION,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="WIN + a")
        )

        self.hypervisor.send_event_keyboard('a', ['LWIN'], delay_s=2.0, note="Launch Windows Notification Center")
        ret = self.hypervisor.send_event_keyboard(['ESC'], delay_s=1.5)

        self.evtmon.stop()
        return ret

    def create_virtual_desktop(self):
        """Create a new virtual desktop (Windows 10 ~)

            - WIN + CTRL + 'd'

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vm_os_type.code < VmPopOSType.Windows10.code:
            self.prglog_mgr.debug("{}(): The running OS is not Windows 10 or higher".format(GET_MY_NAME()))
            return False

        self.evtmon.start(T_ACTION_CREATE_VIRTUAL_DESKTOP)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_COMMON,
                       action=T_ACTION_CREATE_VIRTUAL_DESKTOP,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="WIN + CTRL + d")
        )

        ret = self.hypervisor.send_event_keyboard('d', ['LWIN', 'CTRL'], delay_s=2.0, note="Create a virtual desktop")

        self.evtmon.stop()
        return ret

    def close_virtual_desktop(self):
        """Close a virtual desktop (Windows 10 ~)

            - WIN + CTRL + 'F4'

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vm_os_type.code < VmPopOSType.Windows10.code:
            self.prglog_mgr.debug("{}(): The running OS is not Windows 10 or higher".format(GET_MY_NAME()))
            return False

        self.evtmon.start(T_ACTION_CLOSE_VIRTUAL_DESKTOP)

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_COMMON,
                       action=T_ACTION_CLOSE_VIRTUAL_DESKTOP,
                       method=T_ACTION_METHOD_K,
                       user=self.hypervisor.user_name,
                       desc="",
                       note="WIN + CTRL + F4")
        )

        ret = self.hypervisor.send_event_keyboard(['F4'], ['LWIN', 'CTRL'], delay_s=2.0, note="Close a virtual desktop")

        self.evtmon.stop()
        return ret
