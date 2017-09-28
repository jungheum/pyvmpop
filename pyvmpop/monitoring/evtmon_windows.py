# -*- coding: utf-8 -*-

"""EvtMonWindows (subclass of EvtMonBase)

    * Description
        Event monitor for Windows
"""

import os
import time
import logging
from decorator import decorator
from pyvmpop.common_defines import *
from pyvmpop.utility.pt_utils import PtUtils
from pyvmpop.logging.actlog_manager import ActionItem
from pyvmpop.logging.evtlog_manager import EvtLogManager
from .evtmon_base import EvtMonBase


@decorator
def check_instance(func, *args, **kwargs):
    """Decorator for checking if the instances are valid or not
    """
    msg = ""
    if args[0].agent_path == "":
        msg = "'agent_path' is empty"
    elif args[0].vmpop().automation is None:
        msg = "'Automation' instance is not valid"

    if msg != "":
        args[0].prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
        return False

    return func(*args, **kwargs)


class EvtMonWindows(EvtMonBase):
    """EvtMonWindows class

        - This module uses Process Monitor (procmon.exe) from Microsoft's Windows SysInternals
          (https://technet.microsoft.com/en-us/sysinternals/processmonitor.aspx)

        - Alternatively, you can develop and use your own monitoring agent

    Attributes:
        Refer to EvtMonBase class
    """
    def __init__(self, vmpop, evtmon_type):
        """The constructor

        Args:
            Refer to EvtMonBase class
        """
        super(EvtMonWindows, self).__init__(vmpop, evtmon_type)

        # Set the default path
        if self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_32 or self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_64:
            self.agent_path = self.hypervisor.shared_dir_vm + "\\windows\\monitor\\procmon.exe"

        # Set the progress log manager
        self.prglog_mgr = logging.getLogger(__name__)
        return

    @check_instance
    def pre_process(self):
        """Pre-processes for recording events

            - Terminate 'procmon.exe' if running

        Returns:
            True or False
        """
        if self.switch is False:
            return True

        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        # Set arguments for monitoring agent
        if self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_32 or self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_64:
            arguments = ['/AcceptEula', '/Terminate']
        else:
            return False

        env = ["SEE_MASK_NOZONECHECKS=1"]  # To disable 'Open File Security Warning'

        try:
            process, stdout, stderr = self.hypervisor.execute_process(
                self.agent_path, arguments, environment=env, hidden=True,
                timeout_ms=10000, delay_s=0.5, actlog_off=True
            )
        except Exception as e:
            self.prglog_mgr.debug("{}(): Exception occurs".format(GET_MY_NAME()))
            return False

        if process is None:
            self.prglog_mgr.debug("{}(): Cannot identify the target process's PID".format(GET_MY_NAME()))
            return False
        return True

    @check_instance
    def start(self, event_name, timeout_s=0, restore_active_window=False):
        """Start a monitoring agent

        Args:
            event_name (str): The name of the event for managing log files
            timeout_s (int): If not 0, set the value for 'execute_process'
            restore_active_window (bool): If True, ensure that the original active window is still in active status.
                                          There is a possibility to loose the focus as a result of executing the agent.
                                          (This is required when controlling application elaborately)

        Returns:
            True or False
        """
        if self.switch is False:
            return True

        self.prglog_mgr.info("{}(): EVENT_NO({}), EVENT({})".format(GET_MY_NAME(), self.event_count, event_name))

        # Set the output file path and arguments for monitoring agent
        if self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_32 or self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_64:
            output_path = self.hypervisor.shared_dir_vm_temp + "\\temp_{}.pml".format(self.event_count)
            arguments = ['/AcceptEula', '/Quiet', '/Nofilter', '/BackingFile', output_path]
        else:
            return False

        # Get information about the active window
        if restore_active_window is True:
            pid, title = self.vmpop().automation.get_foreground_window()

        self.time_range[0] = self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_SPECIAL,
                       action=T_ACTION_BEGIN_MONITORING,
                       method=T_ACTION_METHOD_EXE,
                       user=self.hypervisor.user_name,
                       desc="EventNo({})".format(self.event_count),
                       note="EventName({})".format(event_name))
        )

        if timeout_s > 0:
            timeout_ms = timeout_s * 1000
        else:
            timeout_ms = 900000  # default timeout is 15 min (assume that an event is limited to 15 min)

        env = ["SEE_MASK_NOZONECHECKS=1"]  # To disable 'Open File Security Warning'

        try:
            process, stdout, stderr = self.hypervisor.execute_process(
                self.agent_path, arguments, environment=env, hidden=True,
                do_not_wait=True, timeout_ms=timeout_ms, delay_s=3.50,  # This delay is important for the operation
                                                                        # 3.0 (1109) 3.25 (1110) 3.50 (1111)
                actlog_off=True
            )
        except Exception as e:
            self.prglog_mgr.debug("{}(): Exception occurs".format(GET_MY_NAME()))
            return False

        if process is None:
            self.prglog_mgr.debug("{}(): Cannot identify the target process's PID".format(GET_MY_NAME()))
            return False

        # Check if the event log file is created and valid for the next step
        invalid = False

        # Set the output file path and arguments for monitoring agent
        if self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_32 or self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_64:
            target_path_host = self.hypervisor.shared_dir_host_temp + "\\temp_{}.pml".format(self.event_count)

            # Wait until the event log file is created
            if os.path.exists(target_path_host) is False:
                self.prglog_mgr.info("{}(): Wait until the event log file is created".format(GET_MY_NAME()))
                time.sleep(0.3)
                t1 = time.clock()
                while os.path.exists(target_path_host) is False:
                    time.sleep(0.5)
                    if time.clock() - t1 > 15:  # if there is no update during 15 seconds
                        self.prglog_mgr.debug("{}(): The monitor process is not working properly".format(GET_MY_NAME()))
                        invalid = True
                        break

            if invalid is False:
                size_mb = float(os.path.getsize(target_path_host) / 1024 / 1024)
                self.prglog_mgr.info("{}(): The size of the first PML file is {:.1f} MB".format(GET_MY_NAME(), size_mb))
                t1 = time.clock()
                while size_mb < 16:
                    time.sleep(0.3)
                    size_mb_new = float(os.path.getsize(target_path_host) / 1024 / 1024)
                    if time.clock() - t1 > 15:  # if there is no update during 15 seconds
                        self.prglog_mgr.debug("{}(): The monitor process is not working properly".format(GET_MY_NAME()))
                        invalid = True
                        break
                    if size_mb_new <= size_mb:
                        continue
                    size_mb = size_mb_new
                    self.prglog_mgr.info("{}(): The size of the first PML file is {:.1f} MB".format(GET_MY_NAME(), size_mb))
        else:
            return False

        if invalid is True:
            # Terminate the monitor process
            self.vmpop().automation.terminate_process(
                name="procmon*", run_as_admin=True, evtlog_off=True, actlog_off=True
            )
            return False

        # Update variables
        self.running_pid = process.pid
        self.event_name = event_name
        self.time_range_int[0] = time.clock()  # the beginning of this event

        # Ensure that the original active window is still in active status
        if restore_active_window is True:
            if pid != -1:
                if self.vmpop().automation.set_foreground_window(pid=pid) is False:
                    self.vmpop().automation.set_foreground_window(pid=pid)
            elif title != "":
                if self.vmpop().automation.set_foreground_window(window_title=title) is False:
                    self.vmpop().automation.set_foreground_window(window_title=title)
        return True

    @check_instance
    def stop(self):
        """Stop a running monitoring agent

        Returns:
            True or False
        """
        if self.switch is False:
            return True

        self.prglog_mgr.info("{}(): EVENT_NO({}), AGENT_PID({})".format(
            GET_MY_NAME(), self.event_count, self.running_pid)
        )

        if self.running_pid == -1:
            self.prglog_mgr.debug("{}(): Cannot identify the monitor's PID".format(GET_MY_NAME()))
            # Update variables
            self.event_name = ""
            self.event_count += 1
            self.time_range_int = [0, 0]
            return False

        # Set arguments for monitoring agent
        if self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_32 or self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_64:
            arguments = ['/AcceptEula', '/Terminate']
        else:
            return False

        # Check the time difference
        self.time_range_int[1] = time.clock()
        diff = float(self.time_range_int[1] - self.time_range_int[0])
        self.prglog_mgr.info("{}(): This event took {:.3f} seconds".format(GET_MY_NAME(), diff))
        # if diff < 5:  # Procmon.exe should be executed during at least 5 seconds
        #     time.sleep(5-diff)

        self.time_range[1] = self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_SPECIAL,
                       action=T_ACTION_END_MONITORING,
                       method=T_ACTION_METHOD_EXE,
                       user=self.hypervisor.user_name,
                       desc="EventNo({})".format(self.event_count),
                       note="End Of EventNo({})".format(self.event_count))
        )

        env = ["SEE_MASK_NOZONECHECKS=1"]  # To disable 'Open File Security Warning'

        try:
            process, stdout, stderr = self.hypervisor.execute_process(
                self.agent_path, arguments, environment=env, hidden=True,
                timeout_ms=30000, delay_s=1.25,  # 0.5 -> 1.0 (1106) -> 1.25 (1107)
                actlog_off=True
            )
        except Exception as e:
            self.prglog_mgr.debug("{}(): Exception occurs".format(GET_MY_NAME()))
            return False

        if process is None:
            self.prglog_mgr.debug("{}(): Cannot identify the target process's PID".format(GET_MY_NAME()))
            return False

        # Call post-process()
        if self.post_process() is False:
            self.event_not_processed.append((self.event_count, self.event_name, self.time_range))
            self.prglog_mgr.debug("{}(): EVENT_NO({}) is not processed".format(GET_MY_NAME(), self.event_count))

        # Update variables
        self.event_name = ""
        self.event_count += 1
        self.running_pid = -1  # -> monitor process is terminated
        self.time_range_int = [0, 0]

        time.sleep(2.0)  # (2.0 for all) (1.75 for Windows 10) (1.5 is not working)
        return True

    def post_process(self):
        """Post-processes

            - Converting the created event log file
            - Saving the event log file to the log directory

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): EVENT_NO({}), TIME_RANGE({})".format(
            GET_MY_NAME(), self.event_count, self.time_range)
        )

        if self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_32 or self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_64:
            # Set the target and output file path
            target_path = self.hypervisor.shared_dir_vm_temp + "\\temp_{}.pml".format(self.event_count)
            target_path_host = self.hypervisor.shared_dir_host_temp + "\\temp_{}.pml".format(self.event_count)
            output_path = self.hypervisor.shared_dir_vm_temp + "\\temp_{}.csv".format(self.event_count)

            if os.path.exists(target_path_host) is False:
                self.prglog_mgr.debug("{}(): The target PML file does not exist".format(GET_MY_NAME()))
                return False

            size = os.path.getsize(target_path_host)
            size_mb = float(size / 1024 / 1024)
            self.prglog_mgr.info("{}(): The size of the first PML file is {:.1f} MB ({} Bytes)".format(
                GET_MY_NAME(), size_mb, size)
            )

            # Convert the log file format with a filter (if necessary) to a CSV file
            if self.convert_pml_to_csv(target_path, output_path) is False:
                return False
        else:
            return False

        # ------------------------------------------------------------------------------
        # [For normalizing and managing event records... (Possible future work)]
        evtlog_mgr = EvtLogManager(
            shared_dir_host_temp=self.hypervisor.shared_dir_host_temp,
            log_dir=self.actlog_mgr.get_log_dir(),
            evtmon_type=self.evtmon_type
        )

        evtlog_mgr.basic_config(
            action_seq=self.actlog_mgr.get_action_seq(),
            event_seq=self.event_count, event_name=self.event_name,
            time_range=self.time_range
        )

        # if evtlog_mgr.start() is False:  # using Thread
        if evtlog_mgr.run() is False:
            self.prglog_mgr.debug("{}(): The evtlog manager triggered FALSE, try one more time".format(GET_MY_NAME()))
            time.sleep(15)
            if evtlog_mgr.run() is False:  # Try one more time
                return False
        # ------------------------------------------------------------------------------

        # Delete the original log files
        if self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_32 or self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_64:
            files = self.hypervisor.shared_dir_host_temp + "\\temp_{}*.pml".format(self.event_count)
            PtUtils.delete_file(files)

        if os.path.exists(target_path_host) is True:
            return False
        return True

    def convert_pml_to_csv(self, target_path, output_path):
        """Convert the log file format with a filter (if necessary) and Save it

        Args:
            target_path (str): The full path of the target PML file
            output_path (str): The full path of the output CSV file

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): Create a CSV ({}) ".format(GET_MY_NAME(), output_path))

        procmon_config = self.hypervisor.shared_dir_vm + "\\windows\\monitor\\procmon_vmpop.pmc"

        arguments = ['/AcceptEula', '/Quiet']
        arguments.extend(["/OpenLog", target_path])
        arguments.extend(["/LoadConfig", procmon_config, "/SaveApplyFilter"])
        arguments.extend(["/SaveAs", output_path])

        timeout_ms = 300000  # default timeout is 5 minutes
        env = ["SEE_MASK_NOZONECHECKS=1"]  # To disable 'Open File Security Warning'

        try:
            process, stdout, stderr = self.hypervisor.execute_process(
                self.agent_path, arguments, environment=env, hidden=True,
                do_not_wait=True, timeout_ms=timeout_ms, delay_s=1.0,
                actlog_off=True
            )
        except Exception as e:
            self.prglog_mgr.debug("{}(): Exception occurs".format(GET_MY_NAME()))
            return False

        if process is None:
            self.prglog_mgr.debug("{}(): Cannot identify the target process's PID".format(GET_MY_NAME()))
            return False

        # Wait until the monitor process is terminated
        terminated = True

        if self.hypervisor.check_process_terminated_normally(process) is False:
            self.prglog_mgr.info("{}(): Wait until the monitor process is terminated".format(GET_MY_NAME()))
            time.sleep(0.2)

        t1 = time.clock()
        while self.hypervisor.check_process_terminated_normally(process) is False:
            time.sleep(0.2)
            if time.clock() - t1 > 90:  # 1st waiting time is 1:30
                terminated = False
                break

        if terminated is False:
            if self.vmpop().automation.check_process_exist(process.pid) is True:
                # If not finished yet, one of PML files is possibly corrupted
                self.prglog_mgr.info("{}(): One of PML files may be corrupted".format(GET_MY_NAME()))
                if self.vmpop().automation.set_foreground_window(window_title="Process Monitor") is True:
                    self.vmpop().hypervisor.send_event_keyboard(['ENTER'])

                t1 = time.clock()
                while self.hypervisor.check_process_terminated_normally(process) is False:
                    time.sleep(0.5)
                    if time.clock() - t1 > 120:  # 2nd waiting time is 2 minutes
                        self.prglog_mgr.info("{}(): The monitor process is still running".format(GET_MY_NAME()))
                        self.vmpop().automation.terminate_process(name="procmon*", run_as_admin=True, evtlog_off=True)
                        break

        self.prglog_mgr.info("{}(): The monitor process is terminated".format(GET_MY_NAME()))
        return True

    def extra_process(self):
        """Extra-process (not used)

            - Processing the remaining log files (when the post-process is failed)
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if len(self.event_not_processed) > 0:
            return

        if not (self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_32 or
                self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_64):
            return

        for event_id, event_name, time_range in self.event_not_processed:
            # Set the target and output file path
            target_path = self.hypervisor.shared_dir_vm_temp + "\\temp_{}.pml".format(event_id)
            target_path_host = self.hypervisor.shared_dir_host_temp + "\\temp_{}.pml".format(event_id)
            output_path = self.hypervisor.shared_dir_vm_temp + "\\temp_{}.csv".format(event_id)

            if os.path.exists(target_path_host) is False:
                self.prglog_mgr.debug("{}(): The target PML file does not exist".format(GET_MY_NAME()))
                continue

            # Convert the log file format with a filter (if necessary) to a CSV file
            if self.convert_pml_to_csv(target_path, output_path) is False:
                continue

            # ------------------------------------------------------------------------------
            # [For normalizing and managing event records... (Possible future work)]
            evtlog_mgr = EvtLogManager(
                shared_dir_host_temp=self.hypervisor.shared_dir_host_temp,
                log_dir=self.actlog_mgr.get_log_dir(),
                evtmon_type=self.evtmon_type
            )

            evtlog_mgr.basic_config(
                action_seq=self.actlog_mgr.get_action_seq(),
                event_seq=event_id, event_name=event_name,
                time_range=time_range
            )

            # evtlog_mgr.start()
            if evtlog_mgr.run() is False:
                self.prglog_mgr.debug(
                    "{}(): The evtlog manager triggered FALSE, try one more time".format(GET_MY_NAME())
                )
                time.sleep(15)
                if evtlog_mgr.run() is False:  # Try one more time
                    return False
            # ------------------------------------------------------------------------------

            # Delete the original log files
            files = self.hypervisor.shared_dir_host_temp + "\\temp_{}*.pml".format(self.event_count)
            PtUtils.delete_file(files)

        return
