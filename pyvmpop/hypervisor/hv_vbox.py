# -*- coding: utf-8 -*-

"""HvVBox (subclass of HvBase)

    * Description
        Modules for communicating with the VirtualBox hypervisor
"""

import os
import logging
import sys
import time
from decorator import decorator

# VirtualBox API (pyvbox)
import virtualbox

# VmPop automation modules
from pyvmpop.hypervisor.hv_base import HvBase
from pyvmpop.common_defines import *
from pyvmpop.utility.pt_utils import PtUtils
from pyvmpop.logging.actlog_manager import ActionItem


@decorator
def check_session(func, *args, **kwargs):
    """Decorator for checking variables
    """
    if args[0].vbox_session is None:
        msg = "There is no connected session info"
        args[0].prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
        return False
    return func(*args, **kwargs)


class HvVBox(HvBase):
    """HvVBox class

    Attributes:
        Refer to HvBase on the common attributes

        process_count (int): The current process count executed by process_create_ex()
        timed_out_process_count (int): The count of timed_out processes

        vbox (virtualbox.VirtualBox's IVirtualBox)
        vbox_machine (virtualbox.VirtualBox's IMachine)
        vbox_machine_clone (virtualbox.VirtualBox's IMachine)
        vbox_session (virtualbox.VirtualBox's ISession)
        vbox_guest_session (virtualbox.VirtualBox's IGuestSession)

        clone_name (str): The name of cloned VM
        linked_snapshot_name (str): The name of linked snapshot
        vbox_manage (str): The path of 'VboxManage' binary

    .. note:: *pyvbox* package (import virtualbox) is required
    """

    def __init__(self, vmpop, start_mode=VmPopStartMode.CURRENT):
        """The constructor

        Args:
            vmpop (VmPop): The active VmPop instance
            start_mode (VmPopStartMode): Start mode (CURRENT or SNAPSHOT or CLONE_LINKED or CLONE_FULL)
        """
        super(HvVBox, self).__init__(vmpop, start_mode)
        self.hypervisor_type = VmPopHypervisor.VBOX

        self.shared_name = "VMPOP_SHARED_DIR"
        self.shared_dir_vm = "\\\\VBOXSVR\\{0}".format(self.shared_name)

        # Execution tracers (log manager and event manager)
        self.prglog_mgr = logging.getLogger(__name__)
        self.process_count = 0
        self.timed_out_process_count = 0

        # vbox variables
        self.vbox_machine = None  # -> vbox_session.machine (IMachine)
        self.vbox_session = None
        self.vbox_guest_session = None

        # vbox 'clone feature'
        self.vbox_machine_clone = None
        self.clone_name = ""
        self.linked_snapshot_name = ""

        # members for virtualbox operations
        try:
            self.vbox = virtualbox.VirtualBox()
        except:
            self.vbox = None
            msg = "Cannot load 'vboxapi'"
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
            pass

        # Path of VboxManage
        self.vbox_manage = ""
        return

    '''
    #-----------------------------------------------------------------------------------
    # Functions for handling VirtualBox hypervisor
    #-----------------------------------------------------------------------------------
    '''
    def connect_to_vm(self, vm_name, snapshot_name="", debug_mode=False):
        """Connect to a VM

        Args:
            vm_name (str): The name of virtual machine registered in VirtualBox
            snapshot_name (str): The name of snapshot registered in a virtual machine
            debug_mode (bool): If True, turn on DEBUG_MODE

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): Connect to a VM".format(GET_MY_NAME()))

        # Find the target VM
        try:
            self.vbox_machine = self.vbox.find_machine(vm_name)
        except:
            msg = "Cannot find the machine named {}".format(vm_name)
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        # Get the current state
        if self.vbox_machine.state == virtualbox.library.MachineState(5):
            self.vm_state = VmPopState.RUNNING
        elif self.vbox_machine.state == virtualbox.library.MachineState(6):
            self.vm_state = VmPopState.PAUSED
        else:
            self.vm_state = VmPopState.STOPPED

        # get the current session
        try:
            self.vbox_session = self.vbox_machine.create_session()
        except:
            msg = "Cannot create a session with the target VM"
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        # SNAPSHOT mode (Start with a specific snapshot)
        if self.vm_start_mode == VmPopStartMode.SNAPSHOT:
            try:
                snapshot = self.vbox_machine.find_snapshot(snapshot_name)
                progress = self.vbox_session.machine.restore_snapshot(snapshot)
                progress.wait_for_completion()
            except:
                msg = "Restoring a snapshot of the target VM failed"
                self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
                return False

        # CLONE_FULL mode (Create a full clone)
        elif self.vm_start_mode == VmPopStartMode.CLONE_FULL:
            try:
                # Create a new VM
                self.clone_name = "{} (Vmpop Full Clone)".format(vm_name)
                self.vbox_machine_clone = self.vbox.create_machine(
                    "", self.clone_name, [], self.vbox_machine.os_type_id, ""
                )

                # Make a clone
                progress = self.vbox_machine.clone_to(
                    self.vbox_machine_clone, virtualbox.library.CloneMode.machine_state, []
                )
                progress.wait_for_completion()

                # Register a newly created clone
                self.vbox.register_machine(self.vbox_machine_clone)
                self.vbox_machine = self.vbox_machine_clone
            except:
                msg = "Creating a full clone of the target VM failed"
                self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
                return False

        # CLONE_LINKED mode (Create a linked clone)
        elif self.vm_start_mode == VmPopStartMode.CLONE_LINKED:
            try:
                # Create a new VM
                self.clone_name = "{} (Vmpop Linked Clone)".format(vm_name)
                try:
                    self.vbox_machine_clone = self.vbox.find_machine(self.clone_name)
                except:
                    self.vbox_machine_clone = self.vbox.create_machine(
                        "", self.clone_name, [], self.vbox_machine.os_type_id, ""
                    )

                # Take a snapshot for linking the original VM and a newly created clone
                self.linked_snapshot_name = "[VmPop] Linked base for {}".format(vm_name)
                try:
                    self.vbox_session.machine.find_snapshot(self.linked_snapshot_name)
                except:
                    progress, uuid = self.vbox_session.machine.take_snapshot(self.linked_snapshot_name, "", True)
                    progress.wait_for_completion()

                # Make a clone
                snapshot = self.vbox_machine.find_snapshot(self.linked_snapshot_name)
                progress = snapshot.machine.clone_to(
                    self.vbox_machine_clone,
                    virtualbox.library.CloneMode.machine_state,
                    [virtualbox.library.CloneOptions.link]
                )
                progress.wait_for_completion()

                # Register a newly created clone
                self.vbox.register_machine(self.vbox_machine_clone)
                self.vbox_machine = self.vbox_machine_clone
            except:
                msg = "Creating a linked clone of the target VM failed"
                self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
                return False

        if debug_mode is True:
            return True

        # Run the VM if it is stopped or paused
        if self.vm_state == VmPopState.STOPPED:
            if self.start_vm('gui') is False:
                return False
        elif self.vm_state == VmPopState.PAUSED:
            if self.resume_vm() is False:
                return False

        # Get OS type
        os_name = self.vbox_machine.os_type_id
        self.vm_os_type = VmPopOSType.find_by_name(os_name)
        self.vm_name = vm_name if self.clone_name == "" else self.clone_name
        return True

    @check_session
    def start_vm(self, frontend_type='gui'):
        """Start a VM

        Args:
            frontend_type (str): normally 'gui' or 'headless'
                - gui : VirtualBox GUI front-end
                - headless: VBoxHeadless (VRDE Server) front-end --> VM runs without GUI
                - sdl: VirtualBox SDL front-end
                - emergencystop: reserved value, used for aborting the currently running VM or session owner

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vm_state != VmPopState.STOPPED:
            msg = "The VM is not in stopped state"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        self.unlock()

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_COMMON,
                       action=T_ACTION_START_VM,
                       method=T_ACTION_METHOD_HV,
                       user=self.user_name,
                       desc="",
                       note=""),
            do_not_get_time=True
        )

        # Launch a VM
        try:
            progress = self.vbox_machine.launch_vm_process(self.vbox_session, frontend_type, environment='')
            progress.wait_for_completion()
        except:
            msg = "Cannot start the VM"
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        # Wait until completing booting processes
        if self.wait_vm_for_booting(VmPopOSRunLevel.USERLAND) is False:
            msg = "Exception occurred in the booting process"
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        self.vm_state = VmPopState.RUNNING
        time.sleep(5)  # Wait for loading system apps (need a few more seconds?)
        return True

    @check_session
    def resume_vm(self):
        """Resume a VM

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vm_state != VmPopState.PAUSED:
            msg = "The VM is not in paused state"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        try:
            self.vbox_session.console.resume()
        except:
            msg = "Cannot resume the VM"
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
            return False
        time.sleep(2)
        return True

    @check_session
    def stop_vm(self, mode=VmPopStopMode.SHUT_DOWN):
        """Stop a running VM

        Args:
            mode (VmPopStopMode): SAVE_STATE, SHUT_DOWN or POWER_OFF

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_COMMON,
                       action=T_ACTION_STOP_VM,
                       method=T_ACTION_METHOD_HV,
                       user=self.user_name,
                       desc="",
                       note="MODE({})".format(mode.name))
        )

        if self.vm_state != VmPopState.RUNNING:
            msg = "The VM is not in running state"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        # Close the current user session
        if self.vbox_guest_session is not None:
            self.close_user_session()

        if mode == VmPopStopMode.SAVE_STATE:
            progress = self.vbox_session.console.save_state()
            progress.wait_for_completion()
            self.vm_state = VmPopState.SAVED

        elif mode == VmPopStopMode.POWER_OFF:
            progress = self.vbox_session.console.power_down()
            progress.wait_for_completion()
            self.vm_state = VmPopState.STOPPED

        elif mode == VmPopStopMode.SHUT_DOWN:
            self.vbox_session.console.power_button()
            while self.vbox_machine.state != virtualbox.library.MachineState(1):
                time.sleep(2)
            self.vm_state = VmPopState.STOPPED

        time.sleep(3)
        return True

    def lock(self):
        """Lock the current session of the VM
        """
        try:
            self.vbox_machine.lock_machine(self.vbox_session, virtualbox.library.LockType.shared)
        except:
            pass

    def unlock(self):
        """Unlock the current session of the VM
        """
        try:
            self.vbox_session.unlock_machine()
        except:
            pass

    def update_global_session(self):
        """Update the global session

            - 'Run level' is not updated after logoff (sign out)
                - self.vbox_session.console.guest.additions_run_level
                - I expected 'Userland', but it's still 'Desktop' (-> bug?)
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        try:
            session = self.vbox_machine.create_session()
        except:
            msg = "Cannot create a session with the target VM"
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
        else:
            self.vbox_session = session

    def create_user_session(self, user_id, password, validate_shared_drive=True):
        """Create a new session

        Args:
            user_id (str): User ID
            password (str): User password
            validate_shared_drive (bool): If True, create or check the shared drive

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): ID({}), PW({})".format(GET_MY_NAME(), user_id, password))

        # Check OS run level - minimum requirement is USERLAND
        if self.wait_vm_for_booting(VmPopOSRunLevel.USERLAND) is False:
            msg = "OS run level 'Userland' or 'Desktop' is required"
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        # Create a new guest session
        try:
            gs = self.vbox_session.console.guest.create_session(user_id, password)
        except Exception as e:
            msg = "GuestSession failed to start (ID/PW is invalid or the system is not running)"
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        if self.vbox_guest_session is not None:
            self.close_user_session()

        self.vbox_guest_session = gs

        # reason = self.vbox_guest_session.wait_for_array([virtualbox.library.GuestSessionWaitForFlag.start], 6000)
        # if reason != virtualbox.library.GuestSessionWaitResult.start:
        #     msg = "GuestSession failed to start ({})".format(reason)
        #     self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
        #     return False

        # Save user ID and password
        self.user_name = self.vbox_guest_session.user
        self.user_pass = password

        # Initialize variables relating to the current user session
        self.process_count = 0
        self.timed_out_process_count = 0

        msg = "Wait for 5 seconds"
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), msg))
        time.sleep(5)  # For loading latency time

        if validate_shared_drive is True:
            if self.validate_shared_directory() is True:
                return True
            if self.create_shared_directory() is False:
                # Try one more time
                if self.create_shared_directory() is False:
                    return False

        return True

    def restore_user_session(self):
        """Restore the most recent user session

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vbox_guest_session is not None:
            self.close_user_session()
            time.sleep(3)

        if self.create_user_session(self.user_name, self.user_pass, validate_shared_drive=True) is False:
            # Try one more time
            self.prglog_mgr.debug("{}(): Try one more time after 10 seconds".format(GET_MY_NAME()))
            time.sleep(10)
            if self.create_user_session(self.user_name, self.user_pass, validate_shared_drive=True) is False:
                return False
        return True

    def close_user_session(self):
        """Close the current session
           (= Disconnect from the guest session)
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), self.user_name))

        # Close and clean the current user session
        if self.vbox_guest_session is not None:
            try:
                self.vbox_guest_session.close()
            except:
                pass
            self.vbox_guest_session = None

        time.sleep(3)
        return

    @check_session
    def create_shared_directory(self, name="", host_path="", writable=True):
        """Create a shared directory in the Guest VM

            Permanent shared folders (used here)
                - vbox_session.machine.~

            Transient shared folders
                - vbox_session.console.~

        Args:
            name (str): The name of a shared directory
            host_path (str): The path of a directory in the host system
            writable (bool): True or False

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.shared_dir_vm_is_valid is True:
            msg = "Shared directory \"{}\" already exists".format(self.shared_name)
            self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), msg))
            return True

        if name == "":
            name = self.shared_name

        if host_path == "":
            host_path = self.shared_dir_host

        try:
            self.vbox_session.machine.create_shared_folder(name, host_path, writable, automount=True)
            self.vbox_session.machine.save_settings()
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False

        # Wait until the shared directory is activated
        time.sleep(2)
        found = False

        for idx in range(10):
            for sf in self.vbox_session.machine.shared_folders:
                if (sf.name.lower() == name.lower()) and (sf.host_path.lower() == host_path.lower()):
                    found = True
                    break
            if found is True:
                break
            time.sleep(2)

        return found

    @check_session
    def validate_shared_directory(self, check_count=15):
        """Validate the shared directory in the Guest VM

        Args:
            check_count (int): the fixed count for checking if the shared directory is exist or not

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        self.shared_dir_vm_is_valid = False

        # Check the shared directory
        found = False
        for idx in range(check_count):
            if self.directory_exists(self.shared_dir_vm) is True:
                found = True
                break
            if idx != check_count - 1:
                time.sleep(3)

        self.shared_dir_vm_is_valid = found
        return found

    @check_session
    def remove_shared_directory(self, name=""):
        """Remove a shared directory in the Guest VM

            Permanent shared folders (used here)
                - vbox_session.machine.~

            Transient shared folders
                - vbox_session.console.~

        Args:
            name (str): The name of a shared directory

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if name == "":
            name = self.shared_name

        try:
            self.vbox_session.machine.remove_shared_folder(name)
            self.vbox_session.machine.save_settings()
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False

        self.shared_dir_vm_is_valid = False
        time.sleep(5)  # important?
        return True

    def close(self):
        """Post-process

        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        # Disconnect from the guest session
        self.close_user_session()

        # # Remove the shared directory
        # self.remove_shared_directory(name=self.shared_name)

        # Stop debugging features
        self.stop_video_capturing()
        self.stop_packet_capturing()
        return

    def check_guest_additions(self):
        """Check whether GA is running or not

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.vbox_session.console.guest.additions_run_level == \
                virtualbox.library.AdditionsRunLevelType.none:
            return False
        return True

    def get_guest_additions_version(self):
        """Get GA's version

        Returns:
            version (str)
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        version = self.vbox_session.console.guest.additions_version
        # revision = self.vbox_session.console.guest.additions_revision
        return version

    def get_guest_additions_iso(self):
        """Get the path of the default Guest additions iso file

        Returns:
            path (str)
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        path = self.vbox.system_properties.default_additions_iso
        return path

    def update_guest_additions(self, path):
        """Update Guest Additions

            Do not expect that this function is working well

        Args:
            path (str): The full path of ISO file
                        (ISystemProperties -> default_additions_iso())

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        try:
            progress = self.vbox_session.console.guest.update_guest_additions(path, [], [])
            progress.wait_for_completion()
        except:
            msg = "Updating Guest Additions failed"
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        if progress.error_info.text != "":
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), progress.error_info.text))
            return False
        return True

    def wait_vm_for_booting(self, run_level=VmPopOSRunLevel.USERLAND):
        """Wait until the system is in a specific run level

        Args:
            run_level (VmPopOSRunLevel): The target OS run level

        Returns:
            True (booting is completed) or False (not yet)
        """
        if not isinstance(run_level, VmPopOSRunLevel):
            msg = "Invalid 'OS Run Level'"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        if self.vbox_session.console.guest.additions_run_level == virtualbox.library.AdditionsRunLevelType.none:
            self.prglog_mgr.info("{}(): Run level is 'None'".format(GET_MY_NAME()))

        t1 = time.clock()
        while self.vbox_session.console.guest.additions_run_level == virtualbox.library.AdditionsRunLevelType.none:
            time.sleep(3)
            if time.clock() - t1 > 300:  # Maximum waiting time is 5 minutes
                return False

        if self.vbox_session.console.guest.additions_run_level == virtualbox.library.AdditionsRunLevelType.system:
            if run_level == VmPopOSRunLevel.SYSTEM:
                self.prglog_mgr.info("{}(): Run level is 'System'".format(GET_MY_NAME()))
                time.sleep(2)
                return True

        t1 = time.clock()
        while self.vbox_session.console.guest.additions_run_level == virtualbox.library.AdditionsRunLevelType.system:
            time.sleep(3)
            if time.clock() - t1 > 1200:  # Maximum waiting time is 20 minutes
                return False

        if self.vbox_session.console.guest.additions_run_level == virtualbox.library.AdditionsRunLevelType.userland:
            if run_level == VmPopOSRunLevel.USERLAND:
                self.prglog_mgr.info("{}(): Run level is 'Userland'".format(GET_MY_NAME()))
                time.sleep(2)
                return True

        t1 = time.clock()
        while self.vbox_session.console.guest.additions_run_level == virtualbox.library.AdditionsRunLevelType.userland:
            time.sleep(3)
            if time.clock() - t1 > 600:  # Maximum waiting time is 10 minutes
                return False

        if self.vbox_session.console.guest.additions_run_level == virtualbox.library.AdditionsRunLevelType.desktop:
            if run_level == VmPopOSRunLevel.DESKTOP:
                self.prglog_mgr.info("{}(): Run level is 'Desktop'".format(GET_MY_NAME()))
                time.sleep(2)
                return True
            else:
                current_run_level = self.vbox_session.console.guest.additions_run_level
                self.prglog_mgr.info("{}(): Run level is '{}'".format(GET_MY_NAME(), current_run_level))
                time.sleep(2)
                return True

        return False

    def get_screen(self):
        """Get the VM screen information

        Returns:
            A dict having default information as follows:
                - screen_resolution
                - screen_shot
                ...
            For example:
            {
                'screen_resolution': (width, height),
                'screen_shot': png_stream
            }
        """
        self.prglog_mgr.info("{}(): Get the VM information".format(GET_MY_NAME()))

        # status, os type,
        info = dict()
        width, height, bits_per_pixel, x_origin, y_origin, guest_monitor_status = \
            self.vbox_session.console.display.get_screen_resolution(0)
        info['screen_resolution'] = (width, height)
        png = self.vbox_session.console.display.take_screen_shot_to_array(
            0, width, height, virtualbox.library.BitmapFormat(541544016)
        )
        info['screen_shot'] = png
        return info

    def set_resolution(self, width=1024, height=768):
        """Set the resolution of OS

        Args:
            width  (int): The default is 1024
            height (int): The default is 768

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): WIDTH({}), Height({})".format(GET_MY_NAME(), width, height))

        try:
            self.vbox_session.console.display.set_video_mode_hint(0, True, False, 0, 0, width, height, 32)
        except:
            msg = "Setting resolution failed"
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
            return False
        return True

    def send_event_keyboard(self, press_keys, hold_keys=None, press_delay_ms=85, delay_s=0.1, note=""):
        """Send keyboard events to the VM

        Args:
            press_keys (list): Basic input keys
            hold_keys (list): Holding keys during pressing 'press_keys'
            press_delay_ms (int): Number of milliseconds to delay between each press (default: 85)
            delay_s (float): Number of seconds after stroking keyboards (default: 0.1)
            note (str): The additional comment for the action log

        Returns:
            True or False

        .. note:: Refer to the special key map defined in pyvbox (SCANCODES dict)
        """
        pk = press_keys
        if isinstance(press_keys, list):
            pk = "{}".format(",".join(value for value in press_keys))
        pk = pk.replace('\n', ' ')

        hold_keys = [] if hold_keys is None else hold_keys
        hk = hold_keys
        if isinstance(hold_keys, list):
            hk = "{}".format(",".join(value for value in hold_keys))
        hk = hk.replace('\n', ' ')

        if note != "":
            self.prglog_mgr.info("{}(): PRESS({}) + HOLD({}) for \"{}\"".format(GET_MY_NAME(), pk, hk, note))
        else:
            self.prglog_mgr.info("{}(): PRESS({}) + HOLD({})".format(GET_MY_NAME(), pk, hk))

        if pk != '' and hk != '':
            desc = "PRESS({}) + HOLD({})".format(pk, hk)
        elif pk != '' and hk == '':
            desc = "PRESS({})".format(pk)
        elif pk == '' and hk != '':
            desc = "HOLD({})".format(hk)
        else:
            desc = ""

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_INPUT_DEVICE,
                       action=T_ACTION_KEYSTROKE,
                       method=T_ACTION_METHOD_K,
                       user=self.user_name,
                       desc=desc,
                       note=note)
        )

        try:
            self.vbox_session.console.keyboard.put_keys(press_keys, hold_keys, press_delay=press_delay_ms)
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs ({})".format(GET_MY_NAME(), e))
            return False

        time.sleep(delay_s)
        return True

    def send_event_mouse(self, x, y, mode=VmPopMouseMode.PRESS, click=VmPopMouseClick.LCLICK, note=""):
        """Send mouse events to the VM

        Args:
            x (int): Coordinate X (based on 'screen_resolution' from get_screen())
            y (int): Coordinate Y (based on 'screen_resolution' from get_screen())
            mode (VmPopMouseMode): Mouse mode (PRESS = 1, RELEASE = 2)
            click (VmPopMouseClick): Mouse click method (LCLICK = 1, RCLICK = 2)
            note (str): The additional comment for the action log

        Returns:
            True or False
        """
        self.prglog_mgr.info(
            "{}(): X({}), Y({}), MODE({}), CLICK({})".format(GET_MY_NAME(), x, y, mode.name, click.name)
        )

        if self.vbox_session.console.mouse.absolute_supported is False:
            self.prglog_mgr.info("{}(): Mouse absolute pointing is not supported.".format(GET_MY_NAME()))
            return False

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_INPUT_DEVICE,
                       action=T_ACTION_CLICK_MOUSE,
                       method=T_ACTION_METHOD_M,
                       user=self.user_name,
                       desc="X({}), Y({}), MODE({}), CLICK({})".format(x, y, mode.name, click.name),
                       note=note)
        )

        try:
            # Bit 0 (0x01) left mouse button
            # Bit 1 (0x02) right mouse button
            # Bit 2 (0x04) middle mouse button
            button_state = 0x01

            if mode == VmPopMouseMode.RELEASE:
                button_state = 0x00
            else:
                if click == VmPopMouseClick.LCLICK:
                    button_state = 0x01
                elif click == VmPopMouseClick.RCLICK:
                    button_state = 0x02

            self.vbox_session.console.mouse.put_mouse_event_absolute(x, y, 0, 0, button_state)
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False
        return True

    def click_mouse_left_button_at_center(self):
        """Click mouse left button at center point of the screen

        """
        s = self.get_screen()
        (x, y) = s.get('screen_resolution')
        self.send_event_mouse(
            int(x / 2), int(y / 2), mode=VmPopMouseMode.PRESS, click=VmPopMouseClick.LCLICK, note="Click the Center"
        )
        self.send_event_mouse(int(x / 2), int(y / 2), mode=VmPopMouseMode.RELEASE, click=VmPopMouseClick.LCLICK)
        return

    def click_mouse_left_button_at_title_bar(self):
        """Click mouse left button at title bar of the recently maximized window

        """
        s = self.get_screen()
        (x, y) = s.get('screen_resolution')
        self.send_event_mouse(
            int(x / 2), int(3), mode=VmPopMouseMode.PRESS, click=VmPopMouseClick.LCLICK, note="Click the title bar"
        )
        self.send_event_mouse(int(x / 2), int(3), mode=VmPopMouseMode.RELEASE, click=VmPopMouseClick.LCLICK)
        return

    def execute_process(self, command, arguments=[], environment=[], hidden=False, do_not_wait=False,
                        timeout_ms=60000, delay_s=0, handling_uac=False, actlog_off=True):
        """Execute a process in the Guest VM

            - This function is revised from an internal function of pyvbox
            - There can be up to 2048 objects (guest processes, files and directories) a time per guest session.
            - Limitation of active processes is 255?

        Args:
            command (str): Command to execute
            arguments (list): List of arguments for the command
            environment (list): List of environment settings (["VAR=VALUE", ...])
            hidden (bool): If True, hide the window
            do_not_wait (bool): if True, then do not wait after executing the process
            timeout_ms (int): ms to wait for the process to complete.
                              If 0, wait until it is terminated
            delay_s (float): Delay (second) after completing the execution (default: 0.1)
            handling_uac (bool): if True, handling the UAC window
            actlog_off (bool): if True, do not call action logging functions

        Returns:
            IProcess, stdout, stderr
        """
        def read_out(process, flags, stdout, stderr):
            """Read outputs from the current process
            """
            if virtualbox.library.ProcessCreateFlag.wait_for_std_err in flags:
                process.wait_for(int(virtualbox.library.ProcessWaitResult.std_err))
                data = process.read(2, 65000, 0)
                e = data.tobytes().decode('UTF-8') if sys.version_info > (3, 0) else str(data)
                if e is not "":
                    stderr.append(e)
            if virtualbox.library.ProcessCreateFlag.wait_for_std_out in flags:
                process.wait_for(int(virtualbox.library.ProcessWaitResult.std_out))
                data = process.read(1, 65000, 0)
                o = data.tobytes().decode('UTF-8') if sys.version_info > (3, 0) else str(data)
                if o is not "":
                    stdout.append(o)

        if self.vbox_guest_session is None:
            return None, "", ""

        if self.vbox_guest_session.status != virtualbox.library.GuestSessionStatus.started:
            return None, "", ""

        self.prglog_mgr.info("{}(): {} ({})".format(GET_MY_NAME(), command, arguments))

        # -----------------------------------------
        # Manage the process count (Very important)
        # -----------------------------------------
        # : It's because there is the limitation of active processes in VM
        #   (There is no special reason about the count -> They are just experimental results)
        """ In Windows 10, 7, Vista and XP, 'max_count' is configured as follows: """
        max_count = 356

        """ In Windows 8 and 8.1, 'max_count' is configured as follows: """
        if VmPopOSType.Windows8.code <= self.vmpop().automation.vm_os_type.code < VmPopOSType.Windows81.code:
            max_count = 250
        elif VmPopOSType.Windows81.code <= self.vmpop().automation.vm_os_type.code < VmPopOSType.Windows10.code:
            max_count = 128
        # -----------------------------------------

        if self.process_count > max_count:
            if self.vmpop().automation is not None:
                if self.vmpop().automation.evtmon.running() is False:
                    self.restore_user_session()
            else:
                self.restore_user_session()

        self.process_count += 1
        # ---------------------------------

        environment = environment
        flags = [virtualbox.library.ProcessCreateFlag.wait_for_std_err,
                 virtualbox.library.ProcessCreateFlag.wait_for_std_out,
                 virtualbox.library.ProcessCreateFlag.ignore_orphaned_processes]
        priority = virtualbox.library.ProcessPriority.default
        affinity = []

        if hidden is True:
            flags.append(virtualbox.library.ProcessCreateFlag.hidden)

        if actlog_off is False:
            self.actlog_mgr.add(
                ActionItem(method=T_ACTION_METHOD_HV,
                           user=self.user_name,
                           desc="Before calling process_create_ex()",
                           note="{}".format([command] + arguments))
            )

        process = \
            self.vbox_guest_session.process_create_ex(
                command,
                [command] + arguments,
                environment, flags, timeout_ms,
                priority, affinity
            )

        # process.wait_for(int(virtualbox.library.ProcessWaitResult.start), 0)

        # Wait until the process is started
        t1 = time.clock()
        while process.status != virtualbox.library.ProcessStatus.started and \
              process.status != virtualbox.library.ProcessStatus.terminated_normally:
            time.sleep(0.2)
            if time.clock() - t1 > 15:
                self.prglog_mgr.info(
                    "{}(): Starting a process failed (status: \'{}\')".format(GET_MY_NAME(), process.status)
                )
                if self.vmpop().automation is not None:
                    if self.vmpop().automation.evtmon.running() is False:
                        self.restore_user_session()
                else:
                    self.restore_user_session()
                return process, "", ""

        # Show the information message
        self.prglog_mgr.info("{}(): PID({}) is started ('process count' is {})".format(
            GET_MY_NAME(), process.pid, self.process_count)
        )

        # Handle the UAC window (Windows only)
        if handling_uac is True:
            time.sleep(delay_s)
            if self.vmpop().automation.vm_os_type.code < VmPopOSType.Windows7.code:
                self.send_event_keyboard(['TAB'], ['ALT'], delay_s=1.0, note="Focus on the window")
                self.click_mouse_left_button_at_center()
                self.send_event_keyboard(['c'], ['ALT'], delay_s=1.0, note="Click 'Continue'")
            else:
                self.click_mouse_left_button_at_center()
                self.send_event_keyboard(['y'], ['ALT'], delay_s=1.0, note="Click 'Yes'")

            while process.status == virtualbox.library.ProcessStatus.started:
                time.sleep(0.2)
            return process, "", ""

        # If do_not_wait is True, just return
        if do_not_wait is True:
            time.sleep(delay_s)
            return process, "", ""

        # Read the process output and wait for
        stdout = []
        stderr = []
        t1 = time.clock()
        condition = int(timeout_ms / 1000) + 30
        while process.status == virtualbox.library.ProcessStatus.started:
            read_out(process, flags, stdout, stderr)
            time.sleep(0.2)
            if timeout_ms > 0:
                if time.clock() - t1 > condition:
                    self.prglog_mgr.info(
                        "{}(): timed_out but it's still running, so break manually".format(GET_MY_NAME())
                    )
                    self.timed_out_process_count += 1
                    if self.vmpop().automation is not None:
                        if self.vmpop().automation.evtmon.running() is False:
                            self.restore_user_session()
                    else:
                        self.restore_user_session()
                    break
        read_out(process, flags, stdout, stderr)  # Make sure we have read the remainder of the out

        # If the process is timed out --> show the information message
        if process.status == virtualbox.library.ProcessStatus.timed_out_killed or\
           process.status == virtualbox.library.ProcessStatus.timed_out_abnormally:
            self.prglog_mgr.info(
                "{}(): PID({}) is [{}]".format(GET_MY_NAME(), process.pid, process.status)
            )

        time.sleep(delay_s)
        return process, "".join(stdout), "".join(stderr)

    @staticmethod
    def update_process_status(process):
        """Update the status of a process

        Args:
            process (IGuestProcess): The process type of VBox
        """
        process.read(2, 512, 0)

    def wait_process_for_termination(self, process):
        """Wait a process for its termination

        Args:
            process (IGuestProcess): The process type of VBox

        Returns:
            True or False
        """
        while (process.status == virtualbox.library.ProcessStatus.started) or \
              (process.status == virtualbox.library.ProcessStatus.terminating):
            time.sleep(1)
            self.update_process_status(process)

        if (process.status != virtualbox.library.ProcessStatus.terminated_normally) or \
           (process.status != virtualbox.library.ProcessStatus.terminated_signal) or \
           (process.status != virtualbox.library.ProcessStatus.terminated_abnormally) or \
           (process.status != virtualbox.library.ProcessStatus.timed_out_killed) or \
           (process.status != virtualbox.library.ProcessStatus.timed_out_abnormally):
            self.prglog_mgr.info("{}(): PID({}) is terminated ({})".format(GET_MY_NAME(), process.pid, process.status))
            return True
        self.prglog_mgr.debug("{}(): An exception occurred ({})".format(GET_MY_NAME(), process.status))
        return False

    def check_process_terminated_normally(self, process):
        """check if a process is terminated normally or not

        Args:
            process (IGuestProcess): The process type of VBox

        Returns:
            True or False
        """
        self.update_process_status(process)

        if process.status == virtualbox.library.ProcessStatus.terminated_normally:
            return True
        return False

    def check_process_started(self, process):
        """check if a process is started normally or not

        Args:
            process (IGuestProcess): The process type of VBox

        Returns:
            True or False
        """
        self.update_process_status(process)

        if process.status == virtualbox.library.ProcessStatus.started:
            return True
        return False

    def check_process_timedout(self, process):
        """check if a process is timedout or not

        Args:
            process (IGuestProcess): The process type of VBox

        Returns:
            True or False
        """
        self.update_process_status(process)

        if process.status == virtualbox.library.ProcessStatus.timed_out_killed or \
           process.status == virtualbox.library.ProcessStatus.timed_out_abnormally:
            return True
        return False

    def attach_usb_device(self, serial_number):
        """Attach a USB device

            vbox (IVirtualBox) -> host (IHost) -> usb_devices (list of IHostUSBDevice)
                ==> id_p (uuid), manufacturer (str), product (str), serial_number (str)...

        Args:
            serial_number (str): The serial number of the target USB device

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): SerialNo({})".format(GET_MY_NAME(), serial_number))

        found = False
        for device in self.vbox.host.usb_devices:
            if device.serial_number == serial_number:
                found = True
                break

        if found is False:
            msg = "Cannot found {}".format(serial_number)
            self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        try:
            self.vbox_session.console.attach_usb_device(device.id_p, "")
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False

        time.sleep(15)  # Wait until registering the device
        return True

    def detach_usb_device(self, serial_number):
        """Detach a USB device

        Args:
            serial_number (str): The serial number of the target USB device

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): SerialNo({})".format(GET_MY_NAME(), serial_number))

        found = False
        for device in self.vbox.host.usb_devices:
            if device.serial_number == serial_number:
                found = True
                break

        if found is False:
            msg = "Cannot found {}".format(serial_number)
            self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        try:
            self.vbox_session.console.detach_usb_device(device.id_p)
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False

        time.sleep(3)
        return True

    def file_exists(self, path):
        """Check whether a file exists in the current virtual machine

        Args:
            path (str): The file path

        Returns:
            True or False
        """
        try:
            ret = bool(self.vbox_guest_session.file_exists(path, True))
        except:
            self.prglog_mgr.info("{}(): Not found - {}".format(GET_MY_NAME(), path))
            return False

        self.prglog_mgr.info("{}(): Found - {}".format(GET_MY_NAME(), path))
        return ret

    def directory_exists(self, path):
        """Check whether a directory exists in the current virtual machine

        Args:
            path (str): The directory path

        Returns:
            True or False
        """
        try:
            ret = bool(self.vbox_guest_session.directory_exists(path, True))
        except:
            self.prglog_mgr.debug("{}(): Not found - {}".format(GET_MY_NAME(), path))
            return False

        self.prglog_mgr.info("{}(): Found - {}".format(GET_MY_NAME(), path))
        return ret

    def get_current_time(self):
        """Get the current time (not completed)

        Returns:
            utc_time (int)
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        try:
            utc_time = self.vbox.host.utc_time
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False

        return utc_time

    def set_bios_time(self, offset=0):
        """Set the BIOS time using the offset value (milliseconds) from the host system time

            - For example,
                1)  1 hour  = 3600000
                2) 24 hours = 86400000
                3) resync   = 0

        Args:
            offset (int): Time offset (milliseconds) from the host system time

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), offset))

        self.actlog_mgr.add(
            ActionItem(aclass=T_CLASS_COMMON,
                       action=T_ACTION_SET_BIOS_TIME,
                       method=T_ACTION_METHOD_HV,
                       user=self.user_name,
                       desc="Offset '{} seconds' from the host system time".format(offset / 1000),
                       note=""),
            do_not_get_time=True
        )

        self.lock()
        try:
            self.vbox_session.machine.bios_settings.time_offset = offset
            self.vbox_session.machine.save_settings()
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            self.unlock()
            return False
        self.unlock()
        return True

    def run_vbox_manage(self, arguments):
        """Run VboxManage for managing VirtualBox hypervisor

        Args:
            arguments (list)

        Returns:
            True or False
        """
        if not isinstance(arguments, list):
            self.prglog_mgr.debug("{}(): Invalid arguments (not valid list)".format(GET_MY_NAME()))
            return False

        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), arguments))

        if self.vbox_manage == "":
            import platform
            import shutil
            system = platform.system()
            if system == 'Windows':
                search = [
                    'C:\\Program Files\\Oracle\\VirtualBox\\VboxManage.exe',
                    'C:\\Program Files (x86)\\Oracle\\VirtualBox\\VboxManage.exe',
                ]
                for path in search:
                    if os.path.exists(path) is True:
                        self.vbox_manage = path
                        break
            else:
                self.vbox_manage = shutil.which("VboxManage")

        if self.vbox_manage == "":
            msg = "Cannot find VboxManage"
            self.prglog_mgr.error("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        try:
            PtUtils.run_command([self.vbox_manage] + arguments)
        except Exception as e:
            self.prglog_mgr.debug("{}(): Exception occurs - {}".format(GET_MY_NAME(), e))
            return False
        time.sleep(2)
        return True

    '''
    #-----------------------------------------------------------------------------------
    # Functions for setting VirtualBox preferences
    #-----------------------------------------------------------------------------------
    '''
    def enable_usb_controller(self, version):
        """Enable usb controller

            vmpop -> vbox_session (ISession) -> machine (IMachine) -> usb_controllers (list of IUSBController)

        Args:
            version (int): 1, 2, or 3

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if not isinstance(version, int):
            self.prglog_mgr.debug("{}(): Invalid version {}".format(GET_MY_NAME(), version))

        if not (1 <= version <= 3):
            self.prglog_mgr.debug("{}(): Invalid version {}".format(GET_MY_NAME(), version))

        try:
            if version == 1:
                self.vbox_session.machine.add_usb_controller("OHCI", virtualbox.library.USBControllerType.ohci)
            elif version == 2:
                self.vbox_session.machine.add_usb_controller("EHCI", virtualbox.library.USBControllerType.ehci)
            elif version == 3:
                self.vbox_session.machine.add_usb_controller("XHCI", virtualbox.library.USBControllerType.xhci)
            self.vbox_session.machine.save_settings()
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False
        return True

    # def add_virtual_disk(self):
    #     """Add a virtual disk (not completed)
    #
    #     Returns:
    #         True or False
    #     """
    #     self.prglog_mgr.info("{}()".format(GET_MY_NAME()))
    #     return True

    # def create_nat_network(self, name, cidr):
    #     return

    # def set_nat_network(self, nat_name):
    #     return

    '''
    #-----------------------------------------------------------------------------------
    # Functions for debugging VirtualBox hypervisor
    #-----------------------------------------------------------------------------------
    '''
    @check_session
    def get_disk_list(self):
        """Get the disk (including hard disk and usb) list

            vbox_session -> machine -> medium_attachments (list of IMediumAttachment)
                controller
                type_p
                device
                port
                medium (IMedium)
                    format_p
                    id_p
                    location
                    logical_size

        Returns:
            list of dictionaries on disk list
                {
                    'controller': str,
                    'type': str,
                    'format': str,
                    'controller_port': int,
                    'device_slot': int,
                    'id': str,
                    'location': str,
                    'size': int
                 }

                 for sf in self.vbox_session.machine.shared_folders:
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        disk_list = []
        self.lock()
        ma = self.vbox_session.machine.medium_attachments

        for m in ma:
            if m.medium is None:
                continue
            if m.type_p != virtualbox.library.DeviceType.hard_disk and \
               m.type_p != virtualbox.library.DeviceType.usb:
                continue
            disk_list.append(
                {
                    'controller': m.controller,
                    'type': m.type_p,
                    'format': m.medium.format_p,
                    'controller_port': m.port,
                    'device_slot': m.device,
                    'id': m.medium.id_p,
                    'location': m.medium.location,
                    'size': m.medium.logical_size
                }
            )

        self.unlock()
        return disk_list

    def export_disk(self, input_uuid, output_path, image_format):
        """Export the input disk to an image file using VBoxManage

        Args:
            input_uuid (str): The unique ID of a disk
            output_path (str): The output path
            image_format (VmPopImageFormat): RAW, VDI, VMDK, VHD

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if not isinstance(image_format, VmPopImageFormat):
            msg = "Invalid 'image_format'"
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        self.lock()

        if os.path.exists(output_path):
            PtUtils.delete_file(output_path)

        arguments = ['clonemedium', '--format', image_format.name, input_uuid, output_path]
        ret = self.run_vbox_manage(arguments)
        if ret is False:
            self.unlock()
            return False

        # Get IMedium object of the created disk
        m = None
        for disk in reversed(self.vbox.hard_disks):
            if os.path.abspath(disk.location) == output_path:
                m = disk
                break

        # Close the created disk from VBox (= removing it from the registered disks)
        if m is not None:
            m.close()

        self.unlock()
        return True

    @check_session
    def dump_physical_memory(self, file_path):
        """Take the current screenshot to an image file

        Args:
            file_path (str): The full path for storing the screenshot

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), file_path))

        file_path = os.path.abspath(file_path)

        try:
            self.vbox_session.console.debugger.dump_guest_core(file_path, "")
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False
        return True

    @check_session
    def query_os_kernel_log(self):
        """Get the kernel log of the guest OS

            - *nix OS only

        Returns:
            dmesg (str): the kernel log
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        try:
            dmesg = self.vbox_session.console.debugger.query_os_kernel_log(0)
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return ""
        return dmesg

    @check_session
    def take_screenshot(self, file_path):
        """Take the current screenshot to an image file

        Args:
            file_path (str): The full path for storing the screenshot

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), file_path))

        try:
            width, height, bits_per_pixel, x_origin, y_origin, guest_monitor_status = \
                self.vbox_session.console.display.get_screen_resolution(0)
            image = self.vbox_session.console.display.take_screen_shot_to_array(
                0, width, height, virtualbox.library.BitmapFormat.png
            )
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False

        if len(image) > 0:
            PtUtils.save_bytes_to_file(file_path, image)
            return True
        return False

    @check_session
    def start_video_capturing(self, filename):
        """Start the video capturing
            - Format: WebM (https://www.webmproject.org)

        Args:
            filename (str): The filename for storing the video capture

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), filename))

        file_path = "{}\\{}".format(self.actlog_mgr.get_log_dir(), filename)
        file_path = os.path.abspath(file_path)

        if self.vbox_session.machine.video_capture_enabled == 1:
            self.stop_video_capturing()

        try:
            self.vbox_session.machine.video_capture_file = file_path
            self.vbox_session.machine.video_capture_fps = 30  # default 25 fps
            # self.vbox_session.machine.video_capture_rate = 512    # default 512 kbps
            # self.vbox_session.machine.video_capture_width = 1024  # default 1024
            # self.vbox_session.machine.video_capture_height = 768  # default 768
            self.vbox_session.machine.video_capture_enabled = True
            self.vbox_session.machine.save_settings()
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False
        return True

    @check_session
    def stop_video_capturing(self):
        """Stop the video capturing

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        try:
            self.vbox_session.machine.video_capture_enabled = False
            self.vbox_session.machine.save_settings()
        except Exception as e:
            return False
        return True

    @check_session
    def start_packet_capturing(self, file_path, adapter=0):
        """Start the packet capturing
            - Format: PCAP

        Args:
            file_path (str): The full path for storing the packet capture
            adapter (int): The number of the network adapter

        Returns:
            True
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), file_path))

        file_path = os.path.abspath(file_path)

        try:
            network = self.vbox_session.machine.get_network_adapter(adapter)
            network.trace_file = file_path
            network.trace_enabled = True
            self.vbox_session.machine.save_settings()
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False
        return True

    @check_session
    def stop_packet_capturing(self, adapter=0):
        """Stop the packet capturing

        Args:
            adapter (int): The number of the network adapter

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        try:
            network = self.vbox_session.machine.get_network_adapter(adapter)
            network.trace_enabled = False
            self.vbox_session.machine.save_settings()
        except Exception as e:
            return False
        return True

    '''
    #-----------------------------------------------------------------------------------
    # Experimental functions
    #-----------------------------------------------------------------------------------
    '''
    def create_directory(self, dir_path):
        """Creates a directory in the guest

        Args:
            dir_path (str): The full path of a directory

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), dir_path))

        try:
            self.vbox_guest_session.directory_create(
                dir_path, 0, [virtualbox.library.DirectoryCreateFlag.none]
            )
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False
        return True

    def file_copy_to_vm(self, src, dst):
        """This function is not working properly
        """
        src = os.path.abspath(src)

        try:
            progress = self.vbox_guest_session.file_copy_to_guest(
                src, dst, [virtualbox.library.FileCopyFlag.none]
            )
            progress.wait_for_completion()
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False
        return True

    def file_copy_from_vm(self, src, dst):
        """This function is not working properly
        """
        try:
            progress = self.vbox_guest_session.file_copy_from_guest(
                src, dst, [virtualbox.library.FileCopyFlag.none]
            )
            progress.wait_for_completion()
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False
        return True

    def directory_copy_to_vm(self, src, dst):
        """GuestSession::directoryCopyToGuest is not implemented yet
        """
        try:
            progress = self.vbox_guest_session.directory_copy_to_guest(
                src, dst, [virtualbox.library.DirectoryCopyFlags.none]
            )
            progress.wait_for_completion()
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False
        return True

    def directory_copy_from_vm(self, src, dst):
        """GuestSession::directoryCopyFromGuest is not implemented yet
        """
        try:
            progress = self.vbox_guest_session.directory_copy_from_guest(
                src, dst, [virtualbox.library.DirectoryCopyFlags.none]
            )
            progress.wait_for_completion()
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False
        return True

    def mount_iso_image(self, file_path, controller_port=1, device_slot=0):
        """Mount an iso image

        Args:
            file_path (str): The full path of an iso image
            controller_port (int)
            device_slot (int)

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), file_path))

        file_path = os.path.abspath(file_path)

        try:
            medium = self.vbox.open_medium(file_path,
                                           virtualbox.library.DeviceType.dvd,
                                           virtualbox.library.AccessMode.read_only,
                                           False)
            self.vbox_session.machine.mount_medium("IDE", controller_port, device_slot, medium, True)
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return None
        return medium

    def unmount_medium(self, controller_port=1, device_slot=0):
        """Unmount a medium

        Args:
            controller_port (int)
            device_slot (int)

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        try:
            self.vbox_session.machine.mount_medium("IDE", controller_port, device_slot,
                                                   virtualbox.library.IMedium(), True)
        except Exception as e:
            self.prglog_mgr.error("{}(): Exception occurs - ({})".format(GET_MY_NAME(), e))
            return False
        return True
