# -*- coding: utf-8 -*-

"""VmPop

    * Description
        VMPOP (Virtual Machine POPulation System)
            - An automation system designed for populating operating systems or applications,
              and extracting forensically interesting data from populated systems.

    * Authors
        Jungheum Park <jungheum.park@nist.gov> & <junghmi@gmail.com>

    * Related Projects @ NIST
        - CFTT   (Computer Forensic Tool Testing)         www.cftt.nist.gov
        - CFReDS (Computer Forensic Reference Data Sets)  www.cfreds.nist.gov

    * License
        Apache License 2.0

    * Tested Python Environment
        Python 3.4.3, 3.4.4, 3.5.1

    * Requirements - Hypervisor
        VirtualBox (5.0 or higher)
            + Extension pack for high-speed USB connections
            + Guest Additions should be installed in VMs

    * Requirements - Python packages
        pyvbox (v1.0+ for supporting VirtualBox 5.x)
            -> pip install pyvbox
        pypiwin32 (Windows only)
            -> pip install pypiwin32
        decorator
            -> pip install decorator
        python-dateutil
            -> pip install python-dateutil
        dfVFS
            -> pip install dfvfs

    * History
        > 20170912
            - The first release
"""

import logging
import os
import time
from decorator import decorator

# VmPop internal modules
from pyvmpop.common_defines import *
from pyvmpop.utility.pt_utils import PtUtils
from pyvmpop.hypervisor.hv_vbox import HvVBox
from pyvmpop.automation.auto_windows import AutoWindows
from pyvmpop.extracting.extractor import Extractor
from pyvmpop.logging.actlog_manager import ActLogManager


# Set the global logging policy
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d    %(name)-47s %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


def init_progress_log():
    """Initialize the progress log file
    """
    root_logger = logging.getLogger()

    for h in root_logger.handlers:
        if isinstance(h, logging.FileHandler):
            root_logger.removeHandler(h)

    file_handler = logging.FileHandler("last_progress_log.txt", mode='w', encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    log_formatter = logging.Formatter(
        fmt='%(asctime)s.%(msecs)03d    %(name)-47s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)
    return


@decorator
def check_configuration(func, *args, **kwargs):
    """Decorator for checking the current configuration status
    """
    if args[0].hypervisor is None or args[0].automation is None:
        msg = "VmPop should be configured by calling basic_config()"
        args[0].prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
        return False
    return func(*args, **kwargs)


class VmPop:
    """VmPop class

        - Core class of VmPop framework

    Attributes:
        vm_name (str): The current VM's name registered to a hypervisor
        vm_os_type (VmPopOsType): The current VM's os type
        vm_state (VmPopState): The current VM's state (STOPPED = 1, RUNNING = 2, PAUSED = 3)

        shared_dir_host (str): Path of the shared directory in the host system
        shared_dir_host_temp (str): Path of 'temporary' directory for the current VM in the host system
        shared_dir_vm (str): Path of the shared directory in the virtual machine
        shared_dir_vm_temp (str): Path of the 'temporary' directory for the current VM in the virtual machine
        user_name (str): The current user account name

        hypervisor (Hv*): The module for handling a hypervisor
        automation (Auto*): The OS automation module
        extractor  (Extractor): The module for extracting forensically interesting data from VM images

        prglog_mgr (logging): The progress log manager using the standard Python logging module
        actlog_mgr (ActLogManager): The action log manager for user actions
    """

    def __init__(self):
        """The constructor
        """
        # member variables
        self.vm_name = ""
        self.vm_os_type = VmPopOSType.UNKNOWN
        self.vm_state = VmPopState.STOPPED

        self.shared_dir_host = ""
        self.shared_dir_host_temp = ""
        self.shared_dir_vm = ""
        self.shared_dir_vm_temp = ""
        self.user_name = ""

        self.hypervisor = None
        self.automation = None
        self.extractor = None

        # logging and event manager
        init_progress_log()
        self.prglog_mgr = logging.getLogger(__name__)
        self.actlog_mgr = None
        return

    '''
    #-----------------------------------------------------------------------------------
    # VmPop basic functions
    #-----------------------------------------------------------------------------------
    '''

    def basic_config(self, hv_type=VmPopHypervisor.VBOX, os_type=VmPopOSType.UNKNOWN,
                     start_mode=VmPopStartMode.CURRENT, shared_dir='.', log_dir='.'):
        """Set the basic configurations

        Args:
            hv_type (VmPopHypervisor): The type of hypervisor
            os_type (VmPopOSType): The type of OS
            start_mode (VmPopStartMode): Start mode (CURRENT or SNAPSHOT)
            shared_dir (str): The path of a directory for sharing between host and virtual environment
            log_dir (str): The path of a directory for storing logs

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): Set the basic configurations".format(GET_MY_NAME()))

        # Convert relative path to absolute path
        shared_dir = os.path.abspath(shared_dir)
        self.shared_dir_host = shared_dir

        # Set the temporary directory for the current VM (in the host)
        d, t = PtUtils.get_current_date_and_time()
        unique_id = PtUtils.hash_sha1(("{} {}".format(d, t)).encode("UTF-8"))
        self.shared_dir_host_temp = "{}\\temp_{}".format(self.shared_dir_host, unique_id)

        os.makedirs(self.shared_dir_host_temp, exist_ok=True)
        if os.path.isdir(self.shared_dir_host_temp) is False:
            self.prglog_mgr.debug(
                "{}(): Creating a temporary directory failed {}.".format(GET_MY_NAME(), self.shared_dir_host_temp)
            )
            return False

        self.prglog_mgr.info("{}(): The temporary directory is {}.".format(GET_MY_NAME(), self.shared_dir_host_temp))

        # Event manager for actions
        self.actlog_mgr = ActLogManager(self, log_dir)

        # Set a hypervisor
        if hv_type == VmPopHypervisor.VBOX:
            self.hypervisor = HvVBox(self, start_mode=start_mode)
            if self.hypervisor.vbox is None:
                return False
            self.shared_dir_vm = self.hypervisor.shared_dir_vm
        else:
            self.prglog_mgr.debug("{}(): unsupported hypervisor {}.".format(GET_MY_NAME(), hv_type))
            return False

        # Set the temporary directory for the current VM (in the VM)
        self.shared_dir_vm_temp = "{}\\temp_{}".format(self.shared_dir_vm, unique_id)
        self.hypervisor.shared_dir_vm_temp = "{}\\temp_{}".format(self.shared_dir_vm, unique_id)

        # Set a automation module
        if (os_type.code & VmPopOSType.Windows.code) == VmPopOSType.Windows.code:
            self.vm_os_type = os_type
            self.automation = AutoWindows(self)
        else:
            self.prglog_mgr.debug("{}(): unsupported OS {}.".format(GET_MY_NAME(), os_type))
            return False

        # Check the pre-requirements for the automation module
        if self.automation.pre_requirements() is False:
            return False

        # Set an extracting module
        self.extractor = Extractor(self.actlog_mgr)
        return True

    @check_configuration
    def connect_to_vm(self, vm_name, snapshot_name="", user_id="", password=""):
        """Connect to a VM

        Args:
            vm_name (str): The name of virtual machine
            snapshot_name (str): The name of snapshot registered in a virtual machine
            user_id (str): Account ID of a virtual machine
            password (str): Account password of a virtual machine

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): Connect to a VM \"{}\"".format(GET_MY_NAME(), vm_name))

        if self.hypervisor.connect_to_vm(vm_name, snapshot_name) is False:
            self.prglog_mgr.debug("{}(): Cannot connect to VM.".format(GET_MY_NAME()))
            return False

        # Check OS type
        if self.vm_os_type != self.hypervisor.vm_os_type:
            msg = "OS type mis-matches - {} & {}".format(
                self.vm_os_type.os_name,            # User input
                self.hypervisor.vm_os_type.os_name  # Detected name from the hypervisor
            )
            self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
            return False

        if user_id != "":
            if self.hypervisor.create_user_session(user_id, password, validate_shared_drive=False) is False:
                time.sleep(10)  # Try one more time
                if self.hypervisor.create_user_session(user_id, password, validate_shared_drive=False) is False:
                    return False

            if self.hypervisor.validate_shared_directory(check_count=1) is False:
                if self.hypervisor.create_shared_directory() is False:
                    return False

            self.user_name = user_id

        return True

    @check_configuration
    def connect_to_vm_debug(self, vm_name, snapshot_name=""):
        """Connect to a VM (DEBUG MODE for just connecting a specific virtual machine)

        Args:
            vm_name (str): The name of virtual machine
            snapshot_name (str): The name of snapshot registered in a virtual machine

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): Connect to a VM \"{}\"".format(GET_MY_NAME(), vm_name))

        if self.hypervisor.connect_to_vm(vm_name, snapshot_name, debug_mode=True) is False:
            self.prglog_mgr.debug("{}(): Cannot connect to VM.".format(GET_MY_NAME()))
            return False
        return True

    def close(self):
        """Terminate the current session

        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        if self.hypervisor is not None:
            self.hypervisor.close()

        if self.extractor is not None:
            self.extractor.close()

        self.actlog_mgr.close()

        # Delete the temporary directory
        if os.path.isdir(self.shared_dir_host_temp) is True:
            PtUtils.delete_dir(self.shared_dir_host_temp)

        # Class members
        self.vm_name = ""
        self.vm_os_type = VmPopOSType.UNKNOWN
        self.vm_state = VmPopState.STOPPED

        self.shared_dir_host = ""
        self.shared_dir_host_temp = ""
        self.shared_dir_vm = ""
        self.shared_dir_vm_temp = ""
        self.user_name = ""

        self.hypervisor = None
        self.automation = None
        self.extractor = None

        filename = "last_progress_log.txt"
        if os.path.exists(filename) is True:
            new_path = "{}\\{}".format(self.actlog_mgr.get_log_dir(), filename)
            PtUtils.copy_file(filename, new_path)

        return

    