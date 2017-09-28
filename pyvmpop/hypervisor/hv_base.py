# -*- coding: utf-8 -*-

"""HvBase

    * Description
        A base class for all hypervisor classes
"""

import weakref
from pyvmpop.common_defines import *
from pyvmpop.logging.actlog_manager import ActLogManager


class HvBase:
    """HvBase class

    Attributes:
        vmpop (weak reference of VmPop): The active VmPop instance
        hypervisor_type (VmPopHypervisor): The type of hypervisor

        vm_name (str): The current VM's name registered to hypervisor
        vm_os_type (VmPopOSType): The current VM's OS type
        vm_state (VmPopState): The current VM's state (STOPPED = 1, RUNNING = 2, PAUSED = 3)
        vm_start_mode (VmPopStartMode): Start mode (CURRENT = 1, SNAPSHOT = 2)
        user_name (str): The current user account name
        user_pass (str): The current user account's password

        shared_dir_host (str): Path of the shared directory in the host system
        shared_dir_host_temp (str): Path of 'temporary' directory for the current VM in the host system
        shared_name (str): Default name of the shared directory
        shared_dir_vm (str): Path of the shared directory in the virtual machine
        shared_dir_vm_is_valid (bool): If False, the shared directory is invalid in VM (not found)
        shared_dir_vm_temp (str): Path of the 'temporary' directory for the current VM in the virtual machine

        prglog_mgr (logging): The progress log manager using the standard Python logging module
        actlog_mgr (ActLogManager): The action log manager for user actions
    """

    def __init__(self, vmpop, start_mode=VmPopStartMode.SNAPSHOT):
        """The constructor

        Args:
            vmpop (VmPop): The active VmPop instance
            start_mode (VmPopStartMode): Start mode (CURRENT or SNAPSHOT or CLONE_LINKED or CLONE_FULL)
        """
        self.vmpop = weakref.ref(vmpop)
        self.hypervisor_type = None

        self.vm_name = ""  # one of names registered to virtualbox
        self.vm_os_type = VmPopOSType.UNKNOWN
        self.vm_state = VmPopState.STOPPED
        self.vm_start_mode = start_mode
        self.user_name = ""
        self.user_pass = ""

        self.shared_dir_host = vmpop.shared_dir_host
        self.shared_dir_host_temp = vmpop.shared_dir_host_temp
        self.shared_name = ""
        self.shared_dir_vm = ""
        self.shared_dir_vm_is_valid = False
        self.shared_dir_vm_temp = ""

        # Execution tracers (log manager and event manager)
        self.prglog_mgr = None
        self.actlog_mgr = vmpop.actlog_mgr
        return

    def get_type(self):
        """Get the type of this hypervisor

        Returns:
            VmPopHypervisor
        """
        return self.hypervisor_type
