# -*- coding: utf-8 -*-

"""AutoBase

    * Description
        A base class for all automation classes
"""

from pyvmpop.common_defines import *


class AutoBase:
    """AutoBase class

    Attributes:
        hypervisor (Hv*): The hypervisor class's instance

        vm_os_type (VmPopOSType): The current VM's OS type
        vm_os_version (string): The current VM's OS version

        shared_dir_host (str): Path of the shared directory in the host system
        shared_dir_host_temp (str): Path of 'temporary' directory for the current VM in the host system
        shared_dir_vm (str): Path of the shared directory in the virtual machine
        shared_dir_vm_temp (str): Path of the 'temporary' directory for the current VM in the virtual machine

        prglog_mgr (logging): The progress log manager using the standard Python logging module
        actlog_mgr (ActLogManager): The action log manager for user actions
        evtmon (EvtMon*): The instance of the event monitoring module
    """

    def __init__(self, vmpop):
        """The constructor

        Args:
            vmpop (weak reference of VmPop): The active VmPop instance
        """

        # Common variables
        self.hypervisor = vmpop.hypervisor
        self.vm_os_type = vmpop.vm_os_type
        self.vm_os_version = None

        self.shared_dir_host = vmpop.shared_dir_host
        self.shared_dir_host_temp = vmpop.shared_dir_host_temp
        self.shared_dir_vm = vmpop.shared_dir_vm
        self.shared_dir_vm_temp = vmpop.shared_dir_vm_temp

        # Logging and event manager
        self.prglog_mgr = None
        self.actlog_mgr = vmpop.actlog_mgr
        self.evtmon = None
        return

    def switch_for_event_monitor(self, condition):
        """Switch ON or OFF the internal monitoring module

        Args:
            condition (bool): If False, this internal monitoring module is not used
        """
        self.prglog_mgr.info("{}(): CONDITION({})".format(GET_MY_NAME(), condition))

        if self.evtmon is None:
            self.prglog_mgr.debug("{}(): Event monitor is not created".format(GET_MY_NAME()))

        self.evtmon.enable(condition)
        return
