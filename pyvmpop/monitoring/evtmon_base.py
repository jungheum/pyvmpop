# -*- coding: utf-8 -*-

"""EvtMonBase

    * Description
        A base class for all EvtMon classes
"""

import abc
import weakref


class EvtMonBase:
    """EvtMonBase class

    Base class for EvtMon classes

    Attributes:
        switch (bool): If False, this internal monitoring module is not used
        vmpop (weak reference of VmPop): The active VmPop instance
        hypervisor (Hv*): The hypervisor class's instance

        evtmon_type (VmPopEvtMonType): The type of event monitor
        agent_path (str): The full path of event monitor agent

        event_count (int): The total event count
        event_name (str): The current event name
        running_pid (int): If positive number, this means the monitoring agent's process ID
        time_range (list): The begin & end time of the most recent event (string format)
        time_range_int (list): The begin & end time of the most recent event (integer format) --> for internal usages
        event_not_processed (list): The list of event IDs (An event ID is added when the post-process raises FALSE)

        prglog_mgr (logging): The progress log manager
        actlog_mgr (ActLogManager): The action log manager for user actions
    """

    def __init__(self, vmpop, evtmon_type):
        """The constructor

        Args:
            vmpop (VmPop): The active VmPop instance
            evtmon_type (VmPopEvtMonType): The type of event monitor
        """
        self.switch = True
        self.vmpop = weakref.ref(vmpop)
        self.hypervisor = vmpop.hypervisor

        self.evtmon_type = evtmon_type
        self.agent_path = ""

        self.event_count = 1
        self.event_name = ""
        self.running_pid = -1
        self.time_range = ["", ""]
        self.time_range_int = [0, 0]
        self.event_not_processed = []

        # Logging managers
        self.prglog_mgr = None
        self.actlog_mgr = vmpop.actlog_mgr
        return

    def enable(self, condition=True):
        """Switch ON or OFF this module

        Args:
            condition (bool): If False, this internal monitoring module is not used
        """
        self.switch = condition

    def running(self):
        """Is the monitor running?

        Return:
            True or False
        """
        if self.running_pid > 0:
            return True
        return False

    @abc.abstractmethod
    def pre_process(self):
        """Pre-processes for recording events

        Returns:
            True or False
        """
        return True

    @abc.abstractmethod
    def start(self):
        """Start the monitoring agent

        Returns:
            True or False
        """
        return True

    @abc.abstractmethod
    def stop(self):
        """Stop the running monitoring agent

        Returns:
            True or False
        """
        return True

    @abc.abstractmethod
    def post_process(self):
        """Post-processes

        Returns:
            True or False
        """
        return True

    @abc.abstractmethod
    def extra_process(self):
        """Extra-processes

        """
        return
