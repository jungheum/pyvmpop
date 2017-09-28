# -*- coding: utf-8 -*-

"""ActlogManager

    * Description
        Logging manager for 'actions' by user
"""

import os
import time
import datetime
import weakref
from pyvmpop.utility.pt_utils import PtUtils


class ActionItem:
    """ActionItem class

        A simple class as a structure
    """
    def __init__(self, aclass="", action="", method="", user="", desc="", note=""):
        """The constructor

        Args:
            aclass (str)    class of the action
            action (str)    action name
            method (str)    action method
            user   (str)    username associated with this entry
            desc   (str)    action description
            note   (str)    additional information for each action
        """
        self.aclass = aclass
        self.action = action
        self.method = method
        self.user = user
        self.desc = desc
        self.note = note


class ActLogManager:
    """ActLogManager class

        Logging manager for 'actions'

    Attributes:
        vmpop (weak reference of VmPop): The active VmPop instance
        log_dir (str): The base directory path for creating a event log file
        file_path (str): The full path of the current action log file
        action_count (int): The total action count
    """

    """
    =======================
    VmPop action log format
    =======================
    seq:        Sequence number
    date:       YYYY-MM-DD
    time:       HH:mm:ss
    timezone:   ex) (UTC-05:00) Eastern Time (US & Canada)
    class:      class of the action
    action:     action name
    method:     action method
    user:       username associated with this entry
    desc:       action description
    note:       additional information for each action
    """
    _HEADERS = (
        'seq,date,time,timezone,class,action,method,user,desc,note\n'
    )

    def __init__(self, vmpop, log_dir='.'):
        """The constructor

        Args:
            vmpop (VmPop): The active VmPop instance
            log_dir (str): The base directory path for saving an action log file
        """
        self.vmpop = weakref.ref(vmpop)
        self.log_dir = log_dir

        os.makedirs(log_dir, exist_ok=True)
        if os.path.isdir(self.log_dir) is False:
            return

        self.file_path = "{}\\{}".format(log_dir, self.generate_file_name())
        self.write_line(self._HEADERS)

        self.action_count = 1  # The sequence number begins from 1
        return

    def get_action_seq(self):
        return self.action_count

    def get_log_dir(self):
        return self.log_dir

    def generate_file_name(self):
        """Generate a file name

        Returns:
            A name created with the current time (str)
        """
        filename = "Actions.csv"
        now = datetime.datetime.now()
        name = "({:4}-{:02}-{:02}_{:02}.{:02}.{:02})_{}".format(
            now.year, now.month, now.day, now.hour, now.minute, now.second, filename
        )
        return name

    def add(self, a=ActionItem(), do_not_get_time=False):
        """Add an action log

        Args:
            a (ActionItem)
            do_not_get_time (bool): If True, do not get date & time

        Returns:
            tuple of
                d (str): Date (local time)
                t (str): Time (local time)
                z (str): Timezone
        """
        # Get the current date & time
        d = ""
        t = ""
        z = ""

        if do_not_get_time is False:
            if self.vmpop().automation is not None:
                d, t, z = self.vmpop().automation.get_date_time(actlog_off=True)
                if d == "":  # call it more times
                    for idx in range(5):
                        time.sleep(2)
                        d, t, z = self.vmpop().automation.get_date_time(actlog_off=True)
                        if d != "":
                            break
                elif d is None:
                    d = ""

        entries = (
            str(self.action_count),
            d, t, z,
            a.aclass,
            a.action,
            a.method,
            a.user,
            a.desc,
            a.note
        )

        output = "{0:s}\n".format(",".join(value.replace(',', ' ') for value in entries))
        self.write_line(output)
        self.action_count += 1
        return d, t, z

    def write_line(self, line):
        """Write an event to file

        Args:
            line (str): An action
        """
        f = open(self.file_path, "a", encoding="utf-8")
        f.write(line)
        f.close()
        return

    def close(self):
        """Post-processes
        """
        if self.action_count == 1:
            PtUtils.delete_file(self.file_path)
