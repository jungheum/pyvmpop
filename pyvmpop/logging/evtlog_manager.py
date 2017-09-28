# -*- coding: utf-8 -*-

"""EvtLogManager

    * Description
        Logging manager for 'events' in the virtual machine
"""

import os
import logging
from pyvmpop.common_defines import *
from pyvmpop.utility.pt_utils import PtUtils
from threading import Thread


# class EvtLogManager(Thread):  # using Thread (future work)
class EvtLogManager:
    """EvtLogManager class

    Attributes:
        shared_dir_host_temp (str): Path of 'temporary' directory for the current VM in the host system
        log_dir (str): The base directory path for creating a event log file
        evtmon_type (VmPopEvtMonType): What kind of event monitor was used to create the target log file?

        target_path (str): The full path of the target log file
        output_path (str): The final event log file path after converting and filtering processes

        action_seq (int): The unique ID of an action relating to this event
        event_seq  (int): The unique ID of the current event (= sequence number)
        event_name (str): The name of the current event
        time_range (list): The begin & end time of the most recent event
    """

    def __init__(self, shared_dir_host_temp, log_dir, evtmon_type=VmPopEvtMonType.ANY):
        """The constructor

        Args:
            shared_dir_host_temp (str): Path of 'temporary' directory for the current VM in the host system
            log_dir (str): The base directory path for creating a event log file
            evtmon_type (VmPopEvtMonType): What kind of event monitor was used to create the target log file?
        """
        # Thread.__init__(self)  # using Thread

        self.shared_dir_host_temp = shared_dir_host_temp
        self.log_dir = log_dir
        self.evtmon_type = evtmon_type

        self.target_path = ""
        self.output_path = ""

        self.action_seq = -1
        self.event_seq = -1
        self.event_name = ""
        self.time_range = [None, None]

        # Set the progress log manager
        self.prglog_mgr = logging.getLogger(__name__)
        return

    def basic_config(self, action_seq=-1, event_seq=-1, event_name="", time_range=(-1, -1)):
        """Basic configuration

        Args:
            action_seq (int): The unique ID of an action relating to this event
            event_seq  (int): The unique ID of the current event (= sequence number)
            event_name (str): The name of the current event
            time_range (list): The begin & end time of the most recent event

        Returns:
            True or False
        """
        # Set the default variables
        self.action_seq = action_seq
        self.event_seq  = event_seq
        self.event_name = event_name
        self.time_range = time_range
        return True

    def run(self):
        """Start function

        Returns:
            True or False
        """
        # Set the target path
        if self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_32 or self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_64:
            self.target_path = self.shared_dir_host_temp + "\\temp_{}.csv".format(self.event_seq)
        else:
            return False

        # Set the output file path including the new name
        self.output_path = "{}//{}".format(os.path.abspath(self.log_dir), self.generate_file_name())

        # Convert the log file format with a filter (if necessary) and Save it
        if self.save_as_csv() is False:
            self.prglog_mgr.debug("{}(): Converting to CSV failed".format(GET_MY_NAME()))
            return False

        # Normalize event records with the pre-defined schema (if necessary)
        # self.normalize()
        return True

    def save_as_csv(self, delete_original_file=True):
        """Convert the log file format with a filter (if necessary) and Save it

        Args:
            delete_original_file (bool): If True, delete the original file

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): Save as CSV to ({}) ".format(GET_MY_NAME(), self.output_path))

        if os.path.exists(self.target_path) is False:
            self.prglog_mgr.debug("{}(): The target file does not exist ({})".format(GET_MY_NAME(), self.target_path))
            return False

        if self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_32 or self.evtmon_type == VmPopEvtMonType.WIN_PROCMON_64:
            # If the format is already CSV, then just copy it
            PtUtils.copy_file(self.target_path, self.output_path)
        else:
            return False

        if delete_original_file is True:
            PtUtils.delete_file(self.target_path)

        if os.path.exists(self.output_path) is True:
            return True
        return False

    def normalize(self):
        """Normalize event records with the pre-defined schema (if necessary)

            - A possible implementation: Save events into a normalized database
        """
        return

    def generate_file_name(self, extension='csv'):
        """Generate a file name

        Args:
            extension (str): The extension of the file

        Returns:
            A name created with the time and event info (str)
        """
        name = "(E_{:04})_(A_{:04})_({}_{})~({}_{})_Events.{}".format(
            self.event_seq,
            self.action_seq,
            self.time_range[0][0], self.time_range[0][1].replace(':', '.'),
            self.time_range[1][0], self.time_range[1][1].replace(':', '.'),
            extension
        )
        return name
