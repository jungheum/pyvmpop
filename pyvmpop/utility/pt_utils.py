# -*- coding: utf-8 -*-

"""PtUtils

    * Description
        Portable utility functions for Python environment
"""

import os
import glob
import shutil
import datetime
import dateutil.tz
import subprocess
import hashlib


class PtUtils:
    def __init__(self):
        return

    @staticmethod
    def get_current_date_and_time():
        """Get the current date & time

        Returns:
            The current date (str): YYYY-MM-DD
            The current time (str): hh:mm:ss
        """
        now = datetime.datetime.now()
        d = u"{:4}-{:02}-{:02}".format(now.year, now.month, now.day)
        t = u"{:02}:{:02}:{:02}".format(now.hour, now.minute, now.second)
        return d, t

    @staticmethod
    def get_timezone():
        """Get the timezone setting

        Returns:
            Timezone (str): (UTC OO) Timezone
        """
        local_tz = dateutil.tz.tzlocal()
        local_offset = local_tz.utcoffset(datetime.datetime.now(local_tz))
        offset = local_offset.total_seconds() / 3600
        offset = int(offset) if offset == int(offset) else offset
        name = local_tz.tzname(datetime.datetime.now(local_tz))

        timezone = u"(UTC{}) {}".format(offset, name)
        return timezone

    @staticmethod
    def save_bytes_to_file(path, data):
        """Save bytes to a file

        Args:
            path (str): The output path
            data (bytes): The data to be saved
        """
        try:
            f = open(path, "wb")
            f.write(data)
            f.close()
        except:
            pass

    @staticmethod
    def copy_file(src, dst):
        """Copy the src to the dest

        Args:
            src (str): The source path
            dst (str): The destination path
        """
        try:
            shutil.copy(src, dst)
        except:
            pass

    @staticmethod
    def delete_file(path):
        """Delete a file

        Args:
            path (str): The target path
        """
        try:
            path = os.path.abspath(path)
            path = path.replace('[', '[[]').replace(']', '[]]')
            files = glob.glob(path)
            for f in files:
                os.remove(f)
        except:
            pass

    @staticmethod
    def delete_dir(path):
        """Delete a directory

        Args:
            path (str): The target path
        """
        try:
            shutil.rmtree(path, ignore_errors=True)
        except:
            pass

    @staticmethod
    def make_dir(path):
        """Make directories

        Args:
            path (str): The target path

        Returns:
            True or False
        """
        try:
            path = os.path.abspath(path)
            os.makedirs(path, exist_ok=True)
            if os.path.isdir(path) is True:
                return True
        except:
            pass
        return False

    @staticmethod
    def run_command(cmd):
        """Run a command line

        Args:
            cmd (list): A command with arguments

        Returns:
            A return code ('None' value indicates that the process hasn’t terminated yet)
        """
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        while True:
            output = process.stdout.readline()
            if output == b'' and process.poll() is not None:
                break
            if output:
                print(output.strip())
        ret = process.poll()
        return ret

    @staticmethod
    def hash_sha1(data):
        """Calculate SHA-1 value
        """
        hash_context = hashlib.sha1()
        hash_context.update(data)
        return hash_context.hexdigest()
