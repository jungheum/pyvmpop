# -*- coding: utf-8 -*-

"""Extractor

    * Description
        A module for extracting forensically interesting data from image files
"""

import os
import logging
import hashlib
import zipfile

from pyvmpop.common_defines import *
from pyvmpop.utility.pt_utils import PtUtils

# Importing DFDB (Digital Forensics Database)
from . import dfdb_windows

# dfVFS
from dfvfs.analyzer import analyzer
from dfvfs.lib import definitions
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver import resolver, context
from dfvfs.volume import tsk_volume_system, vshadow_volume_system
from dfvfs.helpers import file_system_searcher

# AFF4 (not yet)
# from pyaff4 import data_store
# from pyaff4 import lexicon
# from pyaff4 import plugins
# from pyaff4 import rdfvalue
# from pyaff4 import zip


class Extractor:
    """Extractor class

        - This module uses Digital Forensics Virtual File System (dfVFS)
          (https://github.com/log2timeline/dfvfs)

    Attributes:
        base_dst_path (str): The base directory for extracting data
        file_system_path_spec_list (list): A list of file system path specification (see get_file_system_list())

        prglog_mgr (logging): The progress log manager
        actlog_mgr (ActLogManager): The action log manager for user actions
    """

    # Class constant that defines the default read buffer size.
    READ_BUFFER_SIZE = 32768 * 2  # 64 KB

    # For context see: http://en.wikipedia.org/wiki/Byte
    UNITS_1000 = [u'B', u'kB', u'MB', u'GB', u'TB', u'EB', u'ZB', u'YB']
    UNITS_1024 = [u'B', u'KiB', u'MiB', u'GiB', u'TiB', u'EiB', u'ZiB', u'YiB']

    _LOG_HEADERS = (
        'seq,path,size,sha-256\n'
    )

    def __init__(self, actlog_mgr=None):
        """The constructor

        Args:
            actlog_mgr (ActLogManager): The action log manager for user actions
        """
        self.base_dst_path = ""

        # Variables for dfVFS
        self.file_system_path_spec_list = list()
        # self.resolver_context = context.Context()

        # Set the progress log manager
        self.prglog_mgr = logging.getLogger(__name__)
        self.actlog_mgr = actlog_mgr
        self.base_dst_path = self.actlog_mgr.get_log_dir()
        return

    def open_image(self, path):
        """Open image file(s)

        Args:
            path (str): The full path of the target image file

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), path))

        # Check if the target image has a supported storage media image type
        base_path_spec = self.get_base_path_spec(path)
        if base_path_spec is None:
            return False

        self.file_system_path_spec_list = self.get_file_system_list(base_path_spec)

        if len(self.file_system_path_spec_list) == 0:
            self.prglog_mgr.info("{}(): No supported partitions found".format(GET_MY_NAME()))
            return False

        return True

    def close(self):
        """Close opened instances

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))
        return True

    def get_base_path_spec(self, path):
        """Get the base path specification

        Args:
            path (str): The full path of the target image file

        Returns:
            The base path specification (dfVFS.PathSpec)
        """
        if not os.path.exists(path):
            self.prglog_mgr.debug("{}(): No such source - {}".format(GET_MY_NAME(), path))
            return None

        # Set a path specification for the source
        path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_OS, location=path
        )

        # Determines if a file contains a supported storage media image types
        type_indicators = analyzer.Analyzer.GetStorageMediaImageTypeIndicators(
            path_spec
        )

        if not type_indicators:
            self.prglog_mgr.debug(
                "{}(): Unsupported source - {}".format(GET_MY_NAME(), path)
            )
            return None

        if len(type_indicators) > 1:
            self.prglog_mgr.debug(
                "{}(): Unsupported source (found more than one types) - {}".format(GET_MY_NAME(), path)
            )
            return None

        if len(type_indicators) == 1:
            self.prglog_mgr.info("{}(): Supported source - {}".format(GET_MY_NAME(), type_indicators[0]))
            # Set a child path specification based on the source's path spec and detected type
            path_spec = path_spec_factory.Factory.NewPathSpec(
                type_indicators[0], parent=path_spec
            )

        return path_spec

    def get_file_system_list(self, current_path_spec):
        """Determines the file system path specification (recursively)

        Args:
            current_path_spec (dfVFS.PathSpec): The current path specification

        Returns:
            The file system path specifications (list of instances of dfVFS.PathSpec)
        """
        self.prglog_mgr.info(
            "{}(): The current path spec's location is {}".format(GET_MY_NAME(), self.get_full_path(current_path_spec))
        )

        path_spec_list = list()

        type_indicators = analyzer.Analyzer.GetVolumeSystemTypeIndicators(
            current_path_spec
        )

        if not type_indicators:
            self.prglog_mgr.debug(
                "{}(): No supported volume system found at {}".format(GET_MY_NAME(),
                                                                      self.get_full_path(current_path_spec))
            )
            return path_spec_list

        if type_indicators[0] != definitions.TYPE_INDICATOR_TSK_PARTITION and \
           type_indicators[0] != definitions.TYPE_INDICATOR_VSHADOW:
            return path_spec_list

        type_indicator = type_indicators[0]

        path_spec = path_spec_factory.Factory.NewPathSpec(
            type_indicator, location=u'/',
            parent=current_path_spec
        )

        if type_indicator == definitions.TYPE_INDICATOR_TSK_PARTITION:
            volume_system = tsk_volume_system.TSKVolumeSystem()
        elif type_indicator == definitions.TYPE_INDICATOR_VSHADOW:
            volume_system = vshadow_volume_system.VShadowVolumeSystem()

        volume_system.Open(path_spec)

        volume_identifiers = []
        for volume in volume_system.volumes:
            # Get a volume identifier
            volume_identifier = getattr(volume, 'identifier', None)
            if volume_identifier:
                msg = "A {} volume \"{}\" is detected".format(type_indicator, volume_identifier)
                self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), msg))
                volume_identifiers.append(volume_identifier)

                # Get attributes of the volume
                for attribute in volume.attributes:
                    key = getattr(attribute, 'identifier', None)
                    val = getattr(attribute, 'value', None)
                    msg = "The volume {}'s attribute \"{}\" is {}".format(volume_identifier, key, val)
                    self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), msg))

        if not volume_identifiers:
            if type_indicator == definitions.TYPE_INDICATOR_TSK_PARTITION:
                self.prglog_mgr.info("{}(): No supported partitions found".format(GET_MY_NAME()))
            elif type_indicator == definitions.TYPE_INDICATOR_VSHADOW:
                self.prglog_mgr.info("{}(): No Volume Shadow Copies found".format(GET_MY_NAME()))
            return path_spec_list

        for volume_identifier in sorted(volume_identifiers):
            location = u'/{0:s}'.format(volume_identifier)

            path_spec = path_spec_factory.Factory.NewPathSpec(
                type_indicator, location=location,
                parent=current_path_spec
            )

            if type_indicator == definitions.TYPE_INDICATOR_TSK_PARTITION:
                temp_list = self.get_file_system_list(path_spec)
                if len(temp_list) > 0:
                    path_spec_list.extend(temp_list)

            type_indicators = analyzer.Analyzer.GetFileSystemTypeIndicators(
                path_spec
            )

            if len(type_indicators) > 1 or type_indicators[0] != definitions.TYPE_INDICATOR_TSK:
                continue

            msg = "A {} file system is detected at {}".format(type_indicators[0], self.get_full_path(path_spec))
            self.prglog_mgr.info("{}(): {}".format(GET_MY_NAME(), msg))

            path_spec = path_spec_factory.Factory.NewPathSpec(
                definitions.TYPE_INDICATOR_TSK, location=u'/',
                parent=path_spec
            )

            path_spec_list.append(path_spec)

        return path_spec_list

    def get_full_path(self, path_spec, exclude_volume=False, volume_only=False, combine_volume_path=False):
        """Get the full path of a path specification

        Args:
            path_spec (dfVFS.PathSpec): The current path specification
            exclude_volume (bool): If True, exclude volume identifiers
            volume_only (bool): If True, include volume names only
            combine_volume_path (bool): If True, combine all volume names (e.g., /p1_vss1 from /p1/vss1)

        Returns:
            The full path (str)
        """
        stack = list()

        while 1:
            parent = getattr(path_spec, 'parent', None)
            if parent is None:
                break

            type_indicator = getattr(path_spec, 'type_indicator', None)
            if exclude_volume is True:
                if type_indicator is not None:
                    if type_indicator in definitions.VOLUME_SYSTEM_TYPE_INDICATORS:
                        break

            if volume_only is True:
                if type_indicator is not None:
                    if not (type_indicator in definitions.VOLUME_SYSTEM_TYPE_INDICATORS):
                        path_spec = parent
                        continue

            location = getattr(path_spec, 'location', None)
            if location is not None:
                if combine_volume_path is True:
                    if type_indicator is not None:
                        if type_indicator == definitions.TYPE_INDICATOR_VSHADOW:
                            location = location.replace("/", "_")
                stack.append(location)

            path_spec = parent

        # Get a full path using the stack
        path = ""
        while len(stack) > 0:
            path += stack.pop()

        if path == "":
            path = "/"

        return path

    def extract(self, data_class=[VmPopDataClass.FILE_SYSTEM_METADATA],
                e_options=VmPopExtractOption.FILE_WITH_DIR, path=""):
        """Extract data from the image

        Args:
            data_class (list of VmPopDataClass)
            e_options (set of VmPopExtractOption): Extraction options
            path (target path): This is valid only when data_class is "VmPopDataClass.FILE"

        Returns:
            True or False
        """
        self.prglog_mgr.info("{}()".format(GET_MY_NAME()))

        # e_options = (VmPopExtractOption.FILE_WITH_DIR | VmPopExtractOption.FILE_WITHOUT_DIR |
        #              VmPopExtractOption.ARCHIVE_ZIP)
        # e_options = (VmPopExtractOption.FILE_WITH_DIR | VmPopExtractOption.FILE_WITHOUT_DIR)

        for dc in data_class:
            if not isinstance(dc, VmPopDataClass):
                msg = "Invalid 'VmPopDataClass' - {}".format(dc)
                self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
                continue

            if dc == VmPopDataClass.FILE:
                self.extract_file(path)

            if dc == VmPopDataClass.FILE_SYSTEM_METADATA:
                # e_options = (VmPopExtractOption.FILE_WITHOUT_DIR | VmPopExtractOption.ARCHIVE_ZIP_WITH_DIR)
                self.extract_file_system_metadata(e_options=e_options)

            if dc == VmPopDataClass.WINDOWS_REGISTRY:
                self.extract_windows_registry(e_options=e_options)

        return True

    def extract_file(self, path_src, path_dst=""):
        """Extract a file in the target image (Experimental)

        Args:
            path_src (str): The src path
            path_dst (str): The dst path

        Returns:
            True or False
        """
        base_path_spec = self.volume_path_specs[0]

        file_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_TSK, location=path_src,
            parent=base_path_spec
        )

        # file_system = resolver.Resolver.OpenFileSystem(base_path_spec)
        # file_entry = file_system.GetFileEntryByPathSpec(base_path_spec)
        file_entry = resolver.Resolver.OpenFileEntry(file_path_spec)

        # for sub_file_entry in file_entry.sub_file_entries:
        #     print(sub_file_entry.name)

        file_stat = file_entry.GetStat()

        # print(u'Inode: {0:d}'.format(file_stat.ino))
        # print(u'Inode: {0:s}'.format(file_entry.name))

        file_object = file_entry.GetFileObject()

        path_dst = file_entry.name if path_dst == "" else path_dst
        out_file = open(path_dst, 'wb')

        data = file_object.read(self.READ_BUFFER_SIZE)
        while data:
            out_file.write(data)
            data = file_object.read(self.READ_BUFFER_SIZE)

        out_file.close()
        file_object.close()
        file_path_spec = ""
        return

    def extract_directory(self, path_src, path_dst=""):
        """Extract a directory
        """
        return

    def extract_sector(self, start, end):
        """Extract a range of sectors
        """
        return

    def extract_file_system_metadata(self, e_options=VmPopExtractOption.FILE_WITHOUT_DIR, directory_structure=True):
        """Extract file system metadata from all file systems in the target image

        Args:
            e_options (set of VmPopExtractOption): Extraction options
            directory_structure (bool): If False, ignore the directory structure
                                        That is, save all files into a directory

        Returns:
            True or False
        """
        if len(self.file_system_path_spec_list) == 0:
            self.prglog_mgr.debug("{}(): No supported partitions found".format(GET_MY_NAME()))
            return False

        # Set the destination directory
        base_dst_path = "{}/{}".format(self.base_dst_path, VmPopDataClass.FILE_SYSTEM_METADATA.name)
        if PtUtils.make_dir(base_dst_path) is False:
            self.prglog_mgr.debug("{}(): Making directories failed".format(GET_MY_NAME()))
            return False

        # Create a log file for storing hash values
        seq = 1
        log_path = "{}/file_info.log".format(base_dst_path)
        self.write_line(log_path, self._LOG_HEADERS)

        for file_system_path_spec in self.file_system_path_spec_list:
            # Open the file system
            file_system = resolver.Resolver.OpenFileSystem(file_system_path_spec)

            if file_system.IsNTFS():
                dfdb = dfdb_windows.DFDBFileSystemNTFS
            else:
                self.prglog_mgr.debug(
                    "{}(): Not supported file system {}".format(GET_MY_NAME(), file_system.GetFsType())
                )
                continue

            tmp_path = self.get_full_path(file_system_path_spec.parent)
            tmp_path = tmp_path[1:] if tmp_path.startswith('/') else tmp_path
            dst_path = "{}/{}".format(base_dst_path, tmp_path.replace("/", "_"))

            for item in dfdb:
                path_spec = path_spec_factory.Factory.NewPathSpec(
                    definitions.TYPE_INDICATOR_TSK, location=item.path,
                    parent=file_system_path_spec.parent  # Volume (/p1, /vss1, /vss2...)
                )

                file_entry = file_system.GetFileEntryByPathSpec(path_spec)
                file_stat = file_entry.GetStat()  # type, size
                full_path = "{}/{}".format(self.get_full_path(path_spec), file_entry.name)

                if file_stat.type == definitions.FILE_ENTRY_TYPE_FILE:
                    self.prglog_mgr.info("{}(): [FILE] {}".format(GET_MY_NAME(), full_path))
                    file_info = self.save_file_entry(file_entry, dst_path, directory_structure)
                elif file_stat.type == definitions.FILE_ENTRY_TYPE_DIRECTORY:
                    self.prglog_mgr.info("{}(): [DIR] {}".format(GET_MY_NAME(), full_path))
                else:
                    self.prglog_mgr.info("{}(): TYPE({})".format(GET_MY_NAME(), file_stat.type))

                if file_info is None:
                    continue

                for entry in file_info:
                    path = entry.get("path")
                    if path.startswith(base_dst_path) is True:
                        path = path[len(base_dst_path):]

                    output = "{},{},{},{}\n".format(
                        seq, path, entry.get("size"), entry.get("hash_value")
                    )

                    self.write_line(log_path, output)
                    seq += 1

        return True

    def extract_windows_registry(self, e_options=VmPopExtractOption.FILE_WITHOUT_DIR):
        """Extract all hive files from all file systems in the target image

        Args:
            e_options (set of VmPopExtractOption): Extraction options

        Returns:
            True or False
        """
        if len(self.file_system_path_spec_list) == 0:
            self.prglog_mgr.debug("{}(): No supported partitions found".format(GET_MY_NAME()))
            return False

        # Set the destination directory
        base_dst_path = "{}/{}".format(self.base_dst_path, VmPopDataClass.WINDOWS_REGISTRY.name)
        if PtUtils.make_dir(base_dst_path) is False:
            self.prglog_mgr.debug("{}(): Making directories failed".format(GET_MY_NAME()))
            return False

        # Create a log file for storing hash values
        seq = 1
        log_path = "{}/file_info.log".format(base_dst_path)
        self.write_line(log_path, self._LOG_HEADERS)

        if self.check_option(e_options, VmPopExtractOption.ARCHIVE_ZIP) is True:
            base_dst_path = "{}/{}.zip".format(base_dst_path, VmPopDataClass.WINDOWS_REGISTRY.name)

        for file_system_path_spec in self.file_system_path_spec_list:
            # Open the file system
            file_system = resolver.Resolver.OpenFileSystem(file_system_path_spec)
            # [Alternative 1]
            # self.resolver_context.Empty()
            # file_system = resolver.Resolver.OpenFileSystem(file_system_path_spec,
            #                                                resolver_context=self.resolver_context)
            # [Alternative 2 in the case of TSKFileSystem]
            # file_system = tsk_file_system.TSKFileSystem(context.Context())
            # file_system.Open(file_system_path_spec)

            searcher = file_system_searcher.FileSystemSearcher(file_system, file_system_path_spec)

            dfdb = dfdb_windows.DFDBWindowsHives

            if self.check_option(e_options, VmPopExtractOption.ARCHIVE_ZIP) is True:
                dst_path = base_dst_path
            else:
                tmp_path = self.get_full_path(file_system_path_spec.parent, combine_volume_path=True)
                dst_path = "{}{}".format(base_dst_path, tmp_path)

            for item in dfdb:
                find_spec = file_system_searcher.FindSpec(
                    file_entry_types=[definitions.FILE_ENTRY_TYPE_FILE],
                    location_glob=item.path, case_sensitive=False
                )

                path_spec_generator = searcher.Find(find_specs=[find_spec])

                for path_spec in path_spec_generator:
                    file_entry = file_system.GetFileEntryByPathSpec(path_spec)
                    file_stat = file_entry.GetStat()  # type, size
                    full_path = self.get_full_path(path_spec, combine_volume_path=True)

                    if file_stat.type == definitions.FILE_ENTRY_TYPE_FILE:
                        self.prglog_mgr.info("{}(): [F] {}".format(GET_MY_NAME(), full_path))
                        file_info = self.save_file_entry(file_entry, dst_path, e_options)
                    elif file_stat.type == definitions.FILE_ENTRY_TYPE_DIRECTORY:
                        self.prglog_mgr.info("{}(): [D] {}".format(GET_MY_NAME(), full_path))
                        file_info = self.save_directory_entry(file_entry, dst_path, e_options)
                    else:
                        self.prglog_mgr.info("{}(): TYPE({})".format(GET_MY_NAME(), file_stat.type))

                    if file_info is None:
                        continue

                    for entry in file_info:
                        path = entry.get("path")
                        output = "{},{},{},{}\n".format(
                            seq,
                            path,
                            entry.get("size"),
                            entry.get("hash_value")
                        )

                        self.write_line(log_path, output)
                        seq += 1

            file_system.Close()

        return True

    def extract_unallocated_area(self):
        """Unallocated areas
        """
        return

    def extract_windows_web_browser(self):
        """web-browser artifacts
        """
        return

    def extract_windows_artifact(self):
        """registry, prefetch, shortcuts, event logs, jumplist, windows search, browser artifacts...
        """
        return

    def save_directory_entry(self, dir_entry, base_dst_path=".",
                             e_options=VmPopExtractOption.FILE_WITH_DIR, recursive=True):
        """Save all entries stored in a directory entry

        Args:
            dir_entry (dfVFS.FileEntry): The file entry
            base_dst_path (str): The base destination path
            e_options (set of VmPopExtractOption): Extraction options
            recursive (bool): If True, save files in all sub-directories

        Returns:
            list of file_info (dict) or None
                [{
                    path (str)
                    hash_algorithm (str)
                    hash_value (str)
                    stat (dict)
                }]
        """
        file_info = list()

        for sub_entry in dir_entry.sub_file_entries:
            # print("({}) {}".format(sub_entry.path_spec.inode, sub_entry.name))
            full_path = self.get_full_path(sub_entry.path_spec)
            file_stat = sub_entry.GetStat()

            if file_stat.type == definitions.FILE_ENTRY_TYPE_FILE:
                self.prglog_mgr.info("{}(): [F] {}".format(GET_MY_NAME(), full_path))
                sub_file_info = self.save_file_entry(sub_entry, base_dst_path, e_options)

            elif file_stat.type == definitions.FILE_ENTRY_TYPE_DIRECTORY:
                self.prglog_mgr.info("{}(): [D] {}".format(GET_MY_NAME(), full_path))
                sub_file_info = self.save_directory_entry(sub_entry, base_dst_path, e_options)

            else:
                self.prglog_mgr.info("{}(): TYPE({})".format(GET_MY_NAME(), file_stat.type))

            if sub_file_info is not None:
                file_info.extend(sub_file_info)

        return file_info

    def save_file_entry(self, file_entry, base_dst_path=".", e_options=VmPopExtractOption.FILE_WITH_DIR):
        """Save data stream(s) of a file entry

        Args:
            file_entry (dfVFS.FileEntry): The file entry
            base_dst_path (str): The base destination path
            e_options (set of VmPopExtractOption): Extraction options

        Returns:
            list of file_info (dict) or None
                [{
                    path (str)
                    hash_algorithm (str)
                    hash_value (str)
                    stat (dict)
                }]
        """
        if len(file_entry.data_streams) == 0:
            self.prglog_mgr.debug("{}(): No data streams found".format(GET_MY_NAME()))
            return None

        # Set the base path list
        base_paths = ["", ""]  # [0] for FILE_WITH_DIR, [1] for FILE_WITHOUT_DIR

        if self.check_option(e_options, VmPopExtractOption.ARCHIVE_ZIP) is False:
            temp_path = self.get_full_path(file_entry.path_spec, exclude_volume=True)
            temp_path = temp_path[1:] if temp_path.startswith('/') else temp_path

            if self.check_option(e_options, VmPopExtractOption.FILE_WITH_DIR) is True:
                base_paths[0] = "{}/{}".format(base_dst_path, temp_path)
            if self.check_option(e_options, VmPopExtractOption.FILE_WITHOUT_DIR) is True:
                base_paths[1] = "{}/{}".format(base_dst_path, temp_path.replace("/", "_"))
        else:
            volu_path = self.get_full_path(file_entry.path_spec, volume_only=True, combine_volume_path=True)
            temp_path = self.get_full_path(file_entry.path_spec, exclude_volume=True)
            temp_path = temp_path[1:] if temp_path.startswith('/') else temp_path

            if self.check_option(e_options, VmPopExtractOption.FILE_WITH_DIR) is True:
                base_paths[0] = "{}/{}".format(volu_path, temp_path)
            if self.check_option(e_options, VmPopExtractOption.FILE_WITHOUT_DIR) is True:
                base_paths[1] = "{}/{}".format(volu_path, temp_path.replace("/", "_"))

        if self.check_option(e_options, VmPopExtractOption.ARCHIVE_ZIP) is False:
            for base_path in base_paths:
                if base_path == "": continue
                PtUtils.make_dir(os.path.dirname(base_path))

        file_info = list()

        # Save data stream(s) to the destination path
        for data_stream in file_entry.data_streams:
            try:
                file_object = file_entry.GetFileObject(data_stream_name=data_stream.name)
            except IOError as exception:
                msg = "Unable to open path specification with error {}".format(exception)
                self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
                return file_info

            if not file_object:
                continue

            data_stream_size = file_object.get_size()
            if data_stream_size == 0:  # Skip if data stream is empty
                file_object.close()
                continue

            out_files = [None, None]  # [0] for FILE_WITH_DIR, [1] for FILE_WITHOUT_DIR

            if self.check_option(e_options, VmPopExtractOption.ARCHIVE_ZIP) is False:
                idx = 0
                for base_path in base_paths:
                    if base_path == "":
                        continue

                    if data_stream.name == "":
                        dst_path = base_path
                    else:
                        dst_path = "{}-{}".format(base_path, data_stream.name)

                    try:
                        out_files[idx] = open(dst_path, 'wb')
                        idx += 1
                    except IOError as exception:
                        file_object.close()
                        file_object = None
                        break
            else:
                try:
                    # zipfile
                    out_files[0] = zipfile.ZipFile(base_dst_path, mode='a', compression=zipfile.ZIP_DEFLATED)
                except Exception as exception:
                    file_object.close()
                    file_object = None
                # AFF4
                # with data_store.MemoryDataStore() as resolver:
                #     resolver.Set(base_dst_path, lexicon.AFF4_STREAM_WRITE_MODE,
                #                  rdfvalue.XSDString("truncate"))
                #     zip_file = zip.ZipFile.NewZipFile(resolver, base_dst_path)
                #     volume_urn = zip_file.urn

            if file_object is None:
                continue

            hash_context = hashlib.sha256()

            try:
                data = file_object.read(self.READ_BUFFER_SIZE)
                while data:
                    idx = 0
                    for base_path in base_paths:
                        if base_path == "":
                            continue

                        if self.check_option(e_options, VmPopExtractOption.ARCHIVE_ZIP) is False:
                            out_files[idx].write(data)
                            idx += 1
                        else:
                            if data_stream.name == "":
                                dst_path = base_path
                            else:
                                dst_path = "{}-{}".format(base_path, data_stream.name)
                            # Ex1) zipfile
                            out_files[0].writestr(dst_path, data)
                            # Ex2) AFF4
                            #  segment_urn = volume_urn.Append(dst_path)
                            # with zip_file.CreateMember(segment_urn) as segment:
                            #     segment.Seek(0, 2)
                            #     segment.Write(data)
                    hash_context.update(data)
                    data = file_object.read(self.READ_BUFFER_SIZE)
            except IOError as exception:
                msg = "Unable to read from path specification {}".format(exception)
                self.prglog_mgr.debug("{}(): {}".format(GET_MY_NAME(), msg))
                return file_info
            finally:
                file_object.close()
                if out_files[0] is not None:
                    out_files[0].close()
                if out_files[1] is not None:
                    out_files[1].close()

            if data_stream_size == 0:
                hash_value = 'N/A'
            else:
                hash_value = hash_context.hexdigest()

            file_info.append(
                {
                    # 'path': dst_path,
                    'path': self.get_full_path(file_entry.path_spec, combine_volume_path=True),
                    'size': self.get_human_readable_size(data_stream_size),
                    'hash_algorithm': "SHA-1",
                    'hash_value': hash_value,
                    'stat': file_entry.GetStat()
                }
            )

        return file_info

    def get_human_readable_size(self, size):
        """Retrieves a human readable string of the size

        Args:
          size: The size in bytes

        Returns:
          A human readable string of the size
        """
        magnitude_1000 = 0
        size_1000 = float(size)
        while size_1000 >= 1000:
            size_1000 /= 1000
            magnitude_1000 += 1

        magnitude_1024 = 0
        size_1024 = float(size)
        while size_1024 >= 1024:
            size_1024 /= 1024
            magnitude_1024 += 1

        size_string_1000 = None
        if 0 < magnitude_1000 <= 7:
            size_string_1000 = u'{0:.1f}{1:s}'.format(size_1000, self.UNITS_1000[magnitude_1000])

        size_string_1024 = None
        if 0 < magnitude_1024 <= 7:
            size_string_1024 = u'{0:.1f}{1:s}'.format(size_1024, self.UNITS_1024[magnitude_1024])

        if not size_string_1000 or not size_string_1024:
            return u'{0:d} B'.format(size)

        return u'{0:s} / {1:s} ({2:d} B)'.format(size_string_1024, size_string_1000, size)

    @staticmethod
    def write_line(path, line):
        """Write an entry to file

        Args:
            path (str): The file path
            line (str): An entry
        """
        f = open(path, "a", encoding="utf-8")
        f.write(line)
        f.close()
        return

    @staticmethod
    def check_option(group, item):
        """Check if an option is enabled or not

        Args:
            group: set of options
            item: An option for check
        Return:
            True  if 'item' is enabled  in 'group'
            False if 'item' is disabled in 'group'
        """
        if (group & item) == item:
            return True
        return False
