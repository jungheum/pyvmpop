# -*- coding: utf-8 -*-

"""DFDBWindows

    * Description
        DFDB (Digital Forensics Database) Classes for representing forensically interesting data in Windows
"""

from enum import Enum, IntEnum


class DFDBFileSystemNTFS(Enum):
    """DFDBFileSystemNTFS class

        The record format is (MFT Record, Path, Description)
    """
    MFT     = (0,  "/$MFT",      "Master file table")
    # MFTMirr = (1,  "/$MftMirr", "Master file table 2")
    LogFile = (2,  "/$LogFile", "Log file")
    # Volume  = (3,  "/$Volume",  "Volume")
    # AttrDef = (4,  "/$AttrDef", "Attribute definitions")
    # Root    = (5,  "/",         "Root")
    # Bitmap  = (6,  "/$Bitmap",  "Cluster bitmap")
    # Boot    = (7,  "/$Boot",    "Boot sector")
    # BadClus = (8,  "/$BadClus", "Bad cluster file")
    # Secure  = (9,  "/$Secure",  "Security file")
    # Upcase  = (10, "/$Upcase",  "Upcase table")
    # Extend  = (11, "/$Extend",  "NTFS extension file")
    # Quota   = (24, "/$Quota",   "Quota management file")
    # ObjId   = (25, "/$ObjId",   "Object Id file")
    # Reparse = (26, "/$Reparse", "Reparse point file")
    UsnJrnl = (-1, "/$Extend/$UsnJrnl", "NTFS journal log")

    def __init__(self, mft_record, path, desc):
        self._mft_record = mft_record
        self._path = path
        self._desc = desc

    @property
    def mft_record(self):
        return self._mft_record

    @property
    def path(self):
        return self._path

    @property
    def desc(self):
        return self._desc


class DFDBWindowsHives(Enum):
    """DFDBWindowsHives class

        The record format is (Path, Description)
    """
    BCD      = ("/boot/BCD*",
                "Boot Configuration Data")
    MAIN     = ("/Windows/System32/Config/*",
                "Windows Registry Hive Set")
    BACKUP   = ("/Windows/System32/Config/RegBack/*",
                "Windows Registry Hive Set - Backup")
    TXR      = ("/Windows/System32/Config/TxR/*",
                "Transactional Registry")
    NTUSER   = ("/Users/*/NTUSER.dat*",
                "Windows Registry for an account")
    USRCLASS = ("/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat*",
                "Windows Registry for an account")
    USRCLASS_= ("/Users/*/Local Settings/Application Data/Microsoft/Windows/UsrClass.dat*",
                "Windows Registry for an account (xp and lower)")
    RP       = ("/System Volume Information/_restore*/snapshot/*",
                "Windows Registry - Restore Point")
    SYSCACHE = ("/System Volume Information/Syscache.hve*",
                "Syscache.hve")
    AMCACHE  = ("/Windows/AppCompat/Programs/Amcache.hve*",
                "Amcache.hve")
    SCHEMA   = ("/Windows/System32/SMI/Store/Machine/SCHEMA.dat*",
                "SCHEMA.DAT")

    def __init__(self, path, desc):
        self._path = path
        self._desc = desc

    @property
    def path(self):
        return self._path

    @property
    def desc(self):
        return self._desc

