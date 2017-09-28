# -*- coding: utf-8 -*-

"""Common Defines for VmPop

"""

from enum import Enum, IntEnum
import inspect
GET_MY_NAME = lambda: inspect.stack()[1][3]


class VmPopHypervisor(IntEnum):
    """VmPopHypervisor class
    """
    VBOX = 1


class VmPopState(IntEnum):
    """VmPopState class
    """
    STOPPED = 1
    RUNNING = 2
    PAUSED = 3
    SAVED = 4


class VmPopFunctionMode(IntEnum):
    """VmPopFunctionMode class
    """
    HV = 1  # using Hypervisor's commands
    OS = 2  # Operating System's commands


class VmPopStartMode(IntEnum):
    """VmPopStartMode class
    """
    CURRENT = 1  # Start with the current running VM
    SNAPSHOT = 2  # Start with a specific snapshot
    CLONE_LINKED = 3  # Create a linked clone and Start it
    CLONE_FULL = 4  # Create a full clone and Start it


class VmPopStopMode(IntEnum):
    """VmPopStopMode class
    """
    SAVE_STATE = 1
    SHUT_DOWN = 2
    POWER_OFF = 3


class VmPopOSRunLevel(IntEnum):
    """VmPopOSRunLevel class
    """
    SYSTEM = 1
    USERLAND = 2
    DESKTOP = 3


class VmPopActionMethod(IntEnum):
    """VmPopActionMethod class
    """
    CMD = 0  # Default or extended command line utility
    PS = 1  # PowerShell script
    BAT = 2  # Batch script
    KBD = 3  # Keyboard strokes
    # guest-edition: 'process_create()' or 'execute()' in guestsession class
    WIN_PS = 1
    WIN_KM = 2  # (experimental) keyboard and mice inputs


class VmPopMouseMode(IntEnum):
    """VmPopMouseMode class
    """
    PRESS = 1
    RELEASE = 2


class VmPopMouseClick(IntEnum):
    """VmPopMouseClick class
    """
    LCLICK = 1
    RCLICK = 2


class VmPopActivateMode(IntEnum):
    """VmPopActivateMode class
    """
    PNAME = 0
    PID = 1
    TITLE = 2


class VmPopNICMode(IntEnum):
    """VmPopNICMode class
    """
    DHCP = 1
    STATIC = 2


class VmPopWebAction(IntEnum):
    """VmPopWebAction class
    """
    NEW_TAB = 0x01
    CLOSE_TAB = 0x02
    VISIT_URL = 0x04
    ADD_BOOKMARK = 0x08  # Bookmark (Chrome) == Favorite (IE)
    LOGIN = 0x10
    LOGOUT = 0x20
    DOWNLOAD = 0x40
    SEARCH_KEYWORD = 0x80  # for well-known search engines (google, bing...)


class VmPopWebBrowser(IntEnum):
    """VmPopWebBrowser class
    """
    ANY = 0
    IE7 = 1  # IE 7 or lower
    IE8 = 2  # IE 8
    IE9 = 3  # IE 9
    IE10 = 4  # IE 10
    IE11 = 5  # IE 11
    EDGE = 6
    CHROME = 7
    FIREFOX = 8
    SAFARI = 9


class VmPopWebSite(IntEnum):
    """VmPopWebSite class
    """
    ANY = 0
    GOOGLE = 1
    BING = 2
    LIVE = 3


class VmPopRPType(IntEnum):
    """VmPopRPType class
    """
    APPLICATION_INSTALL = 0
    APPLICATION_UNINSTALL = 1
    DEVICE_DRIVER_INSTALL = 2
    MODIFY_SETTINGS = 3
    CANCELLED_OPERATION = 4


class VmPopRegType(IntEnum):
    """VmPopRegType class
    """
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_DWORD_LITTLE_ENDIAN = 4
    REG_DWORD_BIG_ENDIAN = 5
    REG_LINK = 6
    REG_MULTI_SZ = 7


class VmPopEvtMonType(IntEnum):
    """VmPopEvtMonType class
    """
    ANY = 0
    WIN_PROCMON = 1
    WIN_PROCMON_32 = 1
    WIN_PROCMON_64 = 2


class VmPopImageFormat(IntEnum):
    """VmPopImageFormat class
    """
    RAW = 0
    VDI = 1
    VMDK = 2
    VHD = 3


class VmPopDataClass(IntEnum):
    """VmPopDataClass class (used in Extractor module)
    """
    ALL = 0
    FILE = 1
    DIRECTORY = 2
    FILE_SYSTEM_METADATA = 3
    FILE_SYSTEM_JOURNAL = 4
    UNALLOCATED_AREA = 5
    WINDOWS_REGISTRY = 6


class VmPopExtractOption(IntEnum):
    """VmPopExtractOption (used in Extractor module)
    """
    FILE_WITH_DIR           = 0x00000001  # Extracting raw files including the directory structure
    FILE_WITHOUT_DIR        = 0x00000002  # Extracting raw files
    ARCHIVE_ZIP             = 0x00000010  # Generating an archive file
                                          # This option should be combined with FILE_WITH_DIR or FILE_WITHOUT_DIR

    # ARCHIVE_ZIP_WITH_DIR    = 0x00000004  # Generating an archive file having files including the directory structure
    # ARCHIVE_ZIP_WITHOUT_DIR = 0x00000008  # Generating an archive file having files


class VmPopOSType(Enum):
    """VmPopOSType class
    """
    UNKNOWN         = ("", 0xFFFFFFFF)

    Windows         = ("Windows", 0x00000000)
    WindowsXP       = ("WindowsXP", 0x00000002)
    WindowsXP_64    = ("WindowsXP_64", 0x00000003)
    WindowsVista    = ("WindowsVista", 0x00000004)
    WindowsVista_64 = ("WindowsVista_64", 0x00000005)
    Windows7        = ("Windows7", 0x00000006)
    Windows7_64     = ("Windows7_64", 0x00000007)
    Windows8        = ("Windows8", 0x00000008)
    Windows8_64     = ("Windows8_64", 0x00000009)
    Windows81       = ("Windows81", 0x0000000A)
    Windows81_64    = ("Windows81_64", 0x0000000B)
    Windows10       = ("Windows10", 0x0000000C)
    Windows10_64    = ("Windows10_64", 0x0000000D)

    Linux           = ("Linux", 0x00000100)
    OSX             = ("OSX", 0x00001000)

    def __init__(self, name, code):
        self._name = name
        self._code = code

    @property
    def os_name(self):
        return self._name

    @property
    def code(self):
        return self._code

    @staticmethod
    def find_by_name(name):
        for item in VmPopOSType:
            if item.os_name == name:
                return item
        return VmPopOSType.UNKNOWN


WIN_PS_SCRIPT_NAME = "temp.ps1"
WIN_PS_OUTPUT_NAME = "temp.output"
WIN_BAT_SCRIPT_NAME = "temp.bat"

WIN_PS_BASE_ARGUMENTS_FOR_ENC = \
    [
        "-NoProfile",
        "-ExecutionPolicy", "bypass",
        # "-outputFormat",    "text",
        "-enc"
    ]

WIN_PS_BASE_ARGUMENTS_FOR_FILE = \
    [
        "-NoProfile",
        "-ExecutionPolicy", "bypass",
        # "-outputFormat",    "text",
        "-file"
    ]

WIN_PS_RUN_ADMIN = \
    '''
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        $command = $MyInvocation.MyCommand.Definition
        $arguments = "-NoProfile -ExecutionPolicy bypass &'$command'"
        Start-Process Powershell -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments
        exit
    } '''

WIN_PS_NGENING = \
    '''
    $env:path = [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    [AppDomain]::CurrentDomain.GetAssemblies() | % {
        if (! $_.location) { continue }
        $Name = Split-Path $_.location -leaf
        Write-Host -ForegroundColor Yellow "NGENing: $Name"  # Installing Dlls into Global Assembly Cache (GAC)
        ngen install $_.location | % {"`t$_"}
    } '''

WIN_PS_SELF_TERMINATION = \
    '''
    Stop-Process -Id $PID'''


WIN_BAT_RUN_ADMIN = \
    '''
    ::
    :: VmPop Batch Script Launcher
    ::
    @echo off
    set window_title=VmPop Batch Script
    title %window_title%

    :check_privileges
        NET FILE 1>NUL 2>NUL
        if '%errorlevel%' == '0' (goto got_privileges) else (goto get_privileges)

    :get_privileges
        if '%1'=='ELEV' (echo ELEV & shift /1 & goto got_privileges)
        setlocal DisableDelayedExpansion
        set "batchPath=%~0"
        setlocal EnableDelayedExpansion
        pushd "%~dp0"
        set "vbs=priv.vbs"
        echo Set UAC = CreateObject^("Shell.Application"^) > !vbs!
        echo args = "ELEV " >> !vbs!
        echo For Each strArg in WScript.Arguments >> !vbs!
        echo args = args ^& strArg ^& " "  >> !vbs!
        echo Next >> !vbs!
        REM echo UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> !vbs!
        echo UAC.ShellExecute "!batchPath!", args, "", "runas", 0 >> !vbs!
        "%SystemRoot%\System32\WScript.exe" !vbs! %*
        popd
        REM exit /B
        timeout /t 2 /nobreak > nul
        goto wait_until_done

    :wait_until_done
        timeout /t 1 /nobreak > nul
        tasklist /fi "Windowtitle eq Administrator:  %window_title%" | find ":" > nul
        if errorlevel 1 goto wait_until_done
        exit /B

    :got_privileges
        if '%1'=='ELEV' shift /1
        setlocal & pushd .
        REM cd /d %~dp0
        pushd "%~dp0"

    ::====================================================================
    :: Main Script
    ::
    '''

WIN_BAT_END_PROCESS = \
    '''

    :end_process
        popd
    '''

IGNORED_ERROR_MESSAGE_BAT = \
    ["ERROR: Input redirection is not supported, exiting the process immediately."]


IGNORED_ERROR_MESSAGE_PS = \
    ["Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem' provider failed.",
     "UninstallString : The term 'UninstallString' is not recognized as the name of  a cmdlet,"]


'''
#-----------------------------------------------------------------------------------
# Defines for action log manager
#-----------------------------------------------------------------------------------
'''
# ----------------------------------
# Action methods
# ----------------------------------
T_ACTION_METHOD_HV = u"HV"    # Hypervisor's feature
T_ACTION_METHOD_EXE = u"EXE"  # Execute an executable file (Windows)
T_ACTION_METHOD_PS = u"PS"    # PowerShell (Windows)
T_ACTION_METHOD_BAT = u"BAT"  # Windows Batch (Windows)
T_ACTION_METHOD_K = u"K"      # Keyboard
T_ACTION_METHOD_M = u"M"      # Mouse
T_ACTION_METHOD_KM = u"KM"    # Keyboard & Mouse mixed

# ----------------------------------
# Action classes
# ----------------------------------
T_CLASS_NONE = u""
T_CLASS_COMMON = u"Common"
T_CLASS_INPUT_DEVICE = u"Input Device"
T_CLASS_CONFIGURATION = u"Configuration"
T_CLASS_ACCOUNT = u"Account"
T_CLASS_REGISTRY = u"Registry"
T_CLASS_PROCESS = u"Process"
T_CLASS_APPLICATION = u"Application"  # relating to 'install' and 'uninstall' actions
T_CLASS_FILESYSTEM = u"Filesystem"
T_CLASS_DEVICE = u"Device"
T_CLASS_SEARCH = u"Search"
T_CLASS_SHARE = u"Share"
T_CLASS_NETWORK_DRIVE = u"Network Drive"
T_CLASS_REMOTE_DESKTOP = u"Remote Desktop"
T_CLASS_SYSTEM_BACKUP = u"System Backup"
T_CLASS_SPECIAL = u"Special"  # Special class (not included in user actions) for internal usages

# ----------------------------------
# Actions (Each action can be used for any class)
# ----------------------------------
T_ACTION_INSTALL_OS = u"Install OS"
T_ACTION_START_VM = u"Start VM"
T_ACTION_STOP_VM = u"Stop VM"
T_ACTION_SHUTDOWN_OS = u"Shutdown OS"
T_ACTION_RESTART_OS = u"Restart OS"
T_ACTION_SET_BIOS_TIME = u"Set the BIOS time"
T_ACTION_CLOSE_WINDOW = u"Close the current window"
T_ACTION_MAXIMIZE_WINDOW = u"Maximize the current window"
T_ACTION_SET_CLIPBOARD = u"Set the clipboard"
T_ACTION_KEYSTROKE = u"Keystroke"
T_ACTION_CLICK_MOUSE = u"Click a mouse button"

# ----------------------------------
T_ACTION_CONFIG_OS = u"Configure OS settings"
T_ACTION_DISABLE_NIC = u"Disable NIC"
T_ACTION_ENABLE_NIC = u"Enable NIC"
T_ACTION_CONFIG_NIC_IP = u"Configure NIC's IP settings"
T_ACTION_CONFIG_NIC_DNS = u"Configure NIC's DNS settings"
T_ACTION_CONFIG_AUDIT_POLICY = u"Configure audit policies"
T_ACTION_CONFIG_EVENTLOG = u"Configure eventlog settings"
T_ACTION_SET_DATETIME = u"Set the date and time"
T_ACTION_DISABLE_TIME_SYNC = u"Disable OS time synchronization"
T_ACTION_ENABLE_TIME_SYNC = u"Enable OS time synchronization"
T_ACTION_DISABLE_TIME_SYNC_GA = u"Disable GA time synchronization"
T_ACTION_ENABLE_TIME_SYNC_GA = u"Enable GA time synchronization"
T_ACTION_CHANGE_TIMEZONE = u"Change the current timezone"
T_ACTION_DISABLE_WINDOWS_UPDATE = u"Disable Windows update feature"
T_ACTION_ENABLE_UAC = u"Enable UAC (User Access Control)"
T_ACTION_DISABLE_UAC = u"Disable UAC (User Access Control)"
T_ACTION_ENABLE_METRO_APPS = u"Enable Metro Apps"
T_ACTION_DISABLE_AUTO_LOGON = u"Disable the auto logon option"
T_ACTION_DISABLE_VISTA_MISC = u"Disable two default auto runs in Vista"
T_ACTION_DISABLE_EDGE_SAVE_PROMPT = u"Disable the save prompt of the Edge browser"

# ----------------------------------
T_ACTION_ADD_LOCAL_ACCOUNT = u"Add a local account"
T_ACTION_ADD_EMAIL_ACCOUNT = u"Add an Email account"
T_ACTION_LOGON_ACCOUNT = u"Logon an account"
T_ACTION_LOGON_ACCOUNT_INV_PW = u"Logon an account with an invalid password or pin"
T_ACTION_LOGOFF_ACCOUNT = u"Logoff from an account"
T_ACTION_CHANGE_ACCOUNT = u"Change account settings"
T_ACTION_DELETE_ACCOUNT = u"Delete an account"

# ----------------------------------
T_ACTION_ATTACH_USB = u"Attach a USB device"
T_ACTION_DETACH_USB = u"Detach a USB device"

# ----------------------------------
T_ACTION_OPEN_SHELL = u"Open the default shell"
# T_ACTION_CLOSE_SHELL = u"Close the default shell"
T_ACTION_COPY = u"Copy data"
T_ACTION_CHANGE_DIR = u"Change the working directory"
T_ACTION_OPEN_FILE = u"Open a file"

# ----------------------------------
T_ACTION_SET_REG_VALUE = u"Set a registry value"

# ----------------------------------
T_ACTION_EXECUTE_PROCESS = u"Execute a process"
T_ACTION_TERMINATE_PROCESS = u"Terminate a process"
T_ACTION_LAUNCH_PROGRAM = u"Launch a program"  # == Execute a process
T_ACTION_LAUNCH_STOREAPP = u"Launch a Windows Store app"  # == Execute a process
T_ACTION_SET_FOREGROUND_WINDOW = u"Activate a window"
T_ACTION_CONTROL_PROCESS = u"Control a process"
T_ACTION_INSTALL_PROGRAM = u"Install a program"
T_ACTION_UNINSTALL_PROGRAM = u"Uninstall a program"
T_ACTION_INSTALL_STOREAPP = u"Install a Windows Store app"
T_ACTION_UNINSTALL_STOREAPP = u"Uninstall a Windows Store app"

# ----------------------------------
T_ACTION_CREATE_RESTORE_POINT = u"Create a restore point"
T_ACTION_RESTORE_RESTORE_POINT = u"Restore a restore point"
T_ACTION_ENABLE_FILE_HISTORY = u"Turn on the File History feature"
T_ACTION_DISABLE_FILE_HISTORY = u"Turn off the File History feature"
T_ACTION_CONFIG_FILE_HISTORY = u"Configure File History settings"

# ----------------------------------
T_ACTION_SEARCH_KEYWORD = u"Search a keyword"
T_ACTION_SHARE_DIR = u"Share a directory"
T_ACTION_CONNECT_NETWORK_DIR = u"Connect a network directory"
T_ACTION_MAP_NETWORK_DIR = u"Map a network directory"
T_ACTION_CONNECT_REMOTE_DESKTOP = u"Connect a remote desktop"
T_ACTION_DISCONNECT = u"Disconnect"

# ----------------------------------
T_ACTION_CHECK_NOTIFICATION = u"Check notifications"
T_ACTION_CREATE_VIRTUAL_DESKTOP = u"Create a virtual desktop"
T_ACTION_CLOSE_VIRTUAL_DESKTOP = u"Close a virtual desktop"

# ----------------------------------
# Internal usages (not included in user actions)
T_ACTION_BEGIN_MONITORING = "Monitoring agent ON"
T_ACTION_END_MONITORING = "Monitoring agent OFF"
