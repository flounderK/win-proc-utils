#!/usr/bin/env python3
import ctypes
from ctypes import wintypes
import argparse
import _ctypes
import enum
import re
import logging


log = logging.getLogger("winvmmap")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(levelname)-7s | %(asctime)-23s | %(message)s'))
log.addHandler(handler)
log.setLevel(logging.WARNING)


class NiceHexFieldRepr:
    """
    Class to insert a readable and customizeable repr for
    subclasses
    """
    def __repr__(self):
        repr_map = None
        if hasattr(self, '__repr_map__'):
            repr_map = self.__repr_map__

        ret = []
        for x in self._fields_:
            k, v = x[:2]
            attr = getattr(self, k)
            if repr_map is not None and k in repr_map.keys():
                rep_func = repr_map.get(k)
                ret.append("%s: %s" % (k, rep_func(attr)))
            elif issubclass(v, _ctypes._SimpleCData):
                ret.append("%s: %#x" % (k, attr if attr else 0))
            else:
                ret.append("%s: %s" % (k, bytes(attr)))
        return "\n".join(ret)


def gen_enum_flags_repr(enum_flag_class):
    """
    Generate a repr function that will display human readable
    enum flag values. Useful in __repr_map__ fields
    """
    def inner(attr_val):
        members, uncovered = enum._decompose(enum_flag_class, attr_val)
        member_repr = '|'.join([i.name for i in members])
        rep = "%s: %#x" % (member_repr, attr_val)
        return rep
    return inner


def errcheck_bool(result, func, args):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return args


MAX_PATH = 1024

STANDARD_RIGHTS_REQUIRED = (0x000F0000)
TOKEN_ASSIGN_PRIMARY = (0x0001)
TOKEN_DUPLICATE = (0x0002)
TOKEN_IMPERSONATE = (0x0004)
TOKEN_QUERY = (0x0008)
TOKEN_QUERY_SOURCE = (0x0010)
TOKEN_ADJUST_PRIVILEGES = (0x0020)
TOKEN_ADJUST_GROUPS = (0x0040)
TOKEN_ADJUST_DEFAULT = (0x0080)
TOKEN_ADJUST_SESSIONID = (0x0100)

SE_PRIVILEGE_ENABLED = 0x00000002


class MemState(enum.IntEnum):
    MEM_FREE = 0x10000
    MEM_COMMIT = 0x00001000
    MEM_RESERVE = 0x00002000


MEM_RESET = 0x00080000
MEM_RESET_UNDO = 0x1000000


class MemType(enum.IntEnum):
    MEM_IMAGE = 0x1000000
    MEM_MAPPED = 0x40000
    MEM_PRIVATE = 0x20000


class WinPageProt(enum.IntFlag):
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_TARGETS_INVALID = 0x40000000
    PAGE_TARGETS_NO_UPDATE = 0x40000000
    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_WRITECOMBINE = 0x400


class PageProt(enum.IntFlag):
    PROT_NONE = 0
    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4




PROCESS_CREATE_PROCESS = (0x0080)
PROCESS_CREATE_THREAD = (0x0002)
PROCESS_DUP_HANDLE = (0x0040)
PROCESS_QUERY_INFORMATION = (0x0400)
PROCESS_QUERY_LIMITED_INFORMATION = (0x1000)
PROCESS_SET_INFORMATION = (0x0200)
PROCESS_SET_QUOTA = (0x0100)
PROCESS_SUSPEND_RESUME = (0x0800)
PROCESS_TERMINATE = (0x0001)
PROCESS_VM_OPERATION = (0x0008)
PROCESS_VM_READ = (0x0010)
PROCESS_VM_WRITE = (0x0020)
SYNCHRONIZE = (0x00100000)


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG)
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES*1),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure, NiceHexFieldRepr):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]
    __repr_map__ = {
        "AllocationProtect": gen_enum_flags_repr(WinPageProt),
        "State": gen_enum_flags_repr(MemState),
        "Protect": gen_enum_flags_repr(WinPageProt),
        "Type": gen_enum_flags_repr(MemType),
    }


class MODULEINFO(ctypes.Structure, NiceHexFieldRepr):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


def lookup_library_symbol(symbol, libraries, **kwargs):
    """
    Look up the given symbol, stopping with the first library that contains it
    """
    if not hasattr(libraries, "__iter__") or isinstance(libraries, str):
        libraries = [libraries]

    for lib in libraries:
        if isinstance(lib, str):
            lib = ctypes.WinDLL(lib, **kwargs)
        try:
            looked_up = getattr(lib, symbol)
        except Exception as err:
            continue
        return looked_up


kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('Advapi32', use_last_error=True)
psapi = ctypes.WinDLL('Psapi', use_last_error=True)

GetCurrentProcess = kernel32.GetCurrentProcess
OpenProcessToken = kernel32.OpenProcessToken
OpenProcess = kernel32.OpenProcess
CloseHandle = kernel32.CloseHandle
VirtualQueryEx = kernel32.VirtualQueryEx
ReadProcessMemory = kernel32.ReadProcessMemory


LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges

EnumProcessModules = lookup_library_symbol("EnumProcessModules", 
                                           ["kernel32", "Psapi"],
                                           use_last_error=True)

EnumProcessModulesEx = psapi.EnumProcessModulesEx
GetModuleInformation = psapi.GetModuleInformation
GetMappedFileNameA = psapi.GetMappedFileNameA

GetModuleFileNameExA = lookup_library_symbol("GetModuleFileNameExA", 
                                           ["kernel32", "Psapi"],
                                           use_last_error=True)


GetCurrentProcess.restype = wintypes.HANDLE

OpenProcessToken.errcheck = errcheck_bool
OpenProcessToken.argtypes = (wintypes.HANDLE,
                             wintypes.DWORD,
                             wintypes.PHANDLE)

OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = (wintypes.DWORD,
                        wintypes.BOOL,
                        wintypes.DWORD)


CloseHandle.errcheck = errcheck_bool
CloseHandle.argtypes = (wintypes.HANDLE,)

VirtualQueryEx.argtypes = (wintypes.HANDLE,
                           ctypes.c_void_p,
                           ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                           ctypes.c_size_t)

ReadProcessMemory.errcheck = errcheck_bool
ReadProcessMemory.argtypes = (wintypes.HANDLE,
                              ctypes.c_void_p,
                              ctypes.c_void_p,
                              ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t))


LookupPrivilegeValueW.errcheck = errcheck_bool
LookupPrivilegeValueW.argtypes = (wintypes.LPCSTR,
                                  wintypes.LPCSTR,
                                  ctypes.POINTER(LUID_AND_ATTRIBUTES))

AdjustTokenPrivileges.errcheck = errcheck_bool
AdjustTokenPrivileges.argtypes = (wintypes.HANDLE,
                                  wintypes.BOOL,
                                  ctypes.POINTER(TOKEN_PRIVILEGES),
                                  wintypes.DWORD,
                                  ctypes.c_void_p,
                                  ctypes.POINTER(wintypes.DWORD))


EnumProcessModules.errcheck = errcheck_bool
EnumProcessModules.argtypes = (wintypes.HANDLE,
                               wintypes.HMODULE,
                               wintypes.DWORD,
                               wintypes.LPDWORD)

EnumProcessModulesEx.errcheck = errcheck_bool
EnumProcessModulesEx.argtypes = (wintypes.HANDLE,
                                 wintypes.HMODULE,
                                 wintypes.DWORD,
                                 wintypes.LPDWORD,
                                 wintypes.DWORD)

GetModuleInformation.errcheck = errcheck_bool
GetModuleInformation.argtypes = (wintypes.HANDLE,
                                 wintypes.HMODULE,
                                 ctypes.POINTER(MODULEINFO),
                                 wintypes.DWORD)
GetModuleFileNameExA.restype = wintypes.DWORD
GetModuleFileNameExA.argtypes = (wintypes.HANDLE,
                                 wintypes.HMODULE,
                                 ctypes.c_void_p,
                                 wintypes.DWORD)
GetMappedFileNameA.restype = wintypes.DWORD
GetMappedFileNameA.argtypes = (wintypes.HANDLE,
                               ctypes.c_void_p,
                               ctypes.c_void_p,
                               wintypes.DWORD)


def enable_debug_privilege():
    hProcess = GetCurrentProcess()
    token = wintypes.HANDLE()
    ptoken = wintypes.PHANDLE(token)
    res = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ptoken)

    privileges = TOKEN_PRIVILEGES(1)
    luid_and_attr = privileges.Privileges[0]
    pluid_and_attr = ctypes.byref(luid_and_attr)
    sedebugprivilege_str = bytes(ctypes.create_unicode_buffer("SeDebugPrivilege"))
    res2 = LookupPrivilegeValueW(wintypes.LPCSTR(), sedebugprivilege_str, pluid_and_attr)

    luid_and_attr.Attributes = SE_PRIVILEGE_ENABLED
    out_return_length = wintypes.DWORD()
    res3 = AdjustTokenPrivileges(token, 0, ctypes.byref(privileges), 0, ctypes.c_void_p(), ctypes.byref(out_return_length))
    CloseHandle(token)


def page_prot_from_windows(prot):
    if (prot & WinPageProt.PAGE_NOACCESS) != 0:
      return PageProt.PROT_NONE
    elif (prot & WinPageProt.PAGE_READONLY) != 0:
      return PageProt.PROT_READ
    elif ((prot & WinPageProt.PAGE_READWRITE) != 0) or \
         ((prot & WinPageProt.PAGE_WRITECOPY) != 0):
      return PageProt.PROT_READ | PageProt.PROT_WRITE
    elif (prot & WinPageProt.PAGE_EXECUTE) != 0:
      return PageProt.PROT_EXEC
    elif (prot & WinPageProt.PAGE_EXECUTE_READ) != 0:
      return PageProt.PROT_EXEC | PageProt.PROT_READ
    elif ((prot & WinPageProt.PAGE_EXECUTE_READWRITE) != 0) or \
         ((prot & WinPageProt.PAGE_EXECUTE_WRITECOPY) != 0):
      return PageProt.PROT_READ | PageProt.PROT_WRITE | PageProt.PROT_EXEC
    else:
        log.debug("Unhandled page prot %s" % hex(prot if isinstance(prot, int) else 0))
        return PageProt.PROT_NONE


class MemoryQueryManager:
    def __init__(self, pid):
        self.pid = pid
        self.memory_regions = []
        self.module_infos = []
        self.mapped_files = {}
        self.initial_query()

    def initial_query(self):
        enable_debug_privilege()

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, self.pid)
        pathbuf = (ctypes.c_ubyte*MAX_PATH)()

        # iterate over all of the addresses starting at zero, find all of the regions
        cur_base_address = 0
        mem_regions = []
        mapped_files = {}
        while True:
            mbi = MEMORY_BASIC_INFORMATION()
            ret = VirtualQueryEx(hProcess, cur_base_address, ctypes.byref(mbi), ctypes.sizeof(mbi))
            if ret == 0:
                break
            if mbi.Protect != 0 and (mbi.Protect & WinPageProt.PAGE_GUARD) == 0:
                mem_regions.append(mbi)
            if mbi.Type == MemType.MEM_MAPPED:
                ctypes.memset(pathbuf, 0, ctypes.sizeof(pathbuf))
                ret = GetMappedFileNameA(hProcess, mbi.BaseAddress, ctypes.byref(pathbuf), ctypes.sizeof(pathbuf))
                if ret != 0:
                    mapped_files[mbi.BaseAddress] = ctypes.string_at(pathbuf).decode()
            cur_base_address += mbi.RegionSize
        
        self.memory_regions = mem_regions
        self.mapped_files = mapped_files
        # query the modules (loaded DLL) info specifically
        hmodule = wintypes.HMODULE()
        modules_size = wintypes.DWORD(0)
        EnumProcessModulesEx(hProcess, ctypes.byref(hmodule), ctypes.sizeof(hmodule), ctypes.byref(modules_size), 0)

        hmodule_arr = (wintypes.HMODULE*(modules_size.value // ctypes.sizeof(hmodule)))()
        EnumProcessModulesEx(hProcess, hmodule_arr, ctypes.sizeof(hmodule_arr), ctypes.byref(modules_size), 0)

        moduleinfos = []
        for hModule in hmodule_arr:
            ctypes.memset(pathbuf, 0, ctypes.sizeof(pathbuf))
            mi = MODULEINFO()
            GetModuleInformation(hProcess, hModule, ctypes.byref(mi), ctypes.sizeof(mi))
            GetModuleFileNameExA(hProcess, hModule, ctypes.byref(pathbuf), ctypes.sizeof(pathbuf))
                
            moduleinfos.append((mi, ctypes.string_at(pathbuf).decode()))
        self.module_infos = moduleinfos
        
        CloseHandle(hProcess)

    
    def iter_regions_callback(self, func):
        """
        callback to a function with the signature:
        `func(MemoryQueryManager, process_handle, MEMORY_BASIC_INFORMATION)`
        """
        enable_debug_privilege()
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, self.pid)
        collected = []
        for region in self.memory_regions:
            if region.State == MemState.MEM_FREE:
                continue
            
            try:
                res = func(self, hProcess, region)
            except Exception as err:
                continue
            collected.append(res)
        
        CloseHandle(hProcess)
        return collected
    
    def dump_regions_of_ptrs(self, ptrs):
        """
        Write region that contains the given address
        """
        if not hasattr(ptrs, "__iter__"):
            ptrs = [ptrs]

        enable_debug_privilege()
        # TODO: maybe rewrite this as a callback function 
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, self.pid)
        for region in self.memory_regions:
            if region.State == MemState.MEM_FREE:
                continue
            region_start = region.BaseAddress
            region_end = region_start + region.RegionSize
            write_region_to_file = False
            for p in ptrs:
                if region_start <= p and p <= region_end:
                    write_region_to_file = True
            
            if write_region_to_file is False:
                continue

            self.write_region_to_file(hProcess, region)
        
        CloseHandle(hProcess)

    def write_region_to_file(self, hProcess, region):
        """
        MEMORY_BASIC_INFORMATION
        """
        read_buf = (ctypes.c_ubyte*region.RegionSize)()
        bytes_read = ctypes.c_size_t(0)
        ReadProcessMemory(hProcess, region.BaseAddress, ctypes.byref(read_buf), region.RegionSize,
                            ctypes.byref(bytes_read))
        region_end = region.BaseAddress + region.RegionSize
        filename = f"{self.pid}.{region.BaseAddress:016x}-{region_end:016x}.dump"
        with open(filename, "wb") as f:
            f.write(bytearray(read_buf))
        
    def search_memory_for_pattern(self, pattern, write_region_to_file=False, escape=True):

        if escape is True:
            pattern = re.escape(pattern)
        
        rexp = re.compile(pattern, re.MULTILINE | re.DOTALL)

        found_locations = []
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, self.pid)
        for region in self.memory_regions:
            if region.State == MemState.MEM_FREE:
                continue
            region_start = region.BaseAddress
            region_end = region_start + region.RegionSize
            any_found_matches = False

            read_buf = (ctypes.c_ubyte*region.RegionSize)()
            bytes_read = ctypes.c_size_t(0)
            ReadProcessMemory(hProcess, region.BaseAddress, ctypes.byref(read_buf), region.RegionSize,
                                ctypes.byref(bytes_read))

            read_buf_bytearray = bytearray(read_buf)
            for m in re.finditer(rexp, read_buf_bytearray):
                found_locations.append(region_start + m.start())
                any_found_matches = True
            
            if any_found_matches is False or write_region_to_file is False:
                continue
            
            # inlining the dump to file here to avoid reading the region bytes in again
            filename = f"{self.pid}.{region.BaseAddress:016x}-{region_end:016x}.dump"
            with open(filename, "wb") as f:
                f.write(read_buf_bytearray)
        
        CloseHandle(hProcess)
        return found_locations

    def print_memory(self):
        """
        Print out address space, similar to /proc/self/maps on linux
        """
        for region in self.memory_regions:
            if region.State == MemState.MEM_FREE:
                continue
            region_start = region.BaseAddress
            region_end = region_start + region.RegionSize
            line = "%016x-%016x " % (region_start, region_end)
            prot = page_prot_from_windows(region.Protect)
            if (prot & PageProt.PROT_READ) != 0:
                line += "r"
            else:
                line += "-"
            
            if (prot & PageProt.PROT_WRITE) != 0:
                line += "w"
            else:
                line += "-"
            
            if (prot & PageProt.PROT_EXEC) != 0:
                line += "x"
            else:
                line += "-"

            line += " "

            if region.Type == MemType.MEM_IMAGE:
                for moduleinfo, path in self.module_infos:
                    modstart = moduleinfo.lpBaseOfDll
                    modend = modstart + moduleinfo.SizeOfImage
                    if region_start >= modstart and region_end <= modend:
                        line += path
            if region.Type == MemType.MEM_MAPPED:
                path = self.mapped_files.get(region_start)
                if path is not None:
                    line += path
            print(line)


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, 
                        help="Process id of the process to trace.")
    parser.add_argument("--debug", action="store_true",
                        default=False, help="enable debug logging")
    args = parser.parse_args()
    if args.debug is True:
        log.setLevel(logging.DEBUG)

    mqm = MemoryQueryManager(args.pid)
    mqm.print_memory()


if __name__ == "__main__":
    cli()