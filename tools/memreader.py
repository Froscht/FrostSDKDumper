"""Thin wrapper around /dev/memreader's basic READ_MEMORY ioctl.

The kernel-module ABI is defined in `KernelDriver/include/memreader_ioctl.h`:

    struct memreader_read_request {
        int pid;                       // 4B
        // padding 4B (struct alignment to 8 for ulong)
        unsigned long address;         // 8B
        unsigned long size;            // 8B
        void *buffer;                  // 8B
    };
    #define MEMREADER_MAGIC 'M'
    #define MEMREADER_READ_MEMORY  _IOWR(MEMREADER_MAGIC, 1, struct memreader_read_request)

`_IOWR(type, nr, size)` encodes to:
    (3 << 30) | (sizeof(req) << 16) | (ord('M') << 8) | nr

sizeof(req) on x86-64 = 4 + 4 (pad) + 8 + 8 + 8 = 32.

Run as root.
"""

import ctypes
import fcntl
import os
import sys


_IOC_NRBITS   = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_DIRBITS  = 2

_IOC_NRSHIFT   = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT  = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_READ  = 2
_IOC_WRITE = 1


def _IOC(direction, type_, nr, size):
    return ((direction << _IOC_DIRSHIFT)
            | (ord(type_) << _IOC_TYPESHIFT)
            | (nr << _IOC_NRSHIFT)
            | (size << _IOC_SIZESHIFT))


class MemreaderReadRequest(ctypes.Structure):
    _fields_ = [
        ("pid",     ctypes.c_int),
        ("_pad",    ctypes.c_int),
        ("address", ctypes.c_ulong),
        ("size",    ctypes.c_ulong),
        ("buffer",  ctypes.c_void_p),
    ]


_MEMREADER_READ_MEMORY = _IOC(
    _IOC_READ | _IOC_WRITE, 'M', 1, ctypes.sizeof(MemreaderReadRequest)
)


class MemReader:
    def __init__(self, pid: int, dev_path: str = "/dev/memreader"):
        self.pid = pid
        self.fd = os.open(dev_path, os.O_RDWR)

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def read(self, address: int, size: int) -> bytes:
        buf = (ctypes.c_ubyte * size)()
        req = MemreaderReadRequest(
            pid=self.pid,
            _pad=0,
            address=address,
            size=size,
            buffer=ctypes.cast(buf, ctypes.c_void_p),
        )
        fcntl.ioctl(self.fd, _MEMREADER_READ_MEMORY, req)
        return bytes(buf)

    def read_u32(self, address: int) -> int:
        return int.from_bytes(self.read(address, 4), "little")

    def read_u64(self, address: int) -> int:
        return int.from_bytes(self.read(address, 8), "little")


def find_pid(name_substr: str = "GameThread") -> int:
    """Find a PID whose /proc/<pid>/comm matches `name_substr`.
    Skips any PID whose cmdline contains "CrashReportClient"."""
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
        except (OSError, IOError):
            continue
        if name_substr not in comm:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read()
        except (OSError, IOError):
            continue
        if b"CrashReportClient" in cmdline:
            continue
        return pid
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: memreader.py <pid> <addr_hex> [size]", file=sys.stderr)
        print("       memreader.py find", file=sys.stderr)
        sys.exit(2)
    if sys.argv[1] == "find":
        print(find_pid())
        sys.exit(0)
    pid = int(sys.argv[1])
    addr = int(sys.argv[2], 16)
    size = int(sys.argv[3]) if len(sys.argv) > 3 else 16
    with MemReader(pid) as mr:
        data = mr.read(addr, size)
    print(data.hex())
