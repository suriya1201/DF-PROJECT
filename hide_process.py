import ctypes
from ctypes import wintypes as w

# Constants
DEVICE_NAME = r"\\.\kernel_driver"  # Corrected typo

# IOCTL codes
CTL_CODE = lambda dev, func: (
    (dev << 16) | (0 << 14) | (func << 2) | 0x00000003  # METHOD_BUFFERED
)

IOCTL_READ_PTE = CTL_CODE(0x800, 0x100)
IOCTL_WRITE_PTE = CTL_CODE(0x800, 0x101)
IOCTL_HIDE_VAD = CTL_CODE(0x800, 0x200)
IOCTL_REMAP_MAS = CTL_CODE(0x800, 0x300)

class PTE_REQUEST(ctypes.Structure):
    _fields_ = [
        ("ProcessId", w.ULONG),
        ("VirtualAddress", w.ULONGLONG),
        ("PteValue", w.ULONGLONG),   # out for read, in for write
    ]

class VAD_HIDE(ctypes.Structure):
    _fields_ = [
        ("ProcessId", w.ULONG),
        ("VadNodeAddress", w.ULONGLONG),
    ]

class MAS_REMAP(ctypes.Structure):
    _fields_ = [
        ("ProcessId", w.ULONG),
        ("OldBase", w.ULONGLONG),
        ("Size", w.ULONGLONG),
        ("NewPhysicalFrames", w.ULONGLONG),  # array pointer in driver
    ]

def ioctl(handle, code, in_buf, out_buf):
    bytes_ret = w.DWORD()
    success = ctypes.WinDLL.kernel32.DeviceIoControl(
        handle,
        code,
        ctypes.byref(in_buf), ctypes.sizeof(in_buf),
        ctypes.byref(out_buf), ctypes.sizeof(out_buf),
        ctypes.byref(bytes_ret),
        None)
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())
    return out_buf

def pte_make_nonpresent(handle, pid: int, va: int):
    req = PTE_REQUEST(ProcessId=pid, VirtualAddress=va)
    # read current PTE
    req = ioctl(handle, IOCTL_READ_PTE, req, req)
    original = req.PteValue
    # clear Present bit (bit 0)
    req.PteValue = original & ~1
    ioctl(handle, IOCTL_WRITE_PTE, req, req)
    print(f"PTE @{hex(va)} cleared (was {hex(original)})") # Fixed missing parenthesis

def hide_vad(handle, pid: int, vad_node_rva: int):
    req = VAD_HIDE(ProcessId=pid, VadNodeAddress=vad_node_rva)
    ioctl(handle, IOCTL_HIDE_VAD, req, req)

def remap_mas(handle, pid: int, old_base: int, size: int, new_physical_frames: int):
    req = MAS_REMAP(
        ProcessId=pid,
        OldBase=old_base,
        Size=size,
        NewPhysicalFrames=new_physical_frames
    )
    ioctl(handle, IOCTL_REMAP_MAS, req, req)

# Main function
def main():
    try:
        # Open handle to driver
        handle = ctypes.WinDLL.kernel32.CreateFileW(
            DEVICE_NAME,
            0xC0000000,                     # GENERIC_READ | GENERIC_WRITE
            0, None, 3, 0, None)            # OPEN_EXISTING

        INVALID_HANDLE_VALUE = 0xFFFFFFFFFFFFFFFF
        if handle == INVALID_HANDLE_VALUE:
            raise RuntimeError("Cannot open driver")

        print("Driver opened successfully")

        # Example usage
        pid = 1234  # Replace with actual process ID
        va = 0x10000000  # Replace with actual virtual address

        pte_make_nonpresent(handle, pid, va)

        # Hide VAD node
        hide_vad(handle, pid, 0x12345678)  # Replace with actual VAD node address

        # Remap memory-mapped area
        remap_mas(handle, pid, 0x10000000, 0x1000000, 0x12345678)  # Replace with actual values

    except Exception as e:
        print(f"Error: {e}")

    finally:
        if 'handle' in locals() and handle != INVALID_HANDLE_VALUE:
            ctypes.WinDLL.kernel32.CloseHandle(handle)

if __name__ == "__main__":
    main()