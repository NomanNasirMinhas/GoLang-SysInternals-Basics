package sysinternals

import "syscall"

var (
	ModKernel32 = syscall.NewLazyDLL("kernel32.dll")
	ModAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	ModUser32   = syscall.NewLazyDLL("user32.dll")

	ProcOpenProcessToken      = ModAdvapi32.NewProc("GetProcessToken")
	ProcLookupPrivilegeValueW = ModAdvapi32.NewProc("LookupPrivilegeValueW")
	ProcLookupPrivilegeNameW  = ModAdvapi32.NewProc("LookupPrivilegeNameW")
	ProcAdjustTokenPrivileges = ModAdvapi32.NewProc("AdjustTokenPrivileges")
	ProcGetAsyncKeyState      = ModUser32.NewProc("GetAsyncKeyState")
	ProcVirtualAlloc          = ModKernel32.NewProc("VirtualAlloc")
	ProcCreateThread          = ModKernel32.NewProc("CreateThread")
	ProcWaitForSingleObject   = ModKernel32.NewProc("WaitForSingleObject")
	ProcVirtualAllocEx        = ModKernel32.NewProc("VirtualAllocEx")
	ProcVirtualFreeEx         = ModKernel32.NewProc("VirtualFreeEx")
	ProcCreateRemoteThread    = ModKernel32.NewProc("CreateRemoteThread")
	ProcGetLastError          = ModKernel32.NewProc("GetLastError")
	ProcWriteProcessMemory    = ModKernel32.NewProc("WriteProcessMemory")
	ProcOpenProcess           = ModKernel32.NewProc("OpenProcess")
	ProcGetCurrentProcess     = ModKernel32.NewProc("GetCurrentProcess")
	ProcIsDebuggerPresent     = ModKernel32.NewProc("IsDebuggerPresent")
	ProcGetProcAddress        = ModKernel32.NewProc("GetProcAddress")
	ProcCloseHandle           = ModKernel32.NewProc("CloseHandle")
	ProcGetExitCodeThread     = ModKernel32.NewProc("GetExitCodeThread")
)

const (
	PROCESS_CREATE_PROCESS            = 0x0080
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_SET_INFORMATION           = 0x0200
	PROCESS_SET_QUOTA                 = 0x0100
	PROCESS_SUSPEND_RESUME            = 0x0800
	PROCESS_TERMINATE                 = 0x0001
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_ALL_ACCESS                = 0x001F0FFF
	MEM_COMMIT                        = 0x00001000
	MEM_RESERVE                       = 0x00002000
	MEM_RESET                         = 0x00080000
	MEM_RESET_UNDO                    = 0x1000000
	MEM_RELEASE                       = 0x00008000
	PAGE_EXECUTE_READWRITE            = 0x40
	PAGE_EXECUTE_READ                 = 0x20
	PAGE_EXECUTE                      = 0x10
	PAGE_READONLY                     = 0x02
	PAGE_READWRITE                    = 0x04
	PAGE_WRITECOPY                    = 0x08
	PAGE_NOACCESS                     = 0x01
	INFINITE                          = 0xFFFFFFFF
)

// The Inject struct object contains various values that will be provided to the relevant Windows function via syscall.
type Inject struct {
	Pid              uint32
	DllPath          string
	DLLSize          uint32
	Privilege        string
	RemoteProcHandle uintptr
	Lpaddr           uintptr
	LoadLibAddr      uintptr
	RThread          uintptr
	Token            TOKEN
}

type TOKEN struct {
	tokenHandle syscall.Token
}
