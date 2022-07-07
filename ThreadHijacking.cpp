#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <stdio.h>

using namespace std;

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

#define SE_DEBUG_PRIVILEGE 20

char shell_code[] =
{
	0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB, 0x06, 0x00, 0x00,
	0x00, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8D, 0x93, 0x22, 0x00, 0x00, 0x00,
	0x52, 0xFF, 0xD0, 0x61, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3
};

void get_proc_id(const char* window_title, DWORD &process_id)
{
	GetWindowThreadProcessId(FindWindow(NULL, window_title), &process_id);
}

void error(const char* error_title, const char* error_message)
{
	MessageBox(NULL, error_message, error_title, NULL);
	exit(-1);
}

bool file_exists(string file_name)
{
	struct stat buffer;
	return (stat(file_name.c_str(), &buffer) == 0);
}

int main()
{
	LPBYTE ptr;
	HANDLE h_process, h_thread, h_snap;
	PVOID allocated_memory, buffer;
	DWORD proc_id;
	BOOLEAN buff;

	THREADENTRY32 te32;
	CONTEXT ctx;

	char dll_path[MAX_PATH];
	const char* dll_name = "TestDLL.dll";
	const char* window_title = "Counter-Strike: Global Offensive";

	te32.dwSize = sizeof(te32);
	ctx.ContextFlags = CONTEXT_FULL;

	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &buff);

	if (!file_exists(dll_name))
	{
		error("file_exists", "File doesn't exist");
	}

	if (!GetFullPathName(dll_name, MAX_PATH, dll_path, nullptr))
	{
		error("GetFullPathName", "Failed to get full path");
	}

	get_proc_id(window_title, proc_id);
	if (proc_id == NULL)
	{
		error("get_proc_id", "Failed to get process ID");
	}

	h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);
	if (!h_process)
	{
		error("OpenProcess", "Failed to open a handle to the process");
	}

	h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

	Thread32First(h_snap, &te32);

	while (Thread32Next(h_snap, &te32))
	{
		if (te32.th32OwnerProcessID == proc_id)
		{
			break;
		}
	}

	CloseHandle(h_snap);

	allocated_memory = VirtualAllocEx(h_process, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!allocated_memory)
	{
		CloseHandle(h_process);
		error("VirtualAllocEx", "Failed to allocate memory");
	}

	h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
	if (!h_thread)
	{
		VirtualFreeEx(h_process, allocated_memory, NULL, MEM_RELEASE);
		CloseHandle(h_process);
		error("OpenThread", "Failed to open a handle to the thread");
	}

	SuspendThread(h_thread);
	GetThreadContext(h_thread, &ctx);

	buffer = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ptr = (LPBYTE)buffer;

	memcpy(buffer, shell_code, sizeof(shell_code));

	while (1)
	{
		if (*ptr == 0xb8 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
		{
			*(PDWORD)(ptr + 1) = (DWORD)LoadLibraryA;
		}

		if (*ptr == 0x68 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
		{
			*(PDWORD)(ptr + 1) = ctx.Eip;
		}

		if (*ptr == 0xc3)
		{
			ptr++;
			break;
		}

		ptr++;
	}

	strcpy((char*)ptr, dll_path);

	if (!WriteProcessMemory(h_process, allocated_memory, buffer, sizeof(shell_code) + strlen((char*)ptr), nullptr))
	{
		VirtualFreeEx(h_process, allocated_memory, NULL, MEM_RELEASE);
		ResumeThread(h_thread);

		CloseHandle(h_thread);
		CloseHandle(h_process);

		VirtualFree(buffer, NULL, MEM_RELEASE);
		error("WriteProcessMemory", "Failed to write process memory");
	}

	ctx.Eip = (DWORD)allocated_memory;

	if (!SetThreadContext(h_thread, &ctx))
	{
		VirtualFreeEx(h_process, allocated_memory, NULL, MEM_RELEASE);
		ResumeThread(h_thread);

		CloseHandle(h_thread);
		CloseHandle(h_process);

		VirtualFree(buffer, NULL, MEM_RELEASE);
		error("SetThreadContext", "Failed to set thread context");
	}

	ResumeThread(h_thread);

	CloseHandle(h_thread);
	CloseHandle(h_process);

	VirtualFree(buffer, NULL, MEM_RELEASE);

	MessageBox(NULL, "Successfully injected", "Success!", NULL);

	return NULL;
}

