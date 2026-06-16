#include "DriverWorker.hpp"
#include "Log.hpp"
#include "DriverSelector.hpp"
#include <iostream> // 确保 std::cout 和 std::endl 可用

static BOOLEAN g_bKiller{FALSE};

auto
DriverWorker::InitializeDriver() -> BOOLEAN
{
	return CurrentProvider()->InitDriver();
}

auto
DriverWorker::UninitializeDriver() -> VOID
{
	CurrentProvider()->Uninitialize();
}

auto 
DriverWorker::Read(
	PVOID VirtualAddress,
	PVOID ReadBuffer, 
	ULONG Size) ->BOOLEAN
{
	return CurrentProvider()->Read(VirtualAddress, ReadBuffer, Size);
}

auto 
DriverWorker::Write(
	PVOID VirtualAddress, 
	PVOID WriteBuffer,
	ULONG Size) ->BOOLEAN
{
	return CurrentProvider()->Write(VirtualAddress, WriteBuffer, Size);
}

auto DriverWorker::KillerInit()->BOOLEAN
{
	auto bResut = CurrentKiller()->Initialize();
	if (!bResut)
	{
		return FALSE;
	}
	else
	{
		LOG("Start Killer Driver");
		g_bKiller = TRUE;
		return TRUE;
	}

	return FALSE;
}

auto DriverWorker::Kill(ULONG Pid) ->BOOLEAN
{
	auto bResult{ FALSE };

	// check it again
	if (!g_bKiller)
	{
		return FALSE;
	}

	if (Pid > 4)
	{
		// 修复了原本错误的 LOG(...) << 语法
		std::cout << "Kill pid = " << Pid << std::endl;
		bResult = CurrentKiller()->KillProcess(Pid);
	}

	// unload will cause BSOD
	// never call it like this
	//g_GGProtect64->Uninitialize();
	return bResult;
}

auto DriverWorker::KillUnInit()
{
	if (!g_bKiller)
	{
		return;
	}

	CurrentKiller()->Uninitialize();
}
