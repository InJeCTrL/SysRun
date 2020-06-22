#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#pragma comment (lib, "Psapi.lib")

VOID SeDebugPrivilege()
{
	typedef void(*RtlSeDebug)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
	BOOLEAN WTF = 0;
	HINSTANCE h = LoadLibrary(__TEXT("ntdll.dll"));

	RtlSeDebug RtlAdjustPrivilege = (RtlSeDebug)GetProcAddress(h, "RtlAdjustPrivilege");
	RtlAdjustPrivilege(0x14, TRUE, FALSE, &WTF);
}

DWORD GetPID(LPCTSTR ProcessName)
{
	DWORD PID[2048] = { 0 };
	DWORD Needed = 0;
	UINT n_ps = 0;
	DWORD target = -1;
	HANDLE hProc = NULL;
	TCHAR ImageName[1024] = { 0 };

	if (*ProcessName)
	{
		EnumProcesses(PID, sizeof(PID), &Needed);
		n_ps = Needed / sizeof(DWORD);
		for (UINT i = 0; i < n_ps; i++)
		{
			if ((hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PID[i])))
			{
				if (GetProcessImageFileName(hProc, ImageName, sizeof(ImageName)))
				{
					LPTSTR pProcName = (LPTSTR)ProcessName;
					LPTSTR pImageName = (LPTSTR)ImageName;
					UINT lenProc = 0, lenImage = 0;
					while (*pImageName)
					{
						++pImageName;
						++lenImage;
					}
					while (*pProcName)
					{
						++pProcName;
						++lenProc;
					}
					--pProcName;
					--pImageName;
					if (lenImage < lenProc)
					{
						CloseHandle(hProc);
						continue;
					}
					while (lenProc)
					{
						if (*pImageName-- != *pProcName--)
						{
							break;
						}
						--lenProc;
					}
					if (!lenProc && *pImageName == '\\')
					{
						target = PID[i];
						CloseHandle(hProc);
						break;
					}
				}
				CloseHandle(hProc);
			}
		}
	}

	return target;
}

int main(UINT argc, LPCSTR argv[])
{
	SeDebugPrivilege();

	DWORD PID_winlogon = GetPID(__TEXT("winlogon.exe"));
	TCHAR wPath[1024] = { 0 };
	size_t szPath = 0;
	HANDLE hProc_winlogon = NULL,
		hToken = NULL,
		hToken_Duplicate = NULL;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);
	si.wShowWindow = SW_SHOW;
	si.lpDesktop = NULL;
	si.dwFlags = STARTF_USESHOWWINDOW;

	if (argc != 2)
	{
		wprintf(__TEXT("Usage:\tsysrun.exe FILEPATH"));
	}
	else
	{
		mbstowcs_s(&szPath, wPath, 1024, argv[1], _TRUNCATE);
		if (PID_winlogon == -1)
		{
			wprintf(__TEXT("Error: GetPID-winlogon %d"), PID_winlogon);
		}
		else
		{
			if (hProc_winlogon = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID_winlogon))
			{
				if (OpenProcessToken(hProc_winlogon, TOKEN_DUPLICATE, &hToken))
				{
					if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hToken_Duplicate))
					{
						if (CreateProcessWithTokenW(hToken_Duplicate, LOGON_WITH_PROFILE, wPath, NULL, 0, NULL, NULL, &si, &pi))
						{
							CloseHandle(pi.hProcess);
							CloseHandle(pi.hThread);
						}
						else
						{
							wprintf(__TEXT("Error: CreateProcessWithTokenW\nPath:\t%s"), wPath);
						}
						CloseHandle(hToken_Duplicate);
					}
					else
					{
						wprintf(__TEXT("Error: DuplicateTokenEx"));
					}
					CloseHandle(hToken);
				}
				else
				{
					wprintf(__TEXT("Error: OpenProcessToken"));
				}
				CloseHandle(hProc_winlogon);
			}
			else
			{
				wprintf(__TEXT("Error: OpenProcess-winlogon"));
			}
		}
	}

	return 0;
}