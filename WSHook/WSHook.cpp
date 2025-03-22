#pragma comment(lib, "Ws2_32.lib")

#undef UNICODE
#include <cstdio>
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fstream>
#include <vector>
#include "c:/sources/base/base.h"
#include "encoding.cpp"
#include "psapi.h"
#include "MinHook.h"

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

#define MINPACKETLEN 1
#define VERBOSEOUTPUT 1

void PrintStack(void);

typedef unsigned int u32;

u32 PrintConsole(void *buff, u32 size)
{
    HANDLE std_out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(std_out, buff, size, &written, 0);
    
    return written;
}

void PrintDebug(char *format, ...) 
{
    va_list args;
    va_start(args, format);
    
    char buff[1024] = {0};
    int written = vsprintf(buff, format, args);
    if (written < sizeof(buff)) 
    {
        buff[written++] = '\n';
        OutputDebugStringA(buff); 
        PrintConsole(buff, written);
    }
    
    va_end(args);
}

size_t get_game_module_offset()
{
    HANDLE process_handle  = GetCurrentProcess();
    HMODULE hMods[1024]  = {};
    DWORD cbNeeded;
    
    if( EnumProcessModules(process_handle, hMods, sizeof(hMods), &cbNeeded))
    {
        for (u32  i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
        {
            char szModName[MAX_PATH];
            
            // Get the full path to the module's file.
            
            if ( GetModuleFileNameEx(process_handle, hMods[i], szModName,
                                     MAX_PATH))
            {
                
                if (strncmp(szModName + strlen(szModName) - 4, ".exe", 4) == 0)
                {
					PrintDebug("ModName: %s", szModName);
                    return (size_t)hMods[i];
                }
            }
        }
    }
    
    return 0;
}

void LogAndVerboseOutput(const char* functionName, const char* buffer, size_t bufferLength);

//Prototypes
int (WINAPI *pconnect)(SOCKET s, const sockaddr *name, int namelen) = 0;
int WINAPI MyConnect(SOCKET s, const sockaddr *name, int namelen);

int (WINAPI *precv)(SOCKET s, char* buffer, int length, int flags) = NULL;
int WINAPI MyRecv(SOCKET s, char* buffer, int length, int flags);

int (WINAPI *precvfrom)(SOCKET s, char *buf, int  len, int flags, sockaddr *from, int *fromlen);
int WINAPI MyRecvFrom(SOCKET s, char *buf, int  len, int flags, sockaddr *from, int *fromlen);

int (WINAPI *psend)(SOCKET s, const char* buffer, int length, int flags) = NULL;
int WINAPI MySend(SOCKET s, const char* buffer, int length, int flags);

int (WINAPI *psendto)(SOCKET s, const char *buf, int len, int flags, const sockaddr *to, int tolen);
int WINAPI MySendTo(SOCKET s, const char *buf, int len, int flags, const sockaddr *to, int tolen);

int(WINAPI *pWSAConnect)(SOCKET s, const sockaddr *name, int namelen, LPWSABUF lpCallerData,
                         LPWSABUF lpCalleeData,LPQOS lpSQOS, LPQOS lpGQOS);

int (WINAPI *pWSASend)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
					   LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped,
					   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = NULL;
int WINAPI MyWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
					 LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped,
					 LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
//
int (WINAPI *pWSARecv)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
					   LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,LPWSAOVERLAPPED lpOverlapped, 
					   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = NULL;
int WINAPI MyWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
					 LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,LPWSAOVERLAPPED lpOverlapped, 
					 LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

char * (__cdecl *pLocalizeText)(char * txt);
char * __cdecl MyLocalizeText(char * txt);

char * __cdecl MyLocalizeText(char * txt)
{
	PrintStack();
	
	char *result = pLocalizeText(txt);
    char result_utf8[2048] = {};
    u32 size = s_tcvn_to_utf8(result, result_utf8);
	LogAndVerboseOutput("LocalizeTextIn", txt, strlen(txt));
	LogAndVerboseOutput("LocalizeTextOut", result_utf8, size);
	return result;
}

typedef int (_stdcall *pSendPackToServer)(DWORD, char *data, unsigned long*);
pSendPackToServer SendPackToServerTarget = (pSendPackToServer)(0x6AE9D0); //Set it at address to detour in
pSendPackToServer SendPackToServerOriginal = 0;

int _stdcall MySendPackToServer(DWORD thiz, char *data, unsigned long *length)
{
	if (*length > MINPACKETLEN)
	{
		LogAndVerboseOutput(__FUNCTION__, data, *length);
	}
	if (SendPackToServerOriginal)
	{
		return SendPackToServerOriginal(thiz, data, length);
	}
	return 0;
}


int WINAPI MyConnect(SOCKET s, const sockaddr *name, int namelen)
{
	if (namelen > MINPACKETLEN)
	{
		LogAndVerboseOutput(__FUNCTION__, (char*)name, namelen);
	}
	
	sockaddr_in *addr_in = (sockaddr_in*)name;
	int port = addr_in->sin_port;
	char *ip = inet_ntoa(addr_in->sin_addr);
	
	char buffer[256] = {};
	sprintf(buffer, "%s:%d\n", ip, port);
	LogAndVerboseOutput("address_list.txt", buffer, strlen(buffer));
	
	return pconnect(s, name, namelen);
}

int MyWSAConnect(SOCKET s, const sockaddr *name, int namelen, LPWSABUF lpCallerData,
                 LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS)
{
	if (namelen > MINPACKETLEN)
	{
		LogAndVerboseOutput(__FUNCTION__, (char*)name, namelen);
	}
    
	return pWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

int WINAPI MySend(SOCKET s, const char* buffer, int length, int flags)
{
	if (length > MINPACKETLEN)
	{
		LogAndVerboseOutput(__FUNCTION__, buffer, length);
	}
	return psend(s, buffer, length, flags);
}

int WINAPI MySendTo(SOCKET s, const char *buf, int len, int flags, const sockaddr *to, int tolen)
{
	if (len > MINPACKETLEN)
	{
		LogAndVerboseOutput(__FUNCTION__, buf, len);
	}
	return psendto(s, buf, len, flags, to, tolen);
}

int WINAPI MyWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                     LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped,
                     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	if (lpBuffers->len > MINPACKETLEN)
		LogAndVerboseOutput(__FUNCTION__, lpBuffers->buf, lpBuffers->len);
    
	return pWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                    dwFlags, lpOverlapped, lpCompletionRoutine);
}
int WINAPI MyRecv(SOCKET s, char* buffer, int length, int flags)
{
	if (length > MINPACKETLEN)
		LogAndVerboseOutput(__FUNCTION__, buffer, length);
	return precv(s, buffer, length, flags);
}

int WINAPI MyRecvFrom(SOCKET s, char *buf, int  len, int flags, sockaddr *from, int *fromlen)
{
	if (len > MINPACKETLEN)
	{
		LogAndVerboseOutput(__FUNCTION__, buf, len);
	}
	return precvfrom(s, buf, len, flags, from, fromlen);
}

int WINAPI MyWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                     LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped,
                     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	if (lpBuffers->len > MINPACKETLEN)
	{
		LogAndVerboseOutput(__FUNCTION__, lpBuffers->buf, lpBuffers->len);
	}
	return pWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
                    lpFlags, lpOverlapped, lpCompletionRoutine);
}

void LogAndVerboseOutput(const char* functionName, const char* buffer, size_t bufferLength)
{
	std::ofstream myFile("hook_func_log.txt", std::ios::app);
	char dbuff[256];
	sprintf(dbuff, "%s bufLen: %zd\n", functionName, bufferLength);
	myFile.write(dbuff, strlen(dbuff));
	myFile << std::endl;
    
    
	if (VERBOSEOUTPUT == 1)
	{
		char file_name[64];
		sprintf(file_name, "%s.bin", functionName);
		std::ofstream myFile(file_name, std::ios::app);
		myFile.write(functionName, strlen(functionName));
		myFile << std::endl;
		myFile.write(buffer, bufferLength);
		myFile << std::endl;
	}
}

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
	switch(Reason)
	{
        case DLL_PROCESS_ATTACH:	
        {//Do standard detouring
            PrintDebug("DLL_PROCESS_ATTACH");
            DisableThreadLibraryCalls(hDLL);
            // Initialize MinHook.
            if (MH_Initialize() != MH_OK)
            {
                PrintDebug("MH_Initialize failed");
                return 1;
            }
            
#if 0
            if (MH_CreateHook(SendPackToServerTarget, MySendPackToServer, (LPVOID*)&SendPackToServerOriginal))
                PrintDebug("SendPackToServer() detoured successfully");
            
            if (MH_CreateHookApi(L"Ws2_32", "connect", MyConnect, (LPVOID *)&pconnect) == MH_OK)
                PrintDebug("connect() detoured successfully");
            
            if (MH_CreateHookApi(L"Ws2_32", "send", MySend, (LPVOID *)&psend) == MH_OK)
                PrintDebug("send() detoured successfully");
            
            if (MH_CreateHookApi(L"Ws2_32", "sendto", MySendTo, (LPVOID *)&psendto) == MH_OK)
                PrintDebug("sendto() detoured successfully");
            
            if (MH_CreateHookApi(L"Ws2_32", "recv", MyRecv, (LPVOID *)&precv) == MH_OK)
                PrintDebug("recv() detoured successfully");
            
            if (MH_CreateHookApi(L"Ws2_32", "recvfrom", MyRecvFrom, (LPVOID *)&precvfrom) == MH_OK)
                PrintDebug("recvfrom() detoured successfully");
            
            if (MH_CreateHookApi(L"Ws2_32", "WSAConnect", MyWSAConnect, (LPVOID *)&pWSAConnect) == MH_OK)
                PrintDebug("WSAConnect() detoured successfully");
            
            if (MH_CreateHookApi(L"Ws2_32", "WSASend", MyWSASend, (LPVOID *)&pWSASend) == MH_OK)
                PrintDebug("WSASend() detoured successfully");
            
            if (MH_CreateHookApi(L"Ws2_32", "WSARecv", MyWSARecv, (LPVOID *)&pWSARecv) == MH_OK)
                PrintDebug("WSARecv() detoured successfully");
#endif
            
            AllocConsole();
            
            
            
            MH_STATUS ret = MH_CreateHookApi(L"engine.dll", "?LocalizeText@@YAPBDPBD@Z", MyLocalizeText, (LPVOID *)&pLocalizeText);
            if (ret == MH_OK)
                PrintDebug("LocalizeText() detoured successfully");
            else
            {
                char* err_msg = (char*)MH_StatusToString(ret);
                PrintDebug(err_msg);
                PrintDebug("LocalizeText() detoured failed");
            }
            
            
            
            // Enable the hook for MessageBoxW.
            if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
            {
                PrintDebug("MH_EnableHook pSend failed");
                return 1;
            }
            
            break;
        }
        case DLL_PROCESS_DETACH:
        
		PrintDebug("DLL_PROCESS_DETACH");
        
		// Disable the hook for MessageBoxW.
		if (MH_DisableHook(MH_ALL_HOOKS) != MH_OK)
		{
			return 1;
		}
        
		// Uninitialize MinHook.
		if (MH_Uninitialize() != MH_OK)
		{
			return 1;
		}
		break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

#pragma warning(push)
#pragma warning(disable : 4091)
#include "DbgHelp.h"
#pragma comment(lib, "DbgHelp.lib")
#pragma warning(pop)

void PrintStack(void)
{
	static HANDLE process = 0;
    static size_t current_module_offset = 0;
    static int symbol_size = 0;
    static SYMBOL_INFO* symbol = 0;
    static bool init_success = false;
	if (!process)
	{
		process = GetCurrentProcess();
		SymInitialize(process, NULL, TRUE);
		
        symbol_size = sizeof(SYMBOL_INFO) + 256 * sizeof(TCHAR);
        symbol = (SYMBOL_INFO*)malloc(symbol_size);
        current_module_offset = (size_t)GetModuleHandle(0);
		PrintDebug("Exe Module: %lx\n", current_module_offset);
        
        init_success = symbol && process;
    }
    
    if (init_success)
    {
        const size_t image_base = 0x400000;
        
        const int MAX_STACK_COUNT = 64;
        void* stack[MAX_STACK_COUNT];
        unsigned short frames = CaptureStackBackTrace(0, MAX_STACK_COUNT, stack, NULL);
        
        memset(symbol, 0, symbol_size);
        symbol->MaxNameLen = 255;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        
        PrintDebug("=========call stack==========\n");
        for (u32 i = 1; i < frames; i++)
        {
            HMODULE module = 0;
            char module_name[MAX_PATH] = {0};
            if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                  (LPCSTR)(stack[i]),
                                  &module))
            {
                GetModuleFileName(module, module_name, MAX_PATH);
            } 
            else 
            {
                module = 0;
            }
            
            size_t address = (DWORD64)stack[i] + image_base - (size_t)module;
            SymFromAddr(process, (DWORD64)(stack[i]), 0, symbol);
            
            if ((size_t)module == current_module_offset)
                PrintDebug("%i: %s - 0x%0llX - 0x%0lX in %s\n", frames - i - 1, symbol->Name, symbol->Address, address, module_name);
            else
                PrintDebug("%i: %s - 0x%0llX in %s\n", frames - i - 1, symbol->Name, symbol->Address, module_name);
        }
        PrintDebug("=============================\n");
    }
}