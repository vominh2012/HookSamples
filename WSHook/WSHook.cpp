#pragma comment(lib, "Ws2_32.lib")

#undef UNICODE
#include <cstdio>
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fstream>
#include <vector>
#include "MinHook.h" //*IMPORTANT: Look at path if compiler error

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

#define MINPACKETLEN 1
#define VERBOSEOUTPUT 1


void LogAndVerboseOutput(const char* functionName, const char* buffer, int bufferLength);

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

void LogAndVerboseOutput(const char* functionName, const char* buffer, int bufferLength)
{
	std::ofstream myFile("hook_func_log.txt", std::ios::app);
	char dbuff[256];
	sprintf(dbuff, "%s bufLen: %d\n", functionName, bufferLength);
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
	case DLL_PROCESS_ATTACH:	//Do standard detouring
		OutputDebugString("DLL_PROCESS_ATTACH");
		DisableThreadLibraryCalls(hDLL);
		// Initialize MinHook.
		if (MH_Initialize() != MH_OK)
		{
			OutputDebugString("MH_Initialize failed");
			return 1;
		}

		if (MH_CreateHook(SendPackToServerTarget, MySendPackToServer, (LPVOID*)&SendPackToServerOriginal))
			OutputDebugString("SendPackToServer() detoured successfully");

		if (MH_CreateHookApi(L"Ws2_32", "connect", MyConnect, (LPVOID *)&pconnect) == MH_OK)
			OutputDebugString("connect() detoured successfully");

		if (MH_CreateHookApi(L"Ws2_32", "send", MySend, (LPVOID *)&psend) == MH_OK)
			OutputDebugString("send() detoured successfully");

		if (MH_CreateHookApi(L"Ws2_32", "sendto", MySendTo, (LPVOID *)&psendto) == MH_OK)
			OutputDebugString("sendto() detoured successfully");

		if (MH_CreateHookApi(L"Ws2_32", "recv", MyRecv, (LPVOID *)&precv) == MH_OK)
			OutputDebugString("recv() detoured successfully");

		if (MH_CreateHookApi(L"Ws2_32", "recvfrom", MyRecvFrom, (LPVOID *)&precvfrom) == MH_OK)
			OutputDebugString("recvfrom() detoured successfully");

		if (MH_CreateHookApi(L"Ws2_32", "WSAConnect", MyWSAConnect, (LPVOID *)&pWSAConnect) == MH_OK)
			OutputDebugString("WSAConnect() detoured successfully");

		if (MH_CreateHookApi(L"Ws2_32", "WSASend", MyWSASend, (LPVOID *)&pWSASend) == MH_OK)
			OutputDebugString("WSASend() detoured successfully");

		if (MH_CreateHookApi(L"Ws2_32", "WSARecv", MyWSARecv, (LPVOID *)&pWSARecv) == MH_OK)
			OutputDebugString("WSARecv() detoured successfully");

		// Enable the hook for MessageBoxW.
		if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
		{
			OutputDebugString("MH_EnableHook pSend failed");
			return 1;
		}

		break;
	case DLL_PROCESS_DETACH:

		OutputDebugString("DLL_PROCESS_DETACH");

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
