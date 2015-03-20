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

#define MINPACKETLEN 5
#define VERBOSEOUTPUT 1

//Prototypes

int (WINAPI *precv)(SOCKET socket, char* buffer, int length, int flags) = NULL;
int WINAPI MyRecv(SOCKET socket, char* buffer, int length, int flags);
//
int (WINAPI *psend)(SOCKET socket, const char* buffer, int length, int flags) = NULL;
int WINAPI MySend(SOCKET socket, const char* buffer, int length, int flags);
//
int (WINAPI *pWSASend)(SOCKET socket, LPWSABUF lpBuffers, DWORD dwBufferCount,
					   LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped,
					   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = NULL;
int WINAPI MyWSASend(SOCKET socket, LPWSABUF lpBuffers, DWORD dwBufferCount,
					 LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped,
					 LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
//
int (WINAPI *pWSARecv)(SOCKET socket, LPWSABUF lpBuffers, DWORD dwBufferCount,
					   LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,LPWSAOVERLAPPED lpOverlapped, 
					   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = NULL;
int WINAPI MyWSARecv(SOCKET socket, LPWSABUF lpBuffers, DWORD dwBufferCount,
					 LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,LPWSAOVERLAPPED lpOverlapped, 
					 LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

void LogAndVerboseOutput(const char* functionName, const char* buffer, int bufferLength);


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


		if (MH_CreateHookApi(L"Ws2_32", "send", MySend, (LPVOID *)&psend) == MH_OK)
			OutputDebugString("send() detoured successfully");

		if (MH_CreateHookApi(L"Ws2_32", "recv", MyRecv, (LPVOID *)&precv) == MH_OK)
			OutputDebugString("recv() detoured successfully");

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

int WINAPI MySend(SOCKET socket, const char* buffer, int length, int flags)
{
	if(length > MINPACKETLEN)
	{
		LogAndVerboseOutput("MySend", buffer, length);
	}
	return psend(socket, buffer, length, flags);
}

int WINAPI MyWSASend(SOCKET socket, LPWSABUF lpBuffers, DWORD dwBufferCount,
					 LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped,
					 LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	if(lpBuffers->len > MINPACKETLEN)
		LogAndVerboseOutput("MyWSASend", lpBuffers->buf, lpBuffers->len);

	return pWSASend(socket, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
		dwFlags, lpOverlapped, lpCompletionRoutine);
}
int WINAPI MyRecv(SOCKET socket, char* buffer, int length, int flags)
{
	if(length > MINPACKETLEN)
		LogAndVerboseOutput("MyRecv", buffer, length);
	return precv(socket, buffer, length, flags);
}

int WINAPI MyWSARecv(SOCKET socket, LPWSABUF lpBuffers, DWORD dwBufferCount,
					 LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,LPWSAOVERLAPPED lpOverlapped, 
					 LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	if(lpBuffers->len > MINPACKETLEN)
	{
		LogAndVerboseOutput("MyWSARecv", lpBuffers->buf, lpBuffers->len);
	}
	return pWSARecv(socket, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
		lpFlags, lpOverlapped, lpCompletionRoutine);
}

void LogAndVerboseOutput(const char* functionName, const char* buffer, int bufferLength)
{
	if(VERBOSEOUTPUT == 1)
	{
		std::ofstream myFile ("d:\\data.bin", std::ios::app);
		myFile.write(functionName, strlen(functionName));
		myFile << std::endl;
		myFile.write(buffer, bufferLength);
		myFile << std::endl;
	}
}