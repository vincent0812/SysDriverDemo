#include "SampleDriver.h"

#define DEVICE_NAME L"\\Device\\DemoDevice"
#define SYMBOLIC_NAME L"\\DosDevices\\DemoDevice"

// Driver unload routine
void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicName;
    RtlInitUnicodeString(&symbolicName, SYMBOLIC_NAME);
    IoDeleteSymbolicLink(&symbolicName);
    IoDeleteDevice(DriverObject->DeviceObject);
    KdPrint(("Driver unloaded\n"));
}

// Handle create and close operations
NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


// Handle read operations
NTSTATUS DriverRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG length = stack->Parameters.Read.Length;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    // Simulate read data
    RtlFillMemory(buffer, length, 'A');
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = length;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Handle write operations
NTSTATUS DriverWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG length = stack->Parameters.Write.Length;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    // Simulate write data (no actual operation performed)
    KdPrint(("Data written: %.*s\n", length, (char*)buffer));
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = length;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


// The dispatch function for handling IRP_MJ_DEVICE_CONTROL
NTSTATUS MyDeviceControlRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG outputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PREAD_PORT_INPUT readPortInput;
    USHORT port;
    ULONG bufferSize;
    UCHAR byte;
    PWRITE_PORT_INPUT writePortInput;
    UCHAR value;
    PREAD_MEMORY_INPUT readMemoryInput;
    PHYSICAL_ADDRESS address;
    ULONG size;
    PVOID mappedAddress;
    PWRITE_MEMORY_INPUT writeMemoryInput;    
    
    switch (controlCode) {
        case IOCTL_READ_IO_PORT_BYTE:
            // Handle the custom operation
            // For example, you could read input from the user buffer and write output to the user buffer
            // ...
            if (inputBufferLength < sizeof(READ_PORT_INPUT) || outputBufferLength < sizeof(UCHAR)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            readPortInput = (PREAD_PORT_INPUT)inputBuffer;
            port = readPortInput->Port;
            bufferSize = readPortInput->BufferSize;

            // Ensure bufferSize is valid if needed
            if (bufferSize < sizeof(UCHAR)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            byte = ReadByteFromPort(port);
            *(UCHAR *)outputBuffer = byte;
            Irp->IoStatus.Information = sizeof(UCHAR);
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_WRITE_IO_PORT_BYTE:
            // Handle the custom operation
            // For example, you could read input from the user buffer and write output to the user buffer
            // ...
            if (inputBufferLength < sizeof(WRITE_PORT_INPUT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            writePortInput = (PWRITE_PORT_INPUT)inputBuffer;
            port = writePortInput->Port;
            value = writePortInput->Value;

            WriteByteToPort(port, value);
            Irp->IoStatus.Information = 0;
            status = STATUS_SUCCESS;
            break;
            
        case IOCTL_READ_MEMORY:
            // Handle the custom operation
            // For example, you could read input from the user buffer and write output to the user buffer
            // ...
            if (inputBufferLength < sizeof(READ_MEMORY_INPUT) || outputBufferLength < sizeof(UCHAR)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            readMemoryInput = (PREAD_MEMORY_INPUT)inputBuffer;
            address = readMemoryInput->PhysicalAddress;
            size = readMemoryInput->Size;

            // Ensure the size is valid and the output buffer is large enough
            if (size > outputBufferLength) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

						mappedAddress = MmMapIoSpace(address, size, MmNonCached);
						
            __try {
                // Copy memory from the mapped address to the output buffer
                RtlCopyMemory(outputBuffer, mappedAddress, size);
                Irp->IoStatus.Information = size;
                status = STATUS_SUCCESS;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }
            
            MmUnmapIoSpace(mappedAddress, size);
            break;
            
        case IOCTL_WRITE_MEMORY:
            // Handle the custom operation
            // For example, you could read input from the user buffer and write output to the user buffer
            // ...
            if (inputBufferLength < sizeof(WRITE_MEMORY_INPUT)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            writeMemoryInput = (PWRITE_MEMORY_INPUT)inputBuffer;
            address = writeMemoryInput->PhysicalAddress;
            size = writeMemoryInput->Size;

            // Ensure the size is valid and the input buffer is large enough
            if (inputBufferLength < sizeof(WRITE_MEMORY_INPUT) + size - 1) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            mappedAddress = MmMapIoSpace(address, size, MmNonCached);
            if (mappedAddress == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            __try {
                // Copy data from the input buffer to the mapped address
                RtlCopyMemory(mappedAddress, writeMemoryInput->Data, size);
                status = STATUS_SUCCESS;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }

            MmUnmapIoSpace(mappedAddress, size);
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {

    NTSTATUS status;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING deviceName, symbolicName;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symbolicName, SYMBOLIC_NAME);

    // Create the device
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &DeviceObject);

    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to create device (0x%08X)\n", status));
        return status;
    }

    // Create the symbolic link
    status = IoCreateSymbolicLink(&symbolicName, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to create symbolic link (0x%08X)\n", status));
        IoDeleteDevice(DeviceObject);
        return status;
    }

    // Initialize the driver object with this driver's entry points
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDeviceControlRoutine;

    KdPrint(("Driver loaded successfully\n"));
    return STATUS_SUCCESS;
}



