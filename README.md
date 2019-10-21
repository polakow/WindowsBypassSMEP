# WindowsSMEPBypass
Example of SMEP bypass in Windows 10 1709 for Paged Out.

# Brief description

Vulnerability: Stack based overflow in a third-party driver.

1)Leak ntoskrnl address
        NtSystemQueryInformation
2)Setup payload
    2.1) ROP payload
        Description of the payload in Paged Out ezine. Offsets of gadgets are in main.c
    2.2) Payload
        We are going to elevate our privileges, so our payload is Token Stealer. It is in payload.asm
3)Trigger vuln
        DeviceIoControl

# Important

You need a vulnerable driver to test this. You can make your own or find some vulnerable. You can check HEVD(Hacksys Extreme Vulnerable Driver).
