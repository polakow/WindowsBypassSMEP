# WindowsSMEPBypass
Example of SMEP bypass in Windows 10 1709 for Paged Out.

# Brief description

Vulnerability: Stack based overflow in a third-party driver.

1. **Leak ntoskrnl address**
    - *NtQuerySystemInformation*
2. **Setup payload**
    - *ROP payload*: Description of the payload is in Paged Out #2 ezine. Offsets of gadgets are in main.c
    - *Payload*: We want to elevate our privileges, so our payload is Token Stealer. It is in payload.asm
3. **Trigger vuln**
    - *DeviceIoControl*

# Important

You need a vulnerable driver to test this. You can make your own or find some vulnerable. You can check HEVD(Hacksys Extreme Vulnerable Driver).
