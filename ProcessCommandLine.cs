namespace CupofTEA
{
    using System;
    using System.Runtime.InteropServices;
    using System.Text;

    public class ProcessCommandLine
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCommandLine();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            QueryLimitedInformation = 0x00001000
        }

        public static string GetCommandLineForProcess(int processId)
        {
            IntPtr hProcess = OpenProcess(ProcessAccessFlags.QueryLimitedInformation, false, processId);
            if (hProcess == IntPtr.Zero)
            {
                throw new Exception("Failed to open process.");
            }

            try
            {
                StringBuilder sb = new StringBuilder(1024);
                uint bufferLength = (uint)sb.Capacity;
                if (!QueryFullProcessImageName(hProcess, 0, sb, ref bufferLength))
                {
                    throw new Exception("Failed to get process name.");
                }

                string imagePath = sb.ToString();

                // Get the address of the NtQueryInformationProcess function
                IntPtr ntdll = GetModuleHandle("ntdll.dll");
                IntPtr ntQueryInformationProcessAddr = GetProcAddress(ntdll, "NtQueryInformationProcess");

                if (ntQueryInformationProcessAddr == IntPtr.Zero)
                {
                    throw new Exception("Failed to get NtQueryInformationProcess address.");
                }

                // Define the delegate for NtQueryInformationProcess
                NtQueryInformationProcessDelegate ntQueryInformationProcess =
                    Marshal.GetDelegateForFunctionPointer<NtQueryInformationProcessDelegate>(
                        ntQueryInformationProcessAddr);

                PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                uint returnLength = 0;

                int status = ntQueryInformationProcess(hProcess, 0, ref pbi, (uint)Marshal.SizeOf(pbi), ref returnLength);

                if (status != 0)
                {
                    throw new Exception("NtQueryInformationProcess failed.");
                }

                IntPtr pebAddress = pbi.PebBaseAddress;
                IntPtr rtlUserProcParamsAddress = Marshal.ReadIntPtr(pebAddress, 0x20);
                IntPtr commandLineAddress = Marshal.ReadIntPtr(rtlUserProcParamsAddress, 0x70);

                string commandLine = Marshal.PtrToStringUni(commandLineAddress);

                return commandLine;
            }
            finally
            {
                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                }
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }

        private delegate int NtQueryInformationProcessDelegate(
            IntPtr ProcessHandle,
            int ProcessInformationClass,
            ref PROCESS_BASIC_INFORMATION ProcessInformation,
            uint ProcessInformationLength,
            ref uint ReturnLength);
    }
}
