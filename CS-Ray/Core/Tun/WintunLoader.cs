using System;
using System.IO;
using System.Runtime.InteropServices;

namespace CS_Ray.Core.Tun
{
    /// <summary>
    /// Loads the architecture-correct wintun.dll BEFORE any wintun P/Invoke, from
    /// <c>&lt;exe&gt;\wintun\&lt;arch&gt;\wintun.dll</c>. If the matching DLL is missing, TUN is disabled
    /// gracefully (logged, no crash) — same fallback discipline as the VLC loader in the sister project.
    /// </summary>
    public static class WintunLoader
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        private static IntPtr _handle;

        public static bool Available { get; private set; }
        public static string Status { get; private set; }

        /// <summary>Process-architecture subfolder name: x86 / arm / arm64 / amd64.</summary>
        public static string ArchFolder()
        {
            bool is64 = IntPtr.Size == 8;
            var pa = (Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") ?? "").ToUpperInvariant();
            if (is64) return pa == "ARM64" ? "arm64" : "amd64";
            // 32-bit process: ARM32 Windows reports "ARM"; x86 (incl. WOW64 / arm64-x86-emulation) reports "x86".
            return pa == "ARM" ? "arm" : "x86";
        }

        public static bool EnsureLoaded(Action<string> log)
        {
            if (Available) return true;
            try
            {
                var arch = ArchFolder();
                var dll = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wintun", arch, "wintun.dll");
                if (!File.Exists(dll))
                {
                    Status = "wintun.dll for arch '" + arch + "' not found at " + dll;
                    log?.Invoke("TUN disabled: " + Status);
                    return false;
                }

                _handle = LoadLibrary(dll);
                if (_handle == IntPtr.Zero)
                {
                    int e = Marshal.GetLastWin32Error();
                    Status = "LoadLibrary failed (" + e + " — " + new System.ComponentModel.Win32Exception(e).Message + ") for " + dll;
                    log?.Invoke("TUN disabled: " + Status);
                    return false;
                }

                Available = true;
                Status = "wintun.dll loaded (" + arch + ")";
                log?.Invoke("TUN: " + Status + ".");
                return true;
            }
            catch (Exception ex)
            {
                Status = "loader error: " + ex.Message;
                log?.Invoke("TUN disabled: " + Status);
                return false;
            }
        }
    }
}
