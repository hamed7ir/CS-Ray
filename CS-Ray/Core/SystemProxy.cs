using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace CS_Ray.Core
{
    /// <summary>
    /// Sets/clears the Windows system proxy (WinINET) so OS/browser traffic routes through
    /// CS-Ray's local SOCKS port. Snapshots the user's PRIOR settings on first Set and restores
    /// them on Clear — static state so the crash/close handlers can always restore.
    /// SOCKS-only: covers WinINET apps (browsers); not every app honors it.
    /// </summary>
    public static class SystemProxy
    {
        [DllImport("wininet.dll", SetLastError = true)]
        private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

        private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
        private const int INTERNET_OPTION_REFRESH = 37;
        private const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        private const string Bypass = "<local>;localhost;127.*;10.*;172.16.*;192.168.*";

        private static readonly object Gate = new object();
        private static bool _applied;
        private static object _priorEnable;     // boxed int (DWORD), or null if absent
        private static string _priorServer;     // null if absent
        private static string _priorOverride;   // null if absent

        public static bool IsApplied { get { lock (Gate) return _applied; } }

        /// <summary>Route the system proxy through socks=127.0.0.1:port (snapshots prior state once).</summary>
        public static void Set(int port)
        {
            lock (Gate)
            {
                using (var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true))
                {
                    if (key == null) return;

                    if (!_applied)
                    {
                        _priorEnable = key.GetValue("ProxyEnable");
                        _priorServer = key.GetValue("ProxyServer") as string;
                        _priorOverride = key.GetValue("ProxyOverride") as string;
                    }

                    // HTTP/HTTPS for WinINET/Chromium apps (WinINET socks= is only SOCKS4); keep socks= for SOCKS5 apps.
                    var value = "http=127.0.0.1:" + port + ";https=127.0.0.1:" + port + ";socks=127.0.0.1:" + port;
                    key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                    key.SetValue("ProxyServer", value, RegistryValueKind.String);
                    key.SetValue("ProxyOverride", Bypass, RegistryValueKind.String);
                }
                _applied = true;
                Refresh();
            }
        }

        /// <summary>Restore the user's prior proxy settings (no-op if we never changed them).</summary>
        public static void Clear()
        {
            lock (Gate)
            {
                if (!_applied) return; // never touched it — don't clobber anything

                using (var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true))
                {
                    if (key != null)
                    {
                        key.SetValue("ProxyEnable", _priorEnable != null ? Convert.ToInt32(_priorEnable) : 0, RegistryValueKind.DWord);

                        if (_priorServer != null) key.SetValue("ProxyServer", _priorServer, RegistryValueKind.String);
                        else key.DeleteValue("ProxyServer", throwOnMissingValue: false);

                        if (_priorOverride != null) key.SetValue("ProxyOverride", _priorOverride, RegistryValueKind.String);
                        else key.DeleteValue("ProxyOverride", throwOnMissingValue: false);
                    }
                }
                _applied = false;
                _priorEnable = null; _priorServer = null; _priorOverride = null;
                Refresh();
            }
        }

        private static void Refresh()
        {
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }
    }
}
