using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using CS_Ray.UI;

namespace CS_Ray
{
    static class Program
    {
        // System-DPI awareness (value 1). Per-monitor (2) double-scales with manual math
        // and isn't supported on the target OSes — use system DPI + AutoScaleMode.Font.
        [DllImport("shcore.dll")]
        private static extern int SetProcessDpiAwareness(int value);

        [STAThread]
        static void Main(string[] args)
        {
            // Single-instance (leak safety: two route-managers = leak risk). If another instance already holds the
            // Global\ mutex, surface IT and exit immediately — touch NO routes/adapter/engine on the way out.
            if (!SingleInstance.TryAcquire())
            {
                SingleInstance.SignalExisting();
                return;
            }

            try { SetProcessDpiAwareness(1); } catch { /* shcore absent on older OS; ignore */ }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Surface crashes instead of vanishing silently (lesson from the sister project).
            // Always restore the system proxy first so a crash can't leave the OS pointed at a dead port.
            Application.ThreadException += (s, e) =>
            {
                try { Core.Tun.TunNetwork.RestoreActive(); } catch { }
                try { Core.Tun.TunDevice.StopActive(); } catch { }
                try { Core.SystemProxy.Clear(); } catch { }
                MessageBox.Show(e.Exception.ToString(), "CS-Ray — UI exception");
            };
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                try { Core.Tun.TunNetwork.RestoreActive(); } catch { }
                try { Core.Tun.TunDevice.StopActive(); } catch { }
                try { Core.SystemProxy.Clear(); } catch { }
                MessageBox.Show((e.ExceptionObject as Exception)?.ToString() ?? "unknown", "CS-Ray — fatal");
            };

            var form = new MainForm();
            if (args != null && Array.IndexOf(args, "--autostart") >= 0)
            {
                form.FileLogging = true; // mirror logs to %TEMP%\csray.log for headless inspection
                form.Shown += (s, e) => form.AutoStart();
            }
            try { Application.Run(form); }
            finally
            {
                try { Core.Tun.TunNetwork.RestoreActive(); } catch { }
                try { Core.Tun.TunDevice.StopActive(); } catch { }
                try { Core.SystemProxy.Clear(); } catch { }
                SingleInstance.Release();
            }
        }
    }
}
