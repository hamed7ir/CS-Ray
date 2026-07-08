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
            // ── ON-DEMAND ELEVATION take-over ─────────────────────────────────────────────────────────────────
            // A --elevated-start-tun launch is the app relaunching ITSELF elevated (from MainForm.ElevateForTun) to
            // start TUN. Unlike a normal 2nd launch (which surfaces the 1st and exits), it must TAKE OVER: WAIT for
            // the outgoing un-elevated instance to release the single-instance mutex — which it does only after
            // stopping its engine, so the inbound port is free — then own it. The mutex doubles as the port-hand-off
            // token.
            bool elevatedStartTun = args != null && Array.IndexOf(args, "--elevated-start-tun") >= 0;
            bool tookOver = false;

            if (elevatedStartTun)
            {
                tookOver = SingleInstance.TryAcquireWaiting(10000); // ~10s for the outgoing instance to release
                // If it never freed, we still come up below but show a message and do NOT auto-start TUN (binding
                // 127.0.0.1:10810 would likely fail while the old instance lingers).
            }
            else if (!SingleInstance.TryAcquire())
            {
                // Single-instance (leak safety: two route-managers = leak risk). Another instance holds the mutex →
                // surface IT and exit immediately — touch NO routes/adapter/engine on the way out.
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
            // START-AT-LOGIN: launched from the HKCU Run key at login → start minimized to the tray (quiet).
            if (args != null && Array.IndexOf(args, "--startup") >= 0)
                form.StartInTray = true;

            // ELEVATED TAKE-OVER: reconstruct the intended state on the elevated instance and start TUN. The server
            // is identified by an EXPLICIT --profile <id> (source of truth); ActiveProfileId is only the fallback.
            if (elevatedStartTun)
            {
                if (tookOver)
                {
                    string profileId = GetArgValue(args, "--profile");
                    bool fullTunnel = Array.IndexOf(args, "--full-tunnel") >= 0;
                    bool systemProxy = Array.IndexOf(args, "--system-proxy") >= 0;
                    form.Shown += (s, e) => form.ElevatedStartTun(profileId, fullTunnel, systemProxy);
                }
                else
                {
                    // Took too long to hand off → don't blindly start TUN; come up and tell the user to exit fully.
                    form.Shown += (s, e) => form.ShowTakeoverFailed();
                }
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

        /// <summary>Returns the value following <paramref name="name"/> in <paramref name="args"/> (e.g. the id after
        /// "--profile"), or null if absent. Used to pass the intended profile to the elevated take-over instance.</summary>
        private static string GetArgValue(string[] args, string name)
        {
            if (args == null) return null;
            for (int i = 0; i < args.Length - 1; i++)
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                    return args[i + 1];
            return null;
        }
    }
}
