using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

namespace CS_Ray
{
    /// <summary>
    /// Enforces a single running instance via a <c>Global\</c> named mutex so detection works across elevation
    /// AND sessions — CS-Ray runs elevated (for TUN), and a non-elevated second launch must still detect the
    /// elevated first instance. A second instance broadcasts a registered window message to surface the first,
    /// then exits WITHOUT touching routes/adapter/engine. The OS auto-releases the mutex when the holding process
    /// dies, so a crash never permanently blocks relaunch.
    /// </summary>
    internal static class SingleInstance
    {
        // GUID-suffixed so the names can't collide with anything else on the machine.
        private const string MutexName = @"Global\CS-Ray-SingleInstance-7b1f2c64-9a0e-4d51-8c3a-0f6e2b9d4a11";
        private const string ShowMsgName = "CS-Ray-Show-Existing-7b1f2c64-9a0e-4d51-8c3a-0f6e2b9d4a11";

        private const int HWND_BROADCAST = 0xFFFF;
        private const uint MSGFLT_ALLOW = 1;

        [DllImport("user32.dll", CharSet = CharSet.Auto)] private static extern int RegisterWindowMessage(string lpString);
        [DllImport("user32.dll", CharSet = CharSet.Auto)] private static extern bool PostMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);
        [DllImport("user32.dll")] private static extern bool ChangeWindowMessageFilterEx(IntPtr hWnd, int msg, uint action, IntPtr changeInfo);

        /// <summary>System-wide unique message id used to ask the existing instance to surface its window.</summary>
        public static readonly int ShowMessage = RegisterWindowMessage(ShowMsgName);

        private static Mutex _mutex; // kept alive for the whole process (don't let GC close the handle/free the name)

        /// <summary>True if WE are the first/only instance; false if another instance already holds the mutex.</summary>
        public static bool TryAcquire()
        {
            bool createdNew;
            try
            {
                // Allow Everyone so a non-elevated second launch can OPEN the elevated first instance's mutex
                // (without this ACL the elevated owner's default DACL can deny the medium-IL opener).
                var security = new MutexSecurity();
                security.AddAccessRule(new MutexAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    MutexRights.FullControl, AccessControlType.Allow));
                _mutex = new Mutex(false, MutexName, out createdNew, security);
            }
            catch (UnauthorizedAccessException) { return false; } // it exists (elevated ACL) → already running
            catch
            {
                try { _mutex = new Mutex(false, MutexName, out createdNew); }     // fallback (older OS / no ACL overload)
                catch (UnauthorizedAccessException) { return false; }
                catch { return true; }                                            // never block the app on an odd error
            }
            return createdNew;
        }

        /// <summary>Ask the existing instance to bring its window to the foreground (UIPI-safe broadcast).</summary>
        public static void SignalExisting()
        {
            if (ShowMessage == 0) return;
            try { PostMessage((IntPtr)HWND_BROADCAST, ShowMessage, IntPtr.Zero, IntPtr.Zero); } catch { }
        }

        /// <summary>First (possibly elevated) instance: let the show-message through UIPI from lower-IL senders.</summary>
        public static void AllowSurfaceMessage(IntPtr hwnd)
        {
            if (ShowMessage == 0) return;
            try { ChangeWindowMessageFilterEx(hwnd, ShowMessage, MSGFLT_ALLOW, IntPtr.Zero); } catch { }
        }

        public static void Release()
        {
            try { _mutex?.Dispose(); } catch { }
            _mutex = null;
        }
    }
}
