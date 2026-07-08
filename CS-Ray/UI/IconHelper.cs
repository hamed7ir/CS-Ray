using System.Drawing;
using System.Reflection;

namespace CS_Ray.UI
{
    /// <summary>
    /// Loads + caches the app's embedded .ico resources once. <see cref="App"/> (icon.ico) is the window/app icon for
    /// every Form AND the IDLE tray icon; <see cref="SystemProxy"/> / <see cref="FullTunnel"/> are the mode-specific
    /// tray icons resolved by MainForm.ResolveTrayIcon. Icons copy their data out of the stream on construction, so
    /// the stream is disposed immediately. Any load failure returns null (callers fall back).
    /// </summary>
    internal static class IconHelper
    {
        private static Icon _app, _sysProxy, _fullTunnel;

        /// <summary>icon.ico — the app / window icon for ALL forms, and the idle tray icon.</summary>
        public static Icon App => _app ?? (_app = Load("icon.ico"));

        /// <summary>icon-systemproxy.ico — tray icon when system-proxy is ON and TUN is OFF.</summary>
        public static Icon SystemProxy => _sysProxy ?? (_sysProxy = Load("icon-systemproxy.ico"));

        /// <summary>icon-fulltunnel.ico — tray icon when TUN / full-tunnel is ON (wins over system-proxy).</summary>
        public static Icon FullTunnel => _fullTunnel ?? (_fullTunnel = Load("icon-fulltunnel.ico"));

        private static Icon Load(string name)
        {
            try
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("CS_Ray.icon." + name))
                    return s != null ? new Icon(s) : null;
            }
            catch { return null; }
        }
    }
}
