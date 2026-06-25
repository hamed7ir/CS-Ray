using System;
using System.Drawing;
using System.Drawing.Text;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CS_Ray.UI
{
    /// <summary>
    /// Bundles Roboto (MaterialSkin's intended typeface) as embedded fonts loaded into a process-wide
    /// <see cref="PrivateFontCollection"/>, so the GUI renders in Roboto without installing fonts. Ported from
    /// TelegArm's FontHelper: GDI+ does NOT copy the buffer passed to AddMemoryFont, so the native buffer must
    /// stay allocated for the app's lifetime (we intentionally never free it). Falls back to Segoe UI on failure.
    /// </summary>
    public static class FontHelper
    {
        private static readonly PrivateFontCollection _pfc = new PrivateFontCollection();
        private static FontFamily _ui;

        static FontHelper()
        {
            try
            {
                AddFont("CS_Ray.Fonts.Roboto-Regular.ttf");
                AddFont("CS_Ray.Fonts.Roboto-Medium.ttf");
                AddFont("CS_Ray.Fonts.Roboto-Bold.ttf");
                _ui = Find("Roboto");
            }
            catch { /* fall back to Segoe UI in Make() */ }
        }

        /// <summary>True once Roboto loaded (else we fall back to Segoe UI).</summary>
        public static bool RobotoLoaded => _ui != null;

        /// <summary>A Roboto font at the given size/style, or Segoe UI if Roboto is unavailable.</summary>
        public static Font Ui(float size, FontStyle style = FontStyle.Regular) => Make(_ui, size, style);

        private static Font Make(FontFamily family, float size, FontStyle style)
        {
            try { if (family != null) return new Font(family, size, style); } catch { }
            try { if (family != null) return new Font(family, size, FontStyle.Regular); } catch { }
            return new Font("Segoe UI", size, style);
        }

        private static void AddFont(string resourceName)
        {
            var asm = Assembly.GetExecutingAssembly();
            using (var s = asm.GetManifestResourceStream(resourceName))
            {
                if (s == null) return;
                var data = new byte[s.Length];
                int read = 0;
                while (read < data.Length)
                {
                    int n = s.Read(data, read, data.Length - read);
                    if (n <= 0) break;
                    read += n;
                }
                // GDI+ keeps a pointer to this buffer — keep it allocated for the app's life (never freed).
                IntPtr p = Marshal.AllocCoTaskMem(data.Length);
                Marshal.Copy(data, 0, p, data.Length);
                _pfc.AddMemoryFont(p, data.Length);
            }
        }

        private static FontFamily Find(string namePart)
        {
            foreach (var f in _pfc.Families)
                if (f.Name.IndexOf(namePart, StringComparison.OrdinalIgnoreCase) >= 0) return f;
            return null;
        }
    }
}
