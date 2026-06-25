using System;
using System.Drawing;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// A ContextMenuStrip themed entirely from <see cref="ThemeHelper"/> (ported from TelegArm): background/text
    /// follow dark/light, the hover/selected highlight is the Windows accent, separators and borders are derived
    /// shades. A single shared renderer on <see cref="ToolStripManager"/> themes sub-menus too. Re-themes live on
    /// <see cref="ThemeHelper.ThemeChanged"/>; unsubscribes on dispose. Used for the ☰ dropdown and tab menus.
    /// </summary>
    public class ThemedContextMenuStrip : ContextMenuStrip
    {
        static ThemedContextMenuStrip()
        {
            ToolStripManager.Renderer = new ThemedMenuRenderer(); // one renderer for ALL menus + sub-menus
        }

        public ThemedContextMenuStrip()
        {
            RenderMode = ToolStripRenderMode.ManagerRenderMode;
            Font = FontHelper.Ui(9.5f);
            BackColor = ThemedMenuColors.Background;
            ForeColor = ThemedMenuColors.Text;
            ThemeHelper.ThemeChanged += OnThemeChanged;
        }

        private void OnThemeChanged()
        {
            if (IsDisposed) return;
            try
            {
                BeginInvoke((Action)(() =>
                {
                    BackColor = ThemedMenuColors.Background;
                    ForeColor = ThemedMenuColors.Text;
                    Invalidate(true);
                }));
            }
            catch { }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) ThemeHelper.ThemeChanged -= OnThemeChanged;
            base.Dispose(disposing);
        }
    }

    /// <summary>Menu palette derived from ThemeHelper (no hard-coded theme colors).</summary>
    internal static class ThemedMenuColors
    {
        public static bool Dark => ThemeHelper.IsDark;
        public static Color Background => Dark ? Color.FromArgb(43, 43, 46) : Color.FromArgb(245, 245, 247);
        public static Color Text => Dark ? Color.FromArgb(235, 235, 235) : Color.FromArgb(25, 25, 25);
        public static Color Disabled => Dark ? Color.FromArgb(120, 120, 120) : Color.FromArgb(165, 165, 165);
        public static Color Accent => ThemeHelper.GetWindowsAccentColor();
        public static Color Highlight => Blend(Accent, Background, Dark ? 0.42f : 0.28f);
        public static Color Border => Blend(Background, Dark ? Color.White : Color.Black, 0.16f);

        public static Color Blend(Color a, Color b, float t)
            => Color.FromArgb(
                (int)(a.R * t + b.R * (1 - t)),
                (int)(a.G * t + b.G * (1 - t)),
                (int)(a.B * t + b.B * (1 - t)));
    }

    /// <summary>ProfessionalColorTable whose colors all come from <see cref="ThemedMenuColors"/>.</summary>
    internal sealed class ThemedColorTable : ProfessionalColorTable
    {
        public ThemedColorTable() { UseSystemColors = false; }

        public override Color ToolStripDropDownBackground => ThemedMenuColors.Background;
        public override Color ImageMarginGradientBegin => ThemedMenuColors.Background;
        public override Color ImageMarginGradientMiddle => ThemedMenuColors.Background;
        public override Color ImageMarginGradientEnd => ThemedMenuColors.Background;
        public override Color MenuBorder => ThemedMenuColors.Border;
        public override Color MenuItemBorder => ThemedMenuColors.Accent;
        public override Color MenuItemSelected => ThemedMenuColors.Highlight;
        public override Color MenuItemSelectedGradientBegin => ThemedMenuColors.Highlight;
        public override Color MenuItemSelectedGradientEnd => ThemedMenuColors.Highlight;
        public override Color MenuItemPressedGradientBegin => ThemedMenuColors.Highlight;
        public override Color MenuItemPressedGradientEnd => ThemedMenuColors.Highlight;
        public override Color SeparatorDark => ThemedMenuColors.Border;
        public override Color SeparatorLight => ThemedMenuColors.Border;
        public override Color CheckBackground => ThemedMenuColors.Highlight;
        public override Color CheckSelectedBackground => ThemedMenuColors.Highlight;
        public override Color CheckPressedBackground => ThemedMenuColors.Highlight;
    }

    /// <summary>Renderer that paints item text in the themed color (and dims disabled items).</summary>
    internal sealed class ThemedMenuRenderer : ToolStripProfessionalRenderer
    {
        public ThemedMenuRenderer() : base(new ThemedColorTable()) { RoundedEdges = false; }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = e.Item.Enabled ? ThemedMenuColors.Text : ThemedMenuColors.Disabled;
            base.OnRenderItemText(e);
        }
    }
}
