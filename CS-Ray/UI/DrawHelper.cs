using System;
using System.Drawing;
using System.Drawing.Drawing2D;

namespace CS_Ray.UI
{
    /// <summary>Small shared GDI+ helpers for CS-Ray's owner-drawn controls (toggle, drawer, settings cards).</summary>
    internal static class DrawHelper
    {
        /// <summary>A rounded-rectangle path; a radius of height/2 yields a pill / stadium.</summary>
        public static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            int d = Math.Max(1, radius) * 2;
            if (d > r.Width) d = Math.Max(1, r.Width);
            if (d > r.Height) d = Math.Max(1, r.Height);
            var path = new GraphicsPath();
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        /// <summary>Linear blend a→b by t in [0,1] (opaque).</summary>
        public static Color Blend(Color a, Color b, float t)
            => Color.FromArgb(
                (int)(a.R + (b.R - a.R) * t),
                (int)(a.G + (b.G - a.G) * t),
                (int)(a.B + (b.B - a.B) * t));
    }
}
