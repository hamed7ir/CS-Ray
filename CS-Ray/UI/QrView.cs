using System;
using System.Drawing;
using System.Windows.Forms;
using QRCoder;

namespace CS_Ray.UI
{
    /// <summary>
    /// Draws a QR code for a text (ported from TelegArm's QrControl). QRCoder only computes the module matrix (pure
    /// managed, fine on ARM32); the modules are painted here with GDI+, black on white whatever the theme, because a
    /// tinted QR often doesn't scan. Each module is a whole number of pixels so phone cameras read it cleanly. The
    /// matrix includes the 4-module quiet zone. Nothing is ever written to disk: the payload is a secret.
    /// </summary>
    public sealed class QrView : Control
    {
        private bool[,] _matrix;
        private int _n;

        public QrView()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer
                     | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Color.White;
            ForeColor = Color.Black;
        }

        /// <summary>False when the text didn't fit in a QR code (over about 2.3 KB at this error correction level).</summary>
        public bool HasCode => _matrix != null;

        /// <summary>Modules per side, quiet zone included (0 without a code).</summary>
        public int ModuleCount => _matrix == null ? 0 : _n;

        /// <summary>Encodes <paramref name="text"/> and repaints.</summary>
        public void SetPayload(string text)
        {
            _matrix = null;
            if (!string.IsNullOrEmpty(text))
            {
                try
                {
                    using (var gen = new QRCodeGenerator())
                    using (var data = gen.CreateQrCode(text, QRCodeGenerator.ECCLevel.M))
                    {
                        var mm = data.ModuleMatrix;
                        _n = mm.Count;
                        var m = new bool[_n, _n];
                        for (int r = 0; r < _n; r++)
                            for (int c = 0; c < _n; c++)
                                m[r, c] = mm[r][c];
                        _matrix = m;
                    }
                }
                catch (Exception)
                {
                    _matrix = null;   // too long for a QR code
                }
            }
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(BackColor);
            var m = _matrix;
            if (m == null) return;
            int side = Math.Min(Width, Height);
            int cell = Math.Max(1, side / _n);
            int size = cell * _n;
            int ox = (Width - size) / 2, oy = (Height - size) / 2;
            using (var b = new SolidBrush(ForeColor))
                for (int r = 0; r < _n; r++)
                    for (int c = 0; c < _n; c++)
                        if (m[r, c]) g.FillRectangle(b, ox + c * cell, oy + r * cell, cell, cell);
        }
    }
}
