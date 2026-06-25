using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// Adds finger-friendly touch to a control by handling raw <c>WM_TOUCH</c> (Win7+, incl. RT 8.1 / Win10
    /// ARM32). Because we register for touch and CONSUME the message, Windows does NOT promote it to the
    /// (unreliable) synthesized mouse / press-and-hold-right-click — so touch and mouse stay fully separate and
    /// the mouse paths are untouched. Distinguishes, from one primary contact:
    ///   • TAP        — down→up with no movement past the threshold (→ <c>onTap</c>, e.g. select a row)
    ///   • LONG-PRESS — held still ~500ms with no movement      (→ <c>onLongPress</c>, e.g. open the menu)
    ///   • DRAG       — moved past the threshold                (→ <c>scrollByFingerDy</c>, pan the content)
    /// Attach one per touch-scrollable control; chains over any existing NativeWindow (e.g. ThemedScrollBar's).
    /// </summary>
    internal sealed class TouchScroller : NativeWindow, IDisposable
    {
        private const int WM_TOUCH = 0x0240;
        private const int TOUCHEVENTF_MOVE = 0x0001, TOUCHEVENTF_DOWN = 0x0002, TOUCHEVENTF_UP = 0x0004;
        private const int LongPressMs = 500;

        [DllImport("user32.dll")] private static extern bool RegisterTouchWindow(IntPtr hWnd, uint ulFlags);
        [DllImport("user32.dll")] private static extern bool UnregisterTouchWindow(IntPtr hWnd);
        [DllImport("user32.dll")] private static extern bool GetTouchInputInfo(IntPtr hTouchInput, uint cInputs, [Out] TOUCHINPUT[] pInputs, int cbSize);
        [DllImport("user32.dll")] private static extern bool CloseTouchInputHandle(IntPtr hTouchInput);

        [StructLayout(LayoutKind.Sequential)]
        private struct TOUCHINPUT
        {
            public int x, y;            // 0.01-pixel SCREEN coords
            public IntPtr hSource;
            public int dwID, dwFlags, dwMask, dwTime;
            public IntPtr dwExtraInfo;
            public int cxContact, cyContact;
        }

        private readonly Control _target;
        private readonly Action<int> _scrollByFinger;    // finger Δ along the scroll axis → pan content
        private readonly Action<Point> _onTap;
        private readonly Action<Point> _onLongPress;
        private readonly bool _horz;                      // true = horizontal scroll axis (tab strip)
        private readonly Timer _longPress;
        private readonly int _threshold;

        private int _contactId = -1;
        private Point _start, _last;
        private bool _moved, _fired;

        public TouchScroller(Control target, Action<int> scrollByFinger, Action<Point> onTap, Action<Point> onLongPress, bool horizontal = false)
        {
            _target = target;
            _scrollByFinger = scrollByFinger;
            _onTap = onTap;
            _onLongPress = onLongPress;
            _horz = horizontal;
            _threshold = Math.Max(16, SystemInformation.DragSize.Height * 2); // finger wobble tolerance

            _longPress = new Timer { Interval = LongPressMs };
            _longPress.Tick += (s, e) =>
            {
                _longPress.Stop();
                if (!_moved && _contactId != -1) { _fired = true; _onLongPress?.Invoke(_start); }
            };

            if (target.IsHandleCreated) Attach();
            target.HandleCreated += (s, e) => Attach();
            target.HandleDestroyed += (s, e) => Detach();
        }

        private void Attach()
        {
            try { RegisterTouchWindow(_target.Handle, 0); } catch { } // no-op/false on non-touch hardware
            try { AssignHandle(_target.Handle); } catch { }
        }

        private void Detach()
        {
            try { UnregisterTouchWindow(_target.Handle); } catch { }
            try { ReleaseHandle(); } catch { }
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_TOUCH && HandleTouch(ref m)) { m.Result = (IntPtr)1; return; } // consumed → no mouse promotion
            base.WndProc(ref m);
        }

        private bool HandleTouch(ref Message m)
        {
            int n = (int)(m.WParam.ToInt64() & 0xFFFF);
            if (n <= 0) return false;
            var inputs = new TOUCHINPUT[n];
            if (!GetTouchInputInfo(m.LParam, (uint)n, inputs, Marshal.SizeOf(typeof(TOUCHINPUT)))) return false;
            try
            {
                foreach (var ti in inputs)
                {
                    var client = _target.PointToClient(new Point(ti.x / 100, ti.y / 100));

                    if ((ti.dwFlags & TOUCHEVENTF_DOWN) != 0)
                    {
                        if (_contactId != -1) continue;       // ignore additional fingers (single-touch pan)
                        _contactId = ti.dwID; _start = _last = client; _moved = false; _fired = false;
                        _longPress.Start();
                    }
                    else if (ti.dwID != _contactId) continue;  // not our tracked contact

                    else if ((ti.dwFlags & TOUCHEVENTF_MOVE) != 0)
                    {
                        if (_fired) { _last = client; continue; } // already became a menu → ignore drift
                        int movedBy = _horz ? client.X - _start.X : client.Y - _start.Y;
                        if (!_moved)
                        {
                            if (Math.Abs(movedBy) > _threshold) { _moved = true; _longPress.Stop(); _last = client; }
                        }
                        else
                        {
                            int d = _horz ? client.X - _last.X : client.Y - _last.Y;
                            if (d != 0) { _scrollByFinger?.Invoke(d); _last = client; }
                        }
                    }
                    else if ((ti.dwFlags & TOUCHEVENTF_UP) != 0)
                    {
                        _longPress.Stop();
                        if (!_moved && !_fired) _onTap?.Invoke(_start); // a clean tap
                        _contactId = -1;
                    }
                }
            }
            finally { CloseTouchInputHandle(m.LParam); }
            return true;
        }

        public void Dispose()
        {
            try { _longPress.Dispose(); } catch { }
            Detach();
        }
    }
}
