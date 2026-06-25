using System;
using System.Runtime.InteropServices;

namespace CS_Ray.Core.Tun
{
    internal enum WintunLoggerLevel { Info = 0, Warn = 1, Err = 2 }

    // CALLBACK == __stdcall; level enum, DWORD64 timestamp, LPCWSTR message.
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    internal delegate void WintunLoggerCallback(WintunLoggerLevel level, ulong timestamp,
        [MarshalAs(UnmanagedType.LPWStr)] string message);

    /// <summary>
    /// P/Invoke for the wintun 0.14.x API (signatures per wintun\include\wintun.h: WINAPI/stdcall,
    /// LPCWSTR, const GUID* → ref Guid). The DLL is loaded arch-correctly by <see cref="WintunLoader"/>
    /// before any of these are called, so lazy "wintun.dll" resolution binds to the right module.
    /// </summary>
    internal static class WintunApi
    {
        private const string Dll = "wintun.dll";
        private const CallingConvention Cc = CallingConvention.StdCall;

        [DllImport(Dll, CallingConvention = Cc, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WintunCreateAdapter(
            [MarshalAs(UnmanagedType.LPWStr)] string name,
            [MarshalAs(UnmanagedType.LPWStr)] string tunnelType,
            ref Guid requestedGuid);

        [DllImport(Dll, CallingConvention = Cc, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WintunOpenAdapter([MarshalAs(UnmanagedType.LPWStr)] string name);

        [DllImport(Dll, CallingConvention = Cc, SetLastError = true)]
        public static extern void WintunCloseAdapter(IntPtr adapter);

        // NET_LUID is a 64-bit value; 'out ulong' receives it for the IP Helper conversions.
        [DllImport(Dll, CallingConvention = Cc, SetLastError = true)]
        public static extern void WintunGetAdapterLUID(IntPtr adapter, out ulong luid);

        [DllImport(Dll, CallingConvention = Cc, SetLastError = true)]
        public static extern void WintunSetLogger(WintunLoggerCallback newLogger);

        [DllImport(Dll, CallingConvention = Cc, SetLastError = true)]
        public static extern uint WintunGetRunningDriverVersion();

        [DllImport(Dll, CallingConvention = Cc, SetLastError = true)]
        public static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);

        [DllImport(Dll, CallingConvention = Cc, SetLastError = true)]
        public static extern void WintunEndSession(IntPtr session);

        [DllImport(Dll, CallingConvention = Cc, SetLastError = true)]
        public static extern IntPtr WintunGetReadWaitEvent(IntPtr session);

        // Returns BYTE* to the packet (NULL on none → GetLastError ERROR_NO_MORE_ITEMS / ERROR_HANDLE_EOF).
        [DllImport(Dll, CallingConvention = Cc, SetLastError = true)]
        public static extern IntPtr WintunReceivePacket(IntPtr session, out uint packetSize);

        [DllImport(Dll, CallingConvention = Cc, SetLastError = true)]
        public static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);

        [DllImport(Dll, CallingConvention = Cc, SetLastError = true)]
        public static extern IntPtr WintunAllocateSendPacket(IntPtr session, uint packetSize);

        [DllImport(Dll, CallingConvention = Cc, SetLastError = true)]
        public static extern void WintunSendPacket(IntPtr session, IntPtr packet);
    }
}
