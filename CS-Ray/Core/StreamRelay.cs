using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core
{
    /// <summary>A server stream that can signal "no more data from the client" in-band while still reading (VMess sends
    /// an empty chunk; the server then half-closes its connection to the target).</summary>
    public interface IHalfClosable
    {
        Task CloseWriteAsync(CancellationToken ct);
    }

    /// <summary>
    /// Protocol-agnostic bidirectional relay: two independent pump loops, each with its own buffer.
    ///
    /// Half-close aware, with Xray's policy timeouts: when the local app finishes sending (clean EOF) the response keeps
    /// flowing until the server ends or the downlink is idle for <see cref="DownlinkOnlyMs"/>; when the server finishes,
    /// the app is told at once (FIN via <c>clientSocket.Shutdown(Send)</c>) and may still send for up to
    /// <see cref="UplinkOnlyMs"/> of idle time. An error, a reset, or the token ends both directions immediately. Then
    /// <paramref name="onClose"/> (which must close both streams) runs and both loops are awaited.
    ///
    /// An optional <c>serverPreamble</c> runs at the start of the server→client direction, concurrently with the
    /// client→server pump — used by VLESS to strip its response header without deadlocking the target's request/response
    /// cycle. Protocols with no such header (e.g. Shadowsocks, which consumes its salt inside its own stream) pass null.
    ///
    /// Only real failures reach <paramref name="onError"/>: the local app resetting/aborting its connection is a normal
    /// way to end one, and anything that fails after teardown began is a consequence of the teardown.
    /// </summary>
    public static class StreamRelay
    {
        /// <summary>Downlink idle limit after the app finished sending (Xray policy downlinkOnly = 5 s).</summary>
        public const int DownlinkOnlyMs = 5000;
        /// <summary>Uplink idle limit after the server finished (Xray policy uplinkOnly = 2 s).</summary>
        public const int UplinkOnlyMs = 2000;

        private enum PumpEnd { Eof, Aborted, Failed }

        private sealed class State
        {
            public volatile bool Closing;
            public volatile bool ServerEof;   // the server finished: a late app→server write failing is expected
            public string UplinkWriteError;   // judged at the end: only a real error if the server had NOT finished
            public long LastUp = Stopwatch.GetTimestamp(), LastDown = Stopwatch.GetTimestamp();
            private string _firstError;
            public string FirstError => _firstError;
            public void Report(string s) { Interlocked.CompareExchange(ref _firstError, s, null); }
        }

        /// <param name="clientSocket">The local app's socket, so a server-side EOF can be passed on as a FIN (half-close)
        /// instead of a full close. Null = close everything when the server ends (the old behaviour).</param>
        public static async Task RelayAsync(
            Stream client, Stream server, Action onClose, CancellationToken ct,
            Func<CancellationToken, Task> serverPreamble = null,
            Action<string> onError = null,
            Socket clientSocket = null)
        {
            var st = new State();
            int closed = 0;
            Action closeOnce = () => { if (Interlocked.Exchange(ref closed, 1) == 0) { st.Closing = true; try { onClose?.Invoke(); } catch { } } };
            var up = PumpAsync(client, server, true, st, ct);
            var down = ServerToClientAsync(server, client, serverPreamble, st, ct);

            // Socket/TLS reads don't honour the token on .NET Framework: on cancellation (engine Stop) close the streams.
            using (ct.Register(closeOnce))
            {
                var first = await Task.WhenAny(up, down).ConfigureAwait(false);
                if (first.Result == PumpEnd.Eof && !ct.IsCancellationRequested)
                {
                    if (first == up)
                    {
                        // The app finished sending (e.g. TUN passed on its FIN): pass that on when the protocol can say
                        // it in-band (Xray's VMess client does), then keep the response coming.
                        if (server is IHalfClosable hc)
                        {
                            // Bounded: a stalled uplink must not keep the downlink-idle teardown from running.
                            Task cw;
                            try { cw = hc.CloseWriteAsync(ct); } catch (Exception ex) { cw = Task.FromException(ex); }
                            var observed = cw.ContinueWith(t => { var unused = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
                            await Task.WhenAny(cw, Task.Delay(DownlinkOnlyMs, ct)).ConfigureAwait(false);
                        }
                        await WaitOrIdleAsync(down, () => Interlocked.Read(ref st.LastDown), DownlinkOnlyMs, ct).ConfigureAwait(false);
                    }
                    else if (clientSocket != null)
                    {
                        // The server finished: let the app see EOF now; it may still finish its own sending.
                        bool shut = false;
                        try { clientSocket.Shutdown(SocketShutdown.Send); shut = true; } catch { }
                        if (shut) await WaitOrIdleAsync(up, () => Interlocked.Read(ref st.LastUp), UplinkOnlyMs, ct).ConfigureAwait(false);
                    }
                }

                // Closing the streams unblocks the still-pending ReadAsync on the other pump (cancellation tokens are not
                // reliably honored by socket/SSL reads). Whatever fails from here on is teardown, not a diagnostic.
                closeOnce();

                try { await Task.WhenAll(up, down).ConfigureAwait(false); } catch { }
            }

            string err = st.FirstError ?? (st.ServerEof ? null : st.UplinkWriteError);
            if (err != null) onError?.Invoke(err);
        }

        // Waits for `pump` to finish, giving up when its direction has been idle for `idleMs` (or on cancellation).
        private static async Task WaitOrIdleAsync(Task pump, Func<long> lastActivity, int idleMs, CancellationToken ct)
        {
            long idleTicks = idleMs * Stopwatch.Frequency / 1000;
            long since = Stopwatch.GetTimestamp();   // the window starts at the half-close, never earlier (Xray re-arms its timer)
            while (!pump.IsCompleted && !ct.IsCancellationRequested)
            {
                long left = idleTicks - (Stopwatch.GetTimestamp() - Math.Max(lastActivity(), since));
                if (left <= 0) return;
                int waitMs = (int)Math.Max(50, Math.Min(500, left * 1000 / Stopwatch.Frequency));
                try { await Task.WhenAny(pump, Task.Delay(waitMs, ct)).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
            }
        }

        private static async Task<PumpEnd> ServerToClientAsync(
            Stream server, Stream client, Func<CancellationToken, Task> preamble, State st, CancellationToken ct)
        {
            if (preamble != null)
            {
                try { await preamble(ct).ConfigureAwait(false); }
                catch (Exception ex) { return Classify(ex, "server preamble", false, st); }
                Interlocked.Exchange(ref st.LastDown, Stopwatch.GetTimestamp());
            }
            return await PumpAsync(server, client, false, st, ct).ConfigureAwait(false);
        }

        private static async Task<PumpEnd> PumpAsync(Stream src, Stream dst, bool uplink, State st, CancellationToken ct)
        {
            string label = uplink ? "client→server" : "server→client";
            var buffer = new byte[32 * 1024];
            bool draining = false;   // uplink only: the server finished and stopped taking data — read and discard
            while (true)
            {
                int n;
                try { n = await src.ReadAsync(buffer, 0, buffer.Length, ct).ConfigureAwait(false); }
                catch (Exception ex) { return Classify(ex, label + " read", uplink, st); }   // uplink reads come from the app
                if (n <= 0) { if (!uplink) st.ServerEof = true; return PumpEnd.Eof; }
                Stamp(uplink, st);
                if (draining) continue;

                try
                {
                    await dst.WriteAsync(buffer, 0, n, ct).ConfigureAwait(false);
                    await dst.FlushAsync(ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    if (uplink && st.ServerEof) { draining = true; continue; }   // the app may still be finishing: let it
                    if (uplink)
                    {
                        // The server may be finishing at this very moment (its EOF not yet read): decide at the end.
                        if (st.Closing || ex is ObjectDisposedException || ex is OperationCanceledException) return PumpEnd.Aborted;
                        Interlocked.CompareExchange(ref st.UplinkWriteError, label + " write: " + ex.Message, null);
                        return PumpEnd.Failed;
                    }
                    return Classify(ex, label + " write", true, st);   // downlink writes go to the app
                }
                Stamp(uplink, st);   // a write that waited on flow control is progress too
            }
        }

        private static void Stamp(bool uplink, State st)
        {
            if (uplink) Interlocked.Exchange(ref st.LastUp, Stopwatch.GetTimestamp());
            else Interlocked.Exchange(ref st.LastDown, Stopwatch.GetTimestamp());
        }

        // appSide: the failing operation was on the local app's connection (where a reset/abort is just the app leaving).
        private static PumpEnd Classify(Exception ex, string what, bool appSide, State st)
        {
            if (st.Closing || ex is ObjectDisposedException || ex is OperationCanceledException) return PumpEnd.Aborted;
            if (appSide && IsAbort(ex)) return PumpEnd.Aborted;
            st.Report(what + ": " + ex.Message);
            return PumpEnd.Failed;
        }

        // Connection reset / aborted / shut down — how apps (browsers especially) routinely drop connections.
        private static bool IsAbort(Exception ex)
        {
            for (var e = ex; e != null; e = e.InnerException)
            {
                if (e is SocketException se)
                    return se.SocketErrorCode == SocketError.ConnectionReset || se.SocketErrorCode == SocketError.ConnectionAborted
                        || se.SocketErrorCode == SocketError.Shutdown || se.SocketErrorCode == SocketError.OperationAborted
                        || se.SocketErrorCode == SocketError.Disconnecting || se.SocketErrorCode == SocketError.NotConnected;
            }
            return false;
        }
    }
}
