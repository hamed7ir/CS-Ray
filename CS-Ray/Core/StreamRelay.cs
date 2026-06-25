using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core
{
    /// <summary>
    /// Protocol-agnostic bidirectional relay: two independent pump loops, each with its own
    /// buffer. When either direction ends (EOF or error), <paramref name="onClose"/> is invoked
    /// (which should close both streams to unblock the other pump), then both loops are awaited.
    ///
    /// An optional <c>serverPreamble</c> runs at the start of the server→client direction,
    /// concurrently with the client→server pump — used by VLESS to strip its response header
    /// without deadlocking the target's request/response cycle. Protocols with no such header
    /// (e.g. Shadowsocks, which consumes its salt inside its own stream) pass null.
    /// </summary>
    public static class StreamRelay
    {
        public static async Task RelayAsync(
            Stream client, Stream server, Action onClose, CancellationToken ct,
            Func<CancellationToken, Task> serverPreamble = null,
            Action<string> onError = null)
        {
            string firstError = null;
            void Report(string s) { if (firstError == null) firstError = s; }

            var t1 = PumpAsync(client, server, "client→server", Report, ct);
            var t2 = ServerToClientAsync(server, client, serverPreamble, Report, ct);

            await Task.WhenAny(t1, t2).ConfigureAwait(false);

            // Closing the streams unblocks the still-pending ReadAsync on the other pump
            // (cancellation tokens are not reliably honored by socket/SSL reads).
            onClose?.Invoke();

            try { await Task.WhenAll(t1, t2).ConfigureAwait(false); } catch { }

            // The first real (non-EOF) pump exception is the useful diagnostic — closing the
            // streams afterwards produces ObjectDisposed noise on the other pump, which we ignore.
            if (firstError != null) onError?.Invoke(firstError);
        }

        private static async Task ServerToClientAsync(
            Stream server, Stream client, Func<CancellationToken, Task> preamble, Action<string> onError, CancellationToken ct)
        {
            if (preamble != null)
            {
                try { await preamble(ct).ConfigureAwait(false); }
                catch (Exception ex) { onError?.Invoke("server preamble: " + ex.Message); return; }
            }
            await PumpAsync(server, client, "server→client", onError, ct).ConfigureAwait(false);
        }

        // Once one direction ends and onClose disposes both streams, the other pump's pending
        // read/write throws — that's expected teardown, not a real diagnostic.
        private static bool IsCloseNoise(Exception ex)
            => ex is ObjectDisposedException || ex is OperationCanceledException;

        private static async Task PumpAsync(Stream src, Stream dst, string label, Action<string> onError, CancellationToken ct)
        {
            var buffer = new byte[32 * 1024];
            while (true)
            {
                int n;
                try { n = await src.ReadAsync(buffer, 0, buffer.Length, ct).ConfigureAwait(false); }
                catch (Exception ex) { if (!IsCloseNoise(ex)) onError?.Invoke(label + " read: " + ex.Message); break; }
                if (n <= 0) break; // clean EOF

                try
                {
                    await dst.WriteAsync(buffer, 0, n, ct).ConfigureAwait(false);
                    await dst.FlushAsync(ct).ConfigureAwait(false);
                }
                catch (Exception ex) { if (!IsCloseNoise(ex)) onError?.Invoke(label + " write: " + ex.Message); break; }
            }
        }
    }
}
