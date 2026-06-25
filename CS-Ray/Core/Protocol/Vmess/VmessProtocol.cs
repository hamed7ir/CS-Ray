using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Protocol.Vmess
{
    /// <summary>
    /// Ties the VMess AEAD handshake to the body stream: seals + sends the request header,
    /// then returns a <see cref="VmessBodyStream"/> for the relay. The AEAD response header is
    /// verified lazily on the body stream's first read (concurrently with the outgoing pump).
    /// </summary>
    public static class VmessProtocol
    {
        /// <summary>
        /// Sends the sealed request header over <paramref name="transport"/> and returns the body stream.
        /// </summary>
        public static async Task<Stream> EstablishAsync(
            Stream transport, byte[] uuid16, string targetHost, int targetPort,
            byte command, Action<string> log, CancellationToken ct)
        {
            var cmdKey = VmessAead.GetCmdKey(uuid16);

            var request = new VmessRequest();
            var sealedHeader = request.BuildSealedHeader(cmdKey, targetHost, targetPort, command);

            await transport.WriteAsync(sealedHeader, 0, sealedHeader.Length, ct).ConfigureAwait(false);
            await transport.FlushAsync(ct).ConfigureAwait(false);
            log?.Invoke("VMess request header sent (" + sealedHeader.Length + " bytes) → " + targetHost + ":" + targetPort);

            // Response body key/IV are SHA256-derived from the request body key/IV.
            var respKey = Sha256First16(request.RequestBodyKey);
            var respIV = Sha256First16(request.RequestBodyIV);

            return new VmessBodyStream(
                transport,
                request.RequestBodyKey, request.RequestBodyIV,
                respKey, respIV,
                request.ResponseHeader,
                log);
        }

        private static byte[] Sha256First16(byte[] input)
        {
            using (var sha = SHA256.Create())
            {
                var full = sha.ComputeHash(input);
                var outBuf = new byte[16];
                Buffer.BlockCopy(full, 0, outBuf, 0, 16);
                return outBuf;
            }
        }
    }
}
