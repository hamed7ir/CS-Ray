using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace CS_Ray.Core.Transport
{
    /// <summary>
    /// Server-certificate validation for the managed (BouncyCastle) TLS client — the checks SslStream gets from
    /// SChannel, done explicitly: (1) the chain builds to a root trusted by WINDOWS (same trust store as the SslStream
    /// path), within its validity period, with the serverAuth EKU, revocation NOT checked (parity with TlsTransport's
    /// checkCertificateRevocation:false); (2) the leaf matches the expected host per RFC 6125 — DNS SANs (wildcard
    /// only as the whole left-most label), IP SANs for an IP host, and the subject CN only when the certificate has no
    /// SAN extension at all. Proof of possession (CertificateVerify / key exchange signature) is verified by the BC
    /// handshake itself.
    /// </summary>
    internal static class TlsCertificateValidator
    {
        private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

        /// <summary>Returns null when the chain is trusted and matches <paramref name="host"/>; else a reason.</summary>
        public static string Validate(byte[] leafDer, IList<byte[]> intermediatesDer, string host)
        {
            string chainError = CheckChain(leafDer, intermediatesDer);
            if (chainError != null) return chainError;
            return MatchesHost(leafDer, host) ? null : "certificate does not match the server name '" + host + "'";
        }

        private static string CheckChain(byte[] leafDer, IList<byte[]> intermediatesDer)
        {
            var extra = new List<X509Certificate2>();
            try
            {
                using (var leaf = new X509Certificate2(leafDer))
                using (var chain = new X509Chain())
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthOid));
                    foreach (var der in intermediatesDer)
                    {
                        var c = new X509Certificate2(der);
                        extra.Add(c);
                        chain.ChainPolicy.ExtraStore.Add(c);
                    }
                    if (chain.Build(leaf)) return null;
                    var reasons = new List<string>();
                    foreach (var st in chain.ChainStatus)
                        if (st.Status != X509ChainStatusFlags.NoError) reasons.Add(st.Status.ToString());
                    return "certificate chain not trusted (" + (reasons.Count > 0 ? string.Join(", ", reasons) : "unknown") + ")";
                }
            }
            catch (CryptographicException ex) { return "certificate could not be parsed: " + ex.Message; }
            finally { foreach (var c in extra) c.Dispose(); }
        }

        /// <summary>RFC 6125 host match against the leaf certificate.</summary>
        internal static bool MatchesHost(byte[] leafDer, string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            var cert = new X509CertificateParser().ReadCertificate(leafDer);
            IPAddress ip;
            bool isIp = IPAddress.TryParse(host.Trim('[', ']'), out ip);
            string asciiHost = isIp ? null : ToAscii(host);

            Asn1OctetString sanExt = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);
            if (sanExt != null)
            {
                var names = GeneralNames.GetInstance(X509ExtensionUtilities.FromExtensionValue(sanExt)).GetNames();
                foreach (var gn in names)
                {
                    if (isIp && gn.TagNo == GeneralName.IPAddress)
                    {
                        byte[] want = ip.GetAddressBytes(), got = Asn1OctetString.GetInstance(gn.Name).GetOctets();
                        if (BytesEqual(want, got)) return true;
                    }
                    else if (!isIp && gn.TagNo == GeneralName.DnsName)
                    {
                        if (DnsNameMatches(DerIA5String.GetInstance(gn.Name).GetString(), asciiHost)) return true;
                    }
                }
                return false;   // a SAN extension is authoritative — no CN fallback
            }

            if (isIp) return false;
            foreach (var cn in cert.SubjectDN.GetValueList(X509Name.CN))
                if (DnsNameMatches(cn, asciiHost)) return true;
            return false;
        }

        // Exact (case-insensitive) or a single left-most "*" label: "*.example.com" matches "a.example.com" but not
        // "example.com" nor "a.b.example.com"; partial-label wildcards ("f*.example.com") are not honored.
        internal static bool DnsNameMatches(string pattern, string host)
        {
            if (string.IsNullOrEmpty(pattern) || string.IsNullOrEmpty(host)) return false;
            pattern = pattern.TrimEnd('.').ToLowerInvariant();
            host = host.TrimEnd('.').ToLowerInvariant();
            if (!pattern.StartsWith("*.", StringComparison.Ordinal)) return pattern == host;
            string suffix = pattern.Substring(1);                     // ".example.com"
            if (suffix.IndexOf('*') >= 0 || suffix.Split('.').Length < 3) return false;   // no "*.com"-style wildcards
            int dot = host.IndexOf('.');
            return dot > 0 && host.Substring(dot) == suffix;
        }

        private static string ToAscii(string host)
        {
            try { return new IdnMapping().GetAscii(host.TrimEnd('.')); } catch { return host; }
        }

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }
    }
}
