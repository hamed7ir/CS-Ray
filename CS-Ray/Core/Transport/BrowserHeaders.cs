using System;
using System.Text;

namespace CS_Ray.Core.Transport
{
    /// <summary>
    /// Xray's header masquerade values (common/utils/browser.go), shared by the WebSocket upgrade and the XHTTP
    /// requests so every transport claims the same browser. Each version follows the date the way Xray's generators do
    /// (Chrome: 144 on 2026-01-13, one per 35 days, minus a per-machine delay of up to 105 days; Firefox, Safari and curl
    /// alike), so nothing goes stale; Sec-CH-UA is derived by Chromium's GREASE rule. A clock set before the anchor dates
    /// (an RT tablet with a flat clock battery) is read as the anchor date, never a negative version.
    /// </summary>
    internal static class BrowserHeaders
    {
        private static readonly string[] GreaseChars = { " ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_" };
        private static readonly int[] GreaseVersions = { 8, 99, 24 };
        private static readonly int[][] BrandOrders = { new[] { 0, 1, 2 }, new[] { 0, 2, 1 }, new[] { 1, 0, 2 }, new[] { 1, 2, 0 }, new[] { 2, 0, 1 }, new[] { 2, 1, 0 } };
        private static readonly int[] SafariMinorMap = { 0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6 };

        // Declared after the tables they read: static initializers run in textual order.
        private static readonly double R = MachineFraction();
        public static readonly int ChromeMajor = ChromeVersionFor(DateTime.UtcNow, R);

        public static readonly string ChromeUserAgent =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + ChromeMajor + ".0.0.0 Safari/537.36";
        public static readonly string ChromeSecChUa = SecChUa(ChromeMajor);
        // Xray appends "Edg/…" to the Chrome UA without a space; kept byte-for-byte.
        public static readonly string EdgeUserAgent = ChromeUserAgent + "Edg/" + ChromeMajor + ".0.0.0";
        public static readonly string EdgeSecChUa = SecChUa(ChromeMajor, "\"Microsoft Edge\"");
        public static readonly string FirefoxUserAgent = FirefoxUa(DateTime.UtcNow, R);
        public static readonly string SafariUserAgent =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + SafariVersionFor(DateTime.UtcNow, R) + " Safari/605.1.15";
        public static readonly string CurlUserAgent = "curl/" + CurlVersionFor(DateTime.UtcNow, R);

        private static long DaysSince(DateTime utc, int y, int m, int d)
        {
            var anchor = new DateTime(y, m, d, 0, 0, 0, DateTimeKind.Utc);
            return utc < anchor ? 0 : (long)Math.Floor((utc - anchor).TotalDays);
        }

        /// <summary>Xray ChromeVersion: 144 + (days since 2026-01-13 - 35 - floor(r^2 * 105)) / 35, r in [0, 1).</summary>
        internal static int ChromeVersionFor(DateTime utc, double r)
        {
            long diff = DaysSince(utc, 2026, 1, 13) - 35 - (long)Math.Floor(r * r * 105);
            return 144 + (int)(diff / 35);   // Go integer division (truncates toward zero)
        }

        /// <summary>Xray FirefoxVersion: 128 + (days since 2024-07-29 - 25 - floor(r^2 * 50)) / 30.</summary>
        internal static int FirefoxVersionFor(DateTime utc, double r)
        {
            long diff = DaysSince(utc, 2024, 7, 29) - 25 - (long)Math.Floor(r * r * 50);
            return 128 + (int)(diff / 30);
        }

        private static string FirefoxUa(DateTime utc, double r)
        {
            string v = FirefoxVersionFor(utc, r).ToString();
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + v + ".0) Gecko/20100101 Firefox/" + v + ".0";
        }

        /// <summary>Xray CurlVersion: "8." + (days since 2023-03-20 - 60 - floor(r^2 * 165)) / 57 + ".0".</summary>
        internal static string CurlVersionFor(DateTime utc, double r)
        {
            long diff = DaysSince(utc, 2023, 3, 20) - 60 - (long)Math.Floor(r * r * 165);
            return "8." + Math.Max(0, (int)(diff / 57)) + ".0";
        }

        /// <summary>Xray SafariVersion: (release year - 1999) "." minor, the release being Sep 23 plus a per-machine delay
        /// of up to 75 days, the minor stepping every 15 days through Xray's map.</summary>
        internal static string SafariVersionFor(DateTime utc, double r)
        {
            if (utc.Year < 2026) utc = new DateTime(2026, 1, 13, 0, 0, 0, DateTimeKind.Utc);
            int delay = (int)Math.Floor(r * r * r * 75);
            int year = utc.Year;
            var split = new DateTime(year, 9, 23, 0, 0, 0, DateTimeKind.Utc).AddDays(delay);
            if (utc < split) { year--; split = new DateTime(year, 9, 23, 0, 0, 0, DateTimeKind.Utc).AddDays(delay); }
            int idx = (int)((utc - split).TotalSeconds / 1296000);
            return (year - 1999) + "." + SafariMinorMap[Math.Max(0, Math.Min(SafariMinorMap.Length - 1, idx))];
        }

        // Xray seeds its PRNG from CPU facts so one machine always claims the same versions; a stable hash of the same
        // kind of facts gives this machine its own constant in [0, 1).
        private static double MachineFraction()
        {
            string facts = (Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "") + "|" + Environment.ProcessorCount;
            ulong h = 14695981039346656037UL;   // FNV-1a 64
            foreach (byte b in Encoding.UTF8.GetBytes(facts)) { h ^= b; h *= 1099511628211UL; }
            return (h % 1000000UL) / 1000000.0;
        }

        /// <summary>Chrome's Sec-CH-UA for a major version, by Chromium's GREASE rule (as Xray's browser.go reproduces it):
        /// the fake brand "Not?A?Brand" takes its two characters from the version mod 11, its version from mod 3, and the
        /// three brands are ordered by mod 6. E.g. 124 → "Chromium", "Google Chrome", "Not-A.Brand";v="99".</summary>
        internal static string SecChUa(int major) => SecChUa(major, "\"Google Chrome\"");

        private static string SecChUa(int major, string forkBrand)
        {
            if (major < 0) major = 0;
            string grease = "\"Not" + GreaseChars[major % 11] + "A" + GreaseChars[(major + 1) % 11] + "Brand\";v=\"" + GreaseVersions[major % 3] + "\"";
            var brands = new[] { grease, "\"Chromium\";v=\"" + major + "\"", forkBrand + ";v=\"" + major + "\"" };
            var ordered = new string[3];
            var order = BrandOrders[major % 6];
            for (int i = 0; i < 3; i++) ordered[order[i]] = brands[i];
            return string.Join(", ", ordered);
        }
    }
}
