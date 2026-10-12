namespace CS_Ray.Core.Transport
{
    /// <summary>
    /// Xray's default "chrome" header masquerade values (transport/internet/browser.go), shared by the WebSocket upgrade
    /// and the XHTTP requests so every transport claims the same browser. One pinned Chrome major version.
    /// </summary>
    internal static class BrowserHeaders
    {
        public const string ChromeMajor = "147";

        public const string ChromeUserAgent =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + ChromeMajor + ".0.0.0 Safari/537.36";

        private static readonly string[] GreaseChars = { " ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_" };
        private static readonly int[] GreaseVersions = { 8, 99, 24 };
        private static readonly int[][] BrandOrders = { new[] { 0, 1, 2 }, new[] { 0, 2, 1 }, new[] { 1, 0, 2 }, new[] { 1, 2, 0 }, new[] { 2, 0, 1 }, new[] { 2, 1, 0 } };

        // Declared after the tables it reads: static initializers run in textual order.
        public static readonly string ChromeSecChUa = SecChUa(int.Parse(ChromeMajor));

        /// <summary>Chrome's Sec-CH-UA for a major version, by Chromium's GREASE rule (as Xray's browser.go reproduces it):
        /// the fake brand "Not?A?Brand" takes its two characters from the version mod 11, its version from mod 3, and the
        /// three brands are ordered by mod 6. E.g. 124 → "Chromium", "Google Chrome", "Not-A.Brand";v="99".</summary>
        internal static string SecChUa(int major)
        {
            string grease = "\"Not" + GreaseChars[major % 11] + "A" + GreaseChars[(major + 1) % 11] + "Brand\";v=\"" + GreaseVersions[major % 3] + "\"";
            var brands = new[] { grease, "\"Chromium\";v=\"" + major + "\"", "\"Google Chrome\";v=\"" + major + "\"" };
            var ordered = new string[3];
            var order = BrandOrders[major % 6];
            for (int i = 0; i < 3; i++) ordered[order[i]] = brands[i];
            return string.Join(", ", ordered);
        }
    }
}
