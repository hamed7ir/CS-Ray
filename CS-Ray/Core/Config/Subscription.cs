using System;

namespace CS_Ray.Core.Config
{
    /// <summary>A subscription source: its servers form their own group/tab (Group == this Id).</summary>
    public class Subscription
    {
        public string Id = Guid.NewGuid().ToString();
        public string Name; // display name (tab title) — derived from the URL host when unknown
        public string Url;
    }
}
