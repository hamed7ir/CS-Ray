using System.Collections.Generic;
using System.Text;

namespace CS_Ray.Core.Config
{
    /// <summary>
    /// Reads a one-line YAML flow collection — <c>{k: v, k2: {a: b}, k3: [x, y]}</c> — into the flat key space the Clash
    /// importer uses: every scalar leaf becomes <c>kv[key]</c> (first wins), a list becomes its items joined by ',', and
    /// a nested map's own key maps to "". Quoted scalars ('…' / "…") are unquoted. Malformed input stops quietly.
    /// </summary>
    internal static class YamlFlow
    {
        /// <summary>Flattens <paramref name="text"/> into <paramref name="kv"/>; returns the value of a top-level list (joined) or "".</summary>
        public static string Flatten(string text, Dictionary<string, string> kv)
        {
            int i = 0;
            try { return Value(text, ref i, kv); }
            catch (System.Exception) { return ""; }
        }

        private static string Value(string s, ref int i, Dictionary<string, string> kv)
        {
            Ws(s, ref i);
            if (i >= s.Length) return "";
            if (s[i] == '{')
            {
                i++;
                while (true)
                {
                    Ws(s, ref i);
                    if (i >= s.Length) return "";
                    if (s[i] == '}') { i++; return ""; }
                    string k = Scalar(s, ref i, ":,}");
                    Ws(s, ref i);
                    string v = "";
                    if (i < s.Length && s[i] == ':') { i++; v = Value(s, ref i, kv); }
                    if (k.Length > 0 && !kv.ContainsKey(k)) kv[k] = v;
                    Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') i++;
                    else if (i < s.Length && s[i] != '}') return "";   // malformed: stop
                }
            }
            if (s[i] == '[')
            {
                i++;
                var items = new List<string>();
                while (true)
                {
                    Ws(s, ref i);
                    if (i >= s.Length) break;
                    if (s[i] == ']') { i++; break; }
                    string v = Value(s, ref i, kv);
                    if (v.Length > 0) items.Add(v);
                    Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') i++;
                    else if (i < s.Length && s[i] != ']') break;
                }
                return string.Join(",", items);
            }
            return Scalar(s, ref i, ",}]");
        }

        private static string Scalar(string s, ref int i, string stops)
        {
            Ws(s, ref i);
            if (i < s.Length && (s[i] == '"' || s[i] == '\''))
            {
                char q = s[i++];
                var sb = new StringBuilder();
                while (i < s.Length)
                {
                    char c = s[i++];
                    if (c == q)
                    {
                        if (q == '\'' && i < s.Length && s[i] == '\'') { sb.Append('\''); i++; continue; }   // '' inside '…'
                        break;
                    }
                    if (c == '\\' && q == '"' && i < s.Length) { sb.Append(s[i++]); continue; }
                    sb.Append(c);
                }
                return sb.ToString();
            }
            int start = i;
            while (i < s.Length && stops.IndexOf(s[i]) < 0) i++;
            return s.Substring(start, i - start).Trim();
        }

        private static void Ws(string s, ref int i) { while (i < s.Length && char.IsWhiteSpace(s[i])) i++; }
    }
}
