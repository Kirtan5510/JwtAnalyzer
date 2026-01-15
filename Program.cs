using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Collections.Generic;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length == 0 || Has(args, "-h", "--help"))
        {
            Help();
            return 0;
        }

        string mode = GetArg(args, "--mode");
        string token = GetArg(args, "-t", "--token");
        if (string.IsNullOrWhiteSpace(mode) || string.IsNullOrWhiteSpace(token)) return 1;

        var parts = token.Split('.');
        if (parts.Length < 2) return 1;

        var headerJson = Decode(parts[0]);
        var payloadJson = Decode(parts[1]);
        if (headerJson == null || payloadJson == null) return 1;

        if (mode == "read")
        {
            Console.WriteLine("Header:");
            Console.WriteLine(headerJson);
            Console.WriteLine();
            Console.WriteLine("Payload:");
            Console.WriteLine(payloadJson);
            return 0;
        }

        if (mode == "scan")
        {
            Scan(headerJson, payloadJson, parts.Length == 3, token.Length);
            return 0;
        }

        if (mode == "edit")
        {
            var header = JsonNode.Parse(headerJson);
            var payload = JsonNode.Parse(payloadJson);

            if (Has(args, "--set"))
            {
                var kv = GetArg(args, "--set").Split('=', 2);
                if (kv.Length == 2)
                {
                    if (kv[0] == "alg") header[kv[0]] = kv[1];
                    else payload[kv[0]] = JsonValue.Create(ParseValue(kv[1]));
                }
            }

            if (Has(args, "--remove"))
            {
                var key = GetArg(args, "--remove");
                payload.AsObject().Remove(key);
            }

            PrintNewToken(header, payload);
            return 0;
        }

        return 0;
    }

    static void Scan(string headerJson, string payloadJson, bool hasSig, int len)
    {
        using var h = JsonDocument.Parse(headerJson);
        using var p = JsonDocument.Parse(payloadJson);
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        if (h.RootElement.TryGetProperty("alg", out var alg))
        {
            var a = alg.GetString();
            if (a == "none") Console.WriteLine("VULNERABLE: alg=none");
            else Console.WriteLine("alg: " + a);
        }
        else Console.WriteLine("WARNING: alg missing");

        if (!hasSig) Console.WriteLine("WARNING: missing signature");

        if (p.RootElement.TryGetProperty("exp", out var exp))
        {
            if (now > exp.GetInt64()) Console.WriteLine("EXPIRED");
            else Console.WriteLine("exp: valid");
        }

        if (p.RootElement.TryGetProperty("nbf", out var nbf))
            if (now < nbf.GetInt64()) Console.WriteLine("NOT VALID YET");

        if (p.RootElement.TryGetProperty("iat", out var iat))
            if (iat.GetInt64() > now) Console.WriteLine("WARNING: iat future");

        if (!p.RootElement.TryGetProperty("iss", out _)) Console.WriteLine("INFO: iss missing");
        if (!p.RootElement.TryGetProperty("aud", out _)) Console.WriteLine("INFO: aud missing");
        if (len > 4096) Console.WriteLine("WARNING: large token");
    }

    static void PrintNewToken(JsonNode h, JsonNode p)
    {
        string eh = Encode(h.ToJsonString());
        string ep = Encode(p.ToJsonString());
        Console.WriteLine("Modified JWT:");
        Console.WriteLine($"{eh}.{ep}.");
    }

    static string Decode(string s)
    {
        try
        {
            s = s.Replace('-', '+').Replace('_', '/');
            if (s.Length % 4 == 2) s += "==";
            if (s.Length % 4 == 3) s += "=";
            return Encoding.UTF8.GetString(Convert.FromBase64String(s));
        }
        catch { return null; }
    }

    static string Encode(string j)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(j)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    static object ParseValue(string v)
    {
        if (long.TryParse(v, out var l)) return l;
        if (bool.TryParse(v, out var b)) return b;
        return v;
    }

    static bool Has(string[] a, params string[] k)
    {
        foreach (var x in a)
            foreach (var y in k)
                if (x == y) return true;
        return false;
    }

    static string GetArg(string[] a, params string[] k)
    {
        for (int i = 0; i < a.Length - 1; i++)
            foreach (var y in k)
                if (a[i] == y) return a[i + 1];
        return null;
    }

    static void Help()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("--mode read|scan|edit -t <JWT>");
        Console.WriteLine("--set key=value");
        Console.WriteLine("--remove key");
        Console.WriteLine("-h --help");
    }
}
