using Konscious.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecureKeyForge;

public static class ParanoidKeyForge
{
    // Hash each source separately (SHA512) to avoid structural leaks, then XOR fold.
    public static byte[] MixSources(IEnumerable<byte[]> sources, int poolBytes = 64)
    {
        using var sha = SHA512.Create();
        var acc = new byte[poolBytes];
        foreach (var src in sources)
        {
            var h = sha.ComputeHash(src ?? Array.Empty<byte>());
            for (int i = 0; i < poolBytes; i++) acc[i] ^= h[i];
        }

        // Add strong local randomness so no external source can fully control the pool.
        var sys = new byte[poolBytes];
        RandomNumberGenerator.Fill(sys);
        for (int i = 0; i < poolBytes; i++) acc[i] ^= sys[i];
        return acc;
    }

    // Argon2id KDF to 32-byte master key. Choose spicy parameters for offline use.
    public static byte[] Argon2id(byte[] entropyPool, byte[] salt, int memMB = 256, int iterations = 3, int parallelism = 2, int outLen = 32)
    {
        if (salt == null || salt.Length < 16) throw new ArgumentException("Salt must be at least 16 bytes long.", nameof(salt));
        var argon = new Argon2id(entropyPool)
        {
            DegreeOfParallelism = Math.Max(1, parallelism),
            Iterations = Math.Max(1, iterations),
            MemorySize = Math.Max(8, memMB) * 1024 // MemorySize is in KB
        };
        argon.Salt = salt;
        return argon.GetBytes(outLen);
    }

    // HKDF-SHA256 (RFC 5869): derive labeled subkeys from master.
    public static byte[] HkdfExpand(byte[] master, string label, int outLen)
    {
        var prk = new HMACSHA256(master); // salt omitted: use master already PRK-like
        var okm = new List<byte>(outLen);
        byte[] t = Array.Empty<byte>();
        int ctr = 1;

        while (okm.Count < outLen)
        {
            var h = new HMACSHA256(master);
            h.TransformBlock(t, 0, t.Length, null, 0);
            var info = Encoding.UTF8.GetBytes(label);
            h.TransformBlock(info, 0, info.Length, null, 0);
            var c = new[] { (byte)ctr };
            h.TransformFinalBlock(c, 0, 1);
            t = h.Hash!;
            okm.AddRange(t);
            ctr++;
        }
        return okm.Take(outLen).ToArray();
    }
}
