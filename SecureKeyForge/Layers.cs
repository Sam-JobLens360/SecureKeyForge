using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecureKeyForge;

public static class Layers
{
    // --------- Double AES-GCM (no extra packages) ----------
    public static byte[] DoubleAesGcmEncrypt(byte[] plaintext, byte[] masterKey)
    {
        // Split master into independent subkeys
        var k1 = ParanoidKeyForge.HkdfExpand(masterKey, "AES-GCM-outer", 32);
        var k2 = ParanoidKeyForge.HkdfExpand(masterKey, "AES-GCM-inner", 32);

        // Inner layer
        byte[] n2 = new byte[12]; RandomNumberGenerator.Fill(n2);
        byte[] tag2 = new byte[16];
        byte[] inner = new byte[plaintext.Length];
        using (var aes2 = new AesGcm(k2)) aes2.Encrypt(n2, plaintext, inner, tag2);

        // Outer layer
        byte[] n1 = new byte[12]; RandomNumberGenerator.Fill(n1);
        byte[] tag1 = new byte[16];
        byte[] outer = new byte[inner.Length];
        using (var aes1 = new AesGcm(k1)) aes1.Encrypt(n1, inner, outer, tag1);

        // Simple self-describing blob:
        // [MAGIC "PX2\0":4][ver:1=1][algo:1=1][n1:12][tag1:16][n2:12][tag2:16][ctLen:4][ct...]
        using var ms = new MemoryStream();
        ms.Write(Encoding.ASCII.GetBytes("PX2\0"));
        ms.WriteByte(1);               // version
        ms.WriteByte(1);               // algo id 1 = DoubleAESGCM
        ms.Write(n1, 0, 12);
        ms.Write(tag1, 0, 16);
        ms.Write(n2, 0, 12);
        ms.Write(tag2, 0, 16);
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)outer.Length);
        ms.Write(len);
        ms.Write(outer, 0, outer.Length);
        return ms.ToArray();
    }

    public static byte[] DoubleAesGcmDecrypt(byte[] blob, byte[] masterKey)
    {
        var k1 = ParanoidKeyForge.HkdfExpand(masterKey, "AES-GCM-outer", 32);
        var k2 = ParanoidKeyForge.HkdfExpand(masterKey, "AES-GCM-inner", 32);

        var span = blob.AsSpan();
        if (span.Length < 4 + 1 + 1 + 12 + 16 + 12 + 16 + 4) throw new CryptographicException("Blob too small");
        if (!span.Slice(0, 4).SequenceEqual(Encoding.ASCII.GetBytes("PX2\0"))) throw new CryptographicException("Bad magic");
        if (span[4] != 1) throw new CryptographicException("Bad version");
        if (span[5] != 1) throw new CryptographicException("Bad algo");

        var n1 = span.Slice(6, 12);
        var tag1 = span.Slice(18, 16);
        var n2 = span.Slice(34, 12);
        var tag2 = span.Slice(46, 16);
        uint ctLen = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(62, 4));
        var ct = span.Slice(66, (int)ctLen);

        byte[] inner = new byte[ct.Length];
        using (var aes1 = new AesGcm(k1)) aes1.Decrypt(n1, ct, tag1, inner);

        byte[] pt = new byte[inner.Length];
        using (var aes2 = new AesGcm(k2)) aes2.Decrypt(n2, inner, tag2, pt);

        return pt;
    }

#if USE_SODIUM
    // --------- XChaCha20-Poly1305 over AES-GCM (adds Sodium.Core) ----------
    public static byte[] XChaChaOverAesEncrypt(byte[] plaintext, byte[] masterKey)
    {
        var kA = ParanoidKeyForge.HkdfExpand(masterKey, "AES-outer", 32);
        var kX = ParanoidKeyForge.HkdfExpand(masterKey, "XCHACHA-inner", 32);

        // Inner: XChaCha20-Poly1305
        byte[] nX = new byte[24]; RandomNumberGenerator.Fill(nX);
        var inner = Sodium.SecretAeadXChaCha20Poly1305.Encrypt(plaintext, null, nX, kX); // returns ct||mac

        // Outer: AES-GCM
        byte[] nA = new byte[12]; RandomNumberGenerator.Fill(nA);
        byte[] tagA = new byte[16];
        byte[] outer = new byte[inner.Length];
        using (var aes = new AesGcm(kA)) aes.Encrypt(nA, inner, outer, tagA);

        using var ms = new MemoryStream();
        ms.Write(Encoding.ASCII.GetBytes("PX2\0"));
        ms.WriteByte(1);               // version
        ms.WriteByte(2);               // algo id 2 = XChaChaOverAES
        ms.Write(nA, 0, 12);
        ms.Write(tagA, 0, 16);
        ms.Write(nX, 0, 24);
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)outer.Length);
        ms.Write(len);
        ms.Write(outer, 0, outer.Length);
        return ms.ToArray();
    }

    public static byte[] XChaChaOverAesDecrypt(byte[] blob, byte[] masterKey)
    {
        var span = blob.AsSpan();
        if (!span.Slice(0,4).SequenceEqual(Encoding.ASCII.GetBytes("PX2\0")) || span[4]!=1 || span[5]!=2)
            throw new CryptographicException("Bad header");
        var nA = span.Slice(6,12);
        var tagA = span.Slice(18,16);
        var nX = span.Slice(34,24);
        uint ctLen = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(58,4));
        var ct = span.Slice(62, (int)ctLen);

        var kA = ParanoidKeyForge.HkdfExpand(masterKey, "AES-outer", 32);
        var kX = ParanoidKeyForge.HkdfExpand(masterKey, "XCHACHA-inner", 32);

        byte[] inner = new byte[ct.Length];
        using (var aes = new AesGcm(kA)) aes.Decrypt(nA, ct, tagA, inner);

        return Sodium.SecretAeadXChaCha20Poly1305.Decrypt(inner, null, nX, kX);
    }
#endif
}
