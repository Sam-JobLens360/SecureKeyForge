using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace SecureKeyForge;

public static class Program
{
    public static (byte[] MasterKey, byte[] Salt) ForgeMaster(IEnumerable<byte[]> sources)
    {
        var pool = ParanoidKeyForge.MixSources(sources);
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);
        var masterKey = ParanoidKeyForge.Argon2id(pool, salt, memMB: 512, iterations: 4, parallelism: 2, outLen: 32);
        Array.Clear(pool, 0, pool.Length);
        return (masterKey, salt);
    }

    public static void Main(string[] args)
    {
        // Gather weird sources you like:
        var gps = Encoding.UTF8.GetBytes("40.6892,-74.0445"); // placeholder
        var hw = Encoding.UTF8.GetBytes(Environment.MachineName);
        var usb = Encoding.UTF8.GetBytes("USB-SN:ABCD-EF01-2345-6789");

        // 1) Forge a master key (store the salt; NEVER store the master in plaintext)
        var (master, salt) = ForgeMaster(new[] { gps, hw, usb });

        Console.WriteLine($"Master Key: {Convert.ToBase64String(master)}");
        Console.WriteLine($"Salt: {Convert.ToBase64String(salt)}");

        // 2) Encrypt
        var plaintext = File.ReadAllBytes("Seekwell-Candidate-Job-Brief.pdf");
        var blob = Layers.DoubleAesGcmEncrypt(plaintext, master);
        File.WriteAllBytesAsync("secret.enc", blob);
        // Or, if you added Sodium.Core and compiled with USE_SODIUM, prefer:
        // var blob = Layers.XChaChaOverAesEncrypt(plaintext, master);

        // 3) Decrypt later (re-forge `master` the same way in an air-gapped box)
        var pt = Layers.DoubleAesGcmDecrypt(blob, master);
        File.WriteAllBytesAsync("secret.out", pt);
        // Or: Layers.XChaChaOverAesDecrypt(blob, master);

        CryptographicOperations.ZeroMemory(master);
        CryptographicOperations.ZeroMemory(blob);
        CryptographicOperations.ZeroMemory(plaintext);
    }
}