# SecureKeyForge

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![Language](https://img.shields.io/badge/Language-C%23-178600?logo=csharp&logoColor=white)](https://learn.microsoft.com/dotnet/csharp/)
[![Status](https://img.shields.io/badge/Status-Experimental-orange)](https://github.com/Sam-JobLens360/ParanoidCli)
[![Visibility](https://img.shields.io/badge/Repo-Public-success)](https://github.com/Sam-JobLens360/ParanoidCli)

## Example usage (no external services, all local)
```csharp
// Gather weird sources you like:
var gps = Encoding.UTF8.GetBytes("40.6892,-74.0445"); // placeholder
var hw = Encoding.UTF8.GetBytes(Environment.MachineName);
var usb = Encoding.UTF8.GetBytes("USB-SN:ABCD-EF01-2345-6789");

// 1) Forge a master key (store the salt; NEVER store the master in plaintext)
var (master, salt) = Demo.ForgeMaster(new[] { gps, hw, usb });

// 2) Encrypt
var plaintext = File.ReadAllBytes("secret.bin");
var blob = Layers.DoubleAesGcmEncrypt(plaintext, master);
// Or, if you added Sodium.Core and compiled with USE_SODIUM, prefer:
// var blob = Layers.XChaChaOverAesEncrypt(plaintext, master);

// 3) Decrypt later (re-forge `master` the same way in an air-gapped box)
var pt = Layers.DoubleAesGcmDecrypt(blob, master);
// Or: Layers.XChaChaOverAesDecrypt(blob, master);
```

## Why this satisfies paranoia without tinfoil voodoo
- No single point of failure: independent subkeys via HKDF; two ciphers if you enable XChaCha.
- Entropy discipline: per-source hashing + XOR + Argon2id means one weak source can’t tank the pool.
- Nonce sanity: fresh random nonces per layer; tags verified; authenticated encryption only.
- Self-describing blobs: tiny header lets you rotate algorithms later without format chaos.
