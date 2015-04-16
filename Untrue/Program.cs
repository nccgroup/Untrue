//Released as open source by NCC Group Plc - http://www.nccgroup.com/
//
//Developed by Richard Turnbull, Richard [dot] Turnbull [at] nccgroup [dot] com
//
//http://www.github.com/nccgroup/untrue
//
//Released under AGPL see LICENSE for more information

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NDesk.Options;
using System.IO;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;

namespace Untrue
{
    public enum TDHashAlgorithm { RIPEMD, RIPEMD_SYSTEM, WHIRLPOOL, SHA512 };
    public enum TDEncryptionAlgorithm { AES, SERPENT, TWOFISH, AES_TWOFISH, AES_TWOFISH_SERPENT, SERPENT_AES, SERPENT_TWOFISH_AES, TWOFISH_SERPENT };
    public enum SectorGuess { ZEROS, TRUECRYPT_MBR, STANDARD_MBR, FAT_HEADER, NTFS_HEADER, CIPHERTEXT, PLAINTEXT };

    class Program
    {
        public static string UNTRUE_VERSION = "0.9";
        public static int SECTOR_SIZE = 0x200;
        public static int VOLUME_HEADER_SIZE = SECTOR_SIZE;
        public static int TRUECRYPT_SALT_LENGTH = 64;
        public static int VOLUME_HEADER_LENGTH_WITHOUT_SALT = VOLUME_HEADER_SIZE - TRUECRYPT_SALT_LENGTH;
        public static int PBKDF2_OUTPUT_LENGTH = 3 * 32 * 2;

        public static int RIPEMD_ITERATIONS = 2000;
        public static int RIPEMD_SYSTEM_ITERATIONS = 1000;
        public static int SHA512_ITERATIONS = 1000;
        public static int WHIRLPOOL_ITERATIONS = 1000;

        public static int VOLUME_HEADER_SECTOR_ON_RESCUE_DISK = 0xA6;    // rescue disk image starts with 0x68 blank sectors, then a copy of the first track with volume header at sector 0x3E
        public static int VOLUME_HEADER_SECTOR_ON_FIRST_TRACK = 0x3E;

        static int verbosity = 1;

        static FileStream keyFile = null;
        static FileStream volumeHeaderFile = null;
        static FileStream inputFile = null;
        static FileStream outputFile = null;

        static int KeyLengthForEncryptionAlgorithm(TDEncryptionAlgorithm ea)
        {
            switch (ea)
            {
                case TDEncryptionAlgorithm.AES:
                case TDEncryptionAlgorithm.SERPENT:
                case TDEncryptionAlgorithm.TWOFISH:
                    return 64;      // 256 bits + 256 bits
                case TDEncryptionAlgorithm.AES_TWOFISH:
                case TDEncryptionAlgorithm.SERPENT_AES:
                case TDEncryptionAlgorithm.TWOFISH_SERPENT:
                    return 128;
                case TDEncryptionAlgorithm.AES_TWOFISH_SERPENT:
                case TDEncryptionAlgorithm.SERPENT_TWOFISH_AES:
                    return 192;
            }

            return -1;
        }

        static string HashAlgorithmFriendlyName(TDHashAlgorithm ha)
        {
            switch (ha)
            {
                case TDHashAlgorithm.SHA512:
                    return "SHA-512";
                case TDHashAlgorithm.WHIRLPOOL:
                    return "Whirlpool";
                case TDHashAlgorithm.RIPEMD:
                    return "RIPEMD-160 (standard version with 2000 iterations)";
                case TDHashAlgorithm.RIPEMD_SYSTEM:
                    return "RIPEMD-160 (system encryption version with 1000 iterations)";
            }

            return "";
        }

        static string EncryptionAlgorithmFriendlyName(TDEncryptionAlgorithm ea)
        {
            switch (ea)
            {
                case TDEncryptionAlgorithm.AES:
                    return "AES";
                case TDEncryptionAlgorithm.SERPENT:
                    return "Serpent";
                case TDEncryptionAlgorithm.TWOFISH:
                    return "Twofish";
                case TDEncryptionAlgorithm.AES_TWOFISH:
                    return "AES-Twofish";
                case TDEncryptionAlgorithm.AES_TWOFISH_SERPENT:
                    return "AES-Twofish-Serpent";
                case TDEncryptionAlgorithm.SERPENT_AES:
                    return "Serpent-AES";
                case TDEncryptionAlgorithm.SERPENT_TWOFISH_AES:
                    return "Serpent-Twofish-AES";
                case TDEncryptionAlgorithm.TWOFISH_SERPENT:
                    return "Twofish-Serpent";
            }

            return "";
        }

        static string EncryptionEngineFriendlyName(IBlockCipher bc)
        {
            if (bc is RijndaelEngine)
            {
                return "AES";
            }
            else if (bc is TwofishEngine)
            {
                return "Twofish";
            }
            else if (bc is SerpentEngine)
            {
                return "Serpent";
            }

            return "";
        }



        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: Untrue.exe");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static void ShowVersion()
        {
            Console.WriteLine("Untrue version {0}", UNTRUE_VERSION);
            Console.WriteLine("by Richard Turnbull, NCC Group");
        }

        static void UsageWarning(string s)
        {
            Console.WriteLine("Warning: {0}", s);
        }

        static void UsageError(string s)
        {
            Console.WriteLine("Error: {0}", s);
            if (inputFile != null) inputFile.Close();
            if (outputFile != null) outputFile.Close();
            if (keyFile != null) outputFile.Close();
            if (volumeHeaderFile != null) volumeHeaderFile.Close();
            System.Environment.Exit(1);
        }

        static SectorGuess GuessSectorFormat(byte[] sector)
        {
            bool allZeros = true;

            for (int ii = 0; ii < SECTOR_SIZE; ii++)
            {
                if (sector[ii] != 0)
                {
                    allZeros = false;
                    break;
                }
            }

            if (allZeros)
            {
                return SectorGuess.ZEROS;
            }

            string s = System.Text.Encoding.ASCII.GetString( sector);

            if (s.Contains("TrueCrypt Boot Loader"))
            {
                return SectorGuess.TRUECRYPT_MBR;
            }

            double score = Utils.CalculateChiSquareTestStatisticOnBytes(sector);

            // P(false_plaintext_positive) = 0.0001
            if (score < 347.6539)
            {
                return SectorGuess.CIPHERTEXT;
            }
            else
            {
                if (sector[SECTOR_SIZE - 2] == 0x55 && sector[SECTOR_SIZE - 1] == 0xAA)
                {
                    if (s.Contains("NTFS"))
                    {
                        return SectorGuess.NTFS_HEADER;
                    }
                    else if (s.Contains("FAT"))
                    {
                        return SectorGuess.FAT_HEADER;
                    }
                    else
                    {
                        return SectorGuess.STANDARD_MBR;
                    }
                }
                else
                {
                    return SectorGuess.PLAINTEXT;
                }
            }
        }

        public static void XorBlockInto(byte[] block1, int offset1, int count, byte[] block2, int offset2, byte[] output, int outputOffset)
        {
            if ((offset1 + count > block1.Length) || (offset2 + count > block2.Length) || (outputOffset + count > output.Length))
            {
                throw new ArgumentException("Bad block lengths passed in to xorBlock()");
            }

            for (int ii = 0; ii < count; ii++)
            {
                output[outputOffset + ii] = (byte)(block1[ii + offset1] ^ block2[ii + offset2]);
            }
        }

        private static byte[] XtsTransformSector(
            ICryptoTransform primaryKeyEncrypt,
            ICryptoTransform primaryKeyDecrypt,
            ICryptoTransform secondaryKeyEncrypt,
            byte[] ciphertext,
            long sectorNumber,
            bool isDecrypt)
        {
            int blockLengthInBytes = 16;
            byte[] IV = new byte[blockLengthInBytes];


            for (int ii = 15; ii >= 8; ii--)
            {
                IV[15 - ii] = (byte)((sectorNumber >> (8 * (15 - ii))) & 0xff);
            }

            if (isDecrypt)
            {
                byte[] EK2 = secondaryKeyEncrypt.TransformFinalBlock(IV, 0, IV.Length);

                byte[] plaintext = new byte[ciphertext.Length];
                byte[] buffer = new byte[blockLengthInBytes];
                byte[] buffer2;

                for (int ii = 0; ii < ciphertext.Length; ii += blockLengthInBytes)
                {
                    XorBlockInto(ciphertext, ii, blockLengthInBytes, EK2, 0, buffer, 0);
                    buffer2 = primaryKeyDecrypt.TransformFinalBlock(buffer, 0, buffer.Length);
                    XorBlockInto(buffer2, 0, blockLengthInBytes, EK2, 0, plaintext, ii);

                    UpdateEK2(EK2);
                }

                return plaintext;
            }
            else
            {
                byte[] EK2 = secondaryKeyEncrypt.TransformFinalBlock(IV, 0, IV.Length);

                byte[] plaintext = new byte[ciphertext.Length];
                byte[] buffer = new byte[blockLengthInBytes];
                byte[] buffer2;

                for (int ii = 0; ii < ciphertext.Length; ii += blockLengthInBytes)
                {
                    XorBlockInto(ciphertext, ii, blockLengthInBytes, EK2, 0, buffer, 0);
                    buffer2 = primaryKeyEncrypt.TransformFinalBlock(buffer, 0, buffer.Length);
                    XorBlockInto(buffer2, 0, blockLengthInBytes, EK2, 0, plaintext, ii);

                    UpdateEK2(EK2);
                }

                return plaintext;
            }
        }

        private static byte[] XtsTransformSectorBC(
            IBlockCipher primaryTransform,
            IBlockCipher secondaryTransform,
            byte[] ciphertext,
            long sectorNumber)
        {
            bool isSerpent = (primaryTransform is SerpentEngine);

            int blockLengthInBytes = 16;
            byte[] IV = new byte[blockLengthInBytes];

            for (int ii = 15; ii >= 8; ii--)
            {
                IV[15 - ii] = (byte)((sectorNumber >> (8 * (15 - ii))) & 0xff);
            }

            byte[] EK2 = new byte[blockLengthInBytes];

            if( isSerpent) IV = Utils.ByteArrayReverse(IV);

            secondaryTransform.ProcessBlock(IV, 0, EK2, 0);

            if (isSerpent) EK2 = Utils.ByteArrayReverse(EK2);

            byte[] plaintext = new byte[ciphertext.Length];
            byte[] buffer = new byte[blockLengthInBytes];
            byte[] buffer2 = new byte[blockLengthInBytes];

            for (int ii = 0; ii < ciphertext.Length; ii += blockLengthInBytes)
            {
                XorBlockInto(ciphertext, ii, blockLengthInBytes, EK2, 0, buffer, 0);
                if (isSerpent) buffer = Utils.ByteArrayReverse(buffer);
                primaryTransform.ProcessBlock(buffer, 0, buffer2, 0);
                if (isSerpent) buffer2 = Utils.ByteArrayReverse(buffer2);
                XorBlockInto(buffer2, 0, blockLengthInBytes, EK2, 0, plaintext, ii);

                UpdateEK2(EK2);
            }

            return plaintext;
        }

        private static void UpdateEK2(byte[] EK2)
        {
            byte carriedBit = 0, topBit = 0;

            for (int ii = 0; ii < 16; ii++)
            {
                topBit = (byte)(EK2[ii] >> 7);
                EK2[ii] = (byte)(((EK2[ii] << 1) | carriedBit) & 0xFF);
                carriedBit = topBit;
            }

            if (topBit > 0)
            {
                EK2[0] ^= 0x87;
            }
        }

        private static bool VolumeHeaderIsValid(byte[] volumeHeaderBytes)
        {
            if ((volumeHeaderBytes[0] == (byte)'T') &&
                (volumeHeaderBytes[1] == (byte)'R') &&
                (volumeHeaderBytes[2] == (byte)'U') &&
                (volumeHeaderBytes[3] == (byte)'E'))
            {
                return true;
            }

            return false;
        }

        private static VolumeHeaderResult DecryptVolumeHeader(byte[] volumeHeaderBytes, string password, Dictionary<TDHashAlgorithm, bool> hashAlgorithmsEnabled, Dictionary<TDEncryptionAlgorithm, bool> encryptionAlgorithmsEnabled)
        {
            VolumeHeaderResult result = new VolumeHeaderResult();
            result.Success = false;

            Log(2, "Trying to decrypt volume header...");

            byte[] salt = new byte[TRUECRYPT_SALT_LENGTH];
            Array.Copy(volumeHeaderBytes, salt, TRUECRYPT_SALT_LENGTH);

            Log(3, "\n\tSalt            : " + Utils.ByteArrayToHexString(salt));

            byte[] encryptedVolumeHeader = new byte[VOLUME_HEADER_LENGTH_WITHOUT_SALT];
            Array.Copy(volumeHeaderBytes, TRUECRYPT_SALT_LENGTH, encryptedVolumeHeader, 0, VOLUME_HEADER_LENGTH_WITHOUT_SALT);

            Log(3, "\tEncrypted header: " + Utils.ByteArrayToHexString(encryptedVolumeHeader));

            byte[] passwordBytes = System.Text.Encoding.ASCII.GetBytes(password);

            Log(3, "\tPassword bytes: " + Utils.ByteArrayToHexString(passwordBytes) + "\n");

            foreach( TDHashAlgorithm ha in Enum.GetValues(typeof(TDHashAlgorithm)))
            {
                if (!hashAlgorithmsEnabled[ha])
                {
                    continue;
                }

                PBKDF2 pbkdf2 = null;
                int iterations = 0;

                switch (ha)
                {
                    case TDHashAlgorithm.RIPEMD:
                        pbkdf2 = new PBKDF2(new RipeMD160Digest());
                        iterations = RIPEMD_ITERATIONS;
                        break;
                    case TDHashAlgorithm.RIPEMD_SYSTEM:
                        pbkdf2 = new PBKDF2(new RipeMD160Digest());
                        iterations = RIPEMD_SYSTEM_ITERATIONS;
                        break;
                    case TDHashAlgorithm.WHIRLPOOL:
                        pbkdf2 = new PBKDF2(new WhirlpoolDigest());
                        iterations = WHIRLPOOL_ITERATIONS;
                        break;
                    case TDHashAlgorithm.SHA512:
                        pbkdf2 = new PBKDF2(new Sha512Digest());
                        iterations = SHA512_ITERATIONS;
                        break;
                }

                Log(2, "\tTrying hash algorithm: " + HashAlgorithmFriendlyName(ha)); 

                byte[] key = pbkdf2.GetBytes(PBKDF2_OUTPUT_LENGTH, passwordBytes, salt, iterations);

                Log(3, "\t\tDerived key: " + Utils.ByteArrayToHexString(key));

                byte[] primaryKey1 = new byte[32];
                byte[] secondaryKey1 = new byte[32];
                byte[] primaryKey2 = new byte[32];
                byte[] secondaryKey2 = new byte[32];
                byte[] primaryKey3 = new byte[32];
                byte[] secondaryKey3 = new byte[32];

                foreach (TDEncryptionAlgorithm ea in Enum.GetValues(typeof(TDEncryptionAlgorithm)))
                {

                    IBlockCipher primaryTransform1 = null;
                    IBlockCipher secondaryTransform1 = null;
                    IBlockCipher primaryTransform2 = null;
                    IBlockCipher secondaryTransform2 = null;
                    IBlockCipher primaryTransform3 = null;
                    IBlockCipher secondaryTransform3 = null;

                    if (!encryptionAlgorithmsEnabled[ea])
                    {
                        continue;
                    }

                    switch (ea)
                    {
                        case TDEncryptionAlgorithm.AES:
                            primaryTransform1 = new RijndaelEngine();
                            secondaryTransform1 = new RijndaelEngine();
                            break;
                        case TDEncryptionAlgorithm.SERPENT:
                            primaryTransform1 = new SerpentEngine();
                            secondaryTransform1 = new SerpentEngine();
                            primaryKey1 = Utils.ByteArrayReverse(primaryKey1);
                            secondaryKey1 = Utils.ByteArrayReverse(secondaryKey1);
                            break;
                        case TDEncryptionAlgorithm.TWOFISH:
                            primaryTransform1 = new TwofishEngine();
                            secondaryTransform1 = new TwofishEngine();
                            break;
                        case TDEncryptionAlgorithm.AES_TWOFISH:
                            primaryTransform2 = new RijndaelEngine();
                            secondaryTransform2 = new RijndaelEngine();
                            primaryTransform1 = new TwofishEngine();
                            secondaryTransform1 = new TwofishEngine();
                            break;
                        case TDEncryptionAlgorithm.AES_TWOFISH_SERPENT:
                            primaryTransform3 = new RijndaelEngine();
                            secondaryTransform3 = new RijndaelEngine();
                            primaryTransform2 = new TwofishEngine();
                            secondaryTransform2 = new TwofishEngine();
                            primaryTransform1 = new SerpentEngine();
                            secondaryTransform1 = new SerpentEngine();
                            break;
                        case TDEncryptionAlgorithm.SERPENT_AES:
                            primaryTransform1 = new RijndaelEngine();
                            secondaryTransform1 = new RijndaelEngine();
                            primaryTransform2 = new SerpentEngine();
                            secondaryTransform2 = new SerpentEngine();
                            break;
                        case TDEncryptionAlgorithm.SERPENT_TWOFISH_AES:
                            primaryTransform1 = new RijndaelEngine();
                            secondaryTransform1 = new RijndaelEngine();
                            primaryTransform2 = new TwofishEngine();
                            secondaryTransform2 = new TwofishEngine();
                            primaryTransform3 = new SerpentEngine();
                            secondaryTransform3 = new SerpentEngine();
                            break;
                        case TDEncryptionAlgorithm.TWOFISH_SERPENT:
                            primaryTransform2 = new TwofishEngine();
                            secondaryTransform2 = new TwofishEngine();
                            primaryTransform1 = new SerpentEngine();
                            secondaryTransform1 = new SerpentEngine();
                            break;
                    }

                    Log(2, "\t\tTrying encryption algorithm: " + EncryptionAlgorithmFriendlyName(ea)); 

                    if (primaryTransform2 == null)
                    {
                        Array.Copy(key, 0, primaryKey1, 0, 32);
                        Array.Copy(key, 32, secondaryKey1, 0, 32);
                    }
                    else if (primaryTransform3 == null)
                    {
                        Array.Copy(key, 0, primaryKey1, 0, 32);
                        Array.Copy(key, 32, primaryKey2, 0, 32);
                        Array.Copy(key, 64, secondaryKey1, 0, 32);
                        Array.Copy(key, 96, secondaryKey2, 0, 32);
                    }
                    else
                    {
                        Array.Copy(key, 0, primaryKey1, 0, 32);
                        Array.Copy(key, 32, primaryKey2, 0, 32);
                        Array.Copy(key, 64, primaryKey3, 0, 32);
                        Array.Copy(key, 96, secondaryKey1, 0, 32);
                        Array.Copy(key, 128, secondaryKey2, 0, 32);
                        Array.Copy(key, 160, secondaryKey3, 0, 32);
                    }

                    Log(3, "\t\t\tInitialising " + EncryptionEngineFriendlyName(primaryTransform1) + " with primary key: " + Utils.ByteArrayToHexString(primaryKey1));
                    Log(3, "\t\t\tInitialising " + EncryptionEngineFriendlyName(primaryTransform1) + " with secondary key: " + Utils.ByteArrayToHexString(secondaryKey1));
                    if (primaryTransform1 is SerpentEngine)
                    {
                        primaryKey1 = Utils.ByteArrayReverse(primaryKey1);
                        secondaryKey1 = Utils.ByteArrayReverse(secondaryKey1);
                    }
                    primaryTransform1.Init(false, new KeyParameter(primaryKey1));
                    secondaryTransform1.Init(true, new KeyParameter(secondaryKey1));
                    
                    if (primaryTransform2 != null)
                    {
                        Log(3, "\t\t\tInitialising " + EncryptionEngineFriendlyName(primaryTransform2) + " with primary key: " + Utils.ByteArrayToHexString(primaryKey2));
                        Log(3, "\t\t\tInitialising " + EncryptionEngineFriendlyName(primaryTransform2) + " with secondary key: " + Utils.ByteArrayToHexString(secondaryKey2));
                        if (primaryTransform2 is SerpentEngine)
                        {
                            primaryKey2 = Utils.ByteArrayReverse(primaryKey2);
                            secondaryKey2 = Utils.ByteArrayReverse(secondaryKey2);
                        }
                        primaryTransform2.Init(false, new KeyParameter(primaryKey2));
                        secondaryTransform2.Init(true, new KeyParameter(secondaryKey2));
                    }
                    if (primaryTransform3 != null)
                    {
                        Log(3, "\t\t\tInitialising " + EncryptionEngineFriendlyName(primaryTransform3) + " with primary key: " + Utils.ByteArrayToHexString(primaryKey3));
                        Log(3, "\t\t\tInitialising " + EncryptionEngineFriendlyName(primaryTransform3) + " with secondary key: " + Utils.ByteArrayToHexString(secondaryKey3));
                        if (primaryTransform3 is SerpentEngine)
                        {
                            primaryKey3 = Utils.ByteArrayReverse(primaryKey3);
                            secondaryKey3 = Utils.ByteArrayReverse(secondaryKey3);
                        }
                        primaryTransform3.Init(false, new KeyParameter(primaryKey3));
                        secondaryTransform3.Init(true, new KeyParameter(secondaryKey3));
                    }

                    byte[] decryptedVolumeHeader = null;

                    if (primaryTransform2 == null)
                    {
                        Log(3, "\t\t\tRunning " + EncryptionEngineFriendlyName(primaryTransform1) + " decryption...");

                        decryptedVolumeHeader = XtsTransformSectorBC(
                            primaryTransform1,
                            secondaryTransform1,
                            encryptedVolumeHeader,
                            0);

                        Log(3, "\t\t\tDecrypted header: " + Utils.ByteArrayToHexString(decryptedVolumeHeader));
                    }
                    else if (primaryTransform3 == null)
                    {
                        Log(3, "\t\t\tRunning " + EncryptionEngineFriendlyName(primaryTransform2) + " decryption...");

                        decryptedVolumeHeader = XtsTransformSectorBC(
                            primaryTransform2,
                            secondaryTransform2,
                            encryptedVolumeHeader,
                            0);

                        Log(3, "\t\t\tIntermediate output: " + Utils.ByteArrayToHexString(decryptedVolumeHeader));

                        Log(3, "\t\t\tRunning " + EncryptionEngineFriendlyName(primaryTransform1) + " decryption...");

                        decryptedVolumeHeader = XtsTransformSectorBC(
                            primaryTransform1,
                            secondaryTransform1,
                            decryptedVolumeHeader,
                            0);

                        Log(3, "\t\t\tDecrypted header: " + Utils.ByteArrayToHexString(decryptedVolumeHeader));
                    }
                    else
                    {
                        Log(3, "\t\t\tRunning " + EncryptionEngineFriendlyName(primaryTransform3) + " decryption...");

                        decryptedVolumeHeader = XtsTransformSectorBC(
                            primaryTransform3,
                            secondaryTransform3,
                            encryptedVolumeHeader,
                            0);

                        Log(3, "\t\t\tIntermediate output: " + Utils.ByteArrayToHexString(decryptedVolumeHeader));

                        Log(3, "\t\t\tRunning " + EncryptionEngineFriendlyName(primaryTransform2) + " decryption...");

                        decryptedVolumeHeader = XtsTransformSectorBC(
                            primaryTransform2,
                            secondaryTransform2,
                            decryptedVolumeHeader,
                            0);

                        Log(3, "\t\t\tIntermediate output: " + Utils.ByteArrayToHexString(decryptedVolumeHeader));

                        Log(3, "\t\t\tRunning " + EncryptionEngineFriendlyName(primaryTransform1) + " decryption...");

                        decryptedVolumeHeader = XtsTransformSectorBC(
                            primaryTransform1,
                            secondaryTransform1,
                            decryptedVolumeHeader,
                            0);

                        Log(3, "\t\t\tDecrypted header: " + Utils.ByteArrayToHexString(decryptedVolumeHeader));
                    }

                    if (VolumeHeaderIsValid(decryptedVolumeHeader))
                    {
                        Log(2, "\t\t\tSuccess!");

                        result.Success = true;
                        result.ea = ea;
                        result.ha = ha;
                        result.CiphertextOffset = Utils.ReadLongFromByteArray(decryptedVolumeHeader, 0x2C);
                        result.CiphertextLength = Utils.ReadLongFromByteArray(decryptedVolumeHeader, 0x24);
                        result.VolumeKey = new byte[PBKDF2_OUTPUT_LENGTH];
                        Array.Copy(decryptedVolumeHeader, 0xC0, result.VolumeKey, 0, PBKDF2_OUTPUT_LENGTH);

                        Log(2, "Encryption algorithm for volume: " + EncryptionAlgorithmFriendlyName(result.ea));
                        Log(2, String.Format("Ciphertext offset (sector)     : 0x{0:x}", result.CiphertextOffset / SECTOR_SIZE));
                        Log(2, String.Format("Ciphertext length (sectors)    : 0x{0:x}", result.CiphertextLength / SECTOR_SIZE));
                        Log(3, "Volume encryption key          : " + Utils.ByteArrayToHexString(result.VolumeKey));

                        return result;
                    }
                    else
                    {
                        Log(2, "\t\t\tFailure");
                    }
                }
            }

            return result;
        }

        static byte[] ProcessDiskSector(
            byte[] ciphertext,
            long sectorNumber,
            IBlockCipher primaryTransform1,
            IBlockCipher secondaryTransform1,
            IBlockCipher primaryTransform2,
            IBlockCipher secondaryTransform2,
            IBlockCipher primaryTransform3,
            IBlockCipher secondaryTransform3,
            bool log,
            bool decrypting)
        {
            byte[] plaintext = new byte[ciphertext.Length];

            if (log) Log(3, (decrypting ? "Ciphertext" : "Plaintext") + ": " + Utils.ByteArrayToHexString(ciphertext));

            if (primaryTransform3 != null)
            {
                if( log) Log(3, "Running " + EncryptionEngineFriendlyName(primaryTransform1) + " " + (decrypting ? "decryption" : "encryption"));
                plaintext = XtsTransformSectorBC(primaryTransform3, secondaryTransform3, ciphertext, sectorNumber);
                if (log) Log(3, "Intermediate output: " + Utils.ByteArrayToHexString(plaintext));
                if (log) Log(3, "Running " + EncryptionEngineFriendlyName(primaryTransform2) + " " + (decrypting ? "decryption" : "encryption"));
                plaintext = XtsTransformSectorBC(primaryTransform2, secondaryTransform2, plaintext, sectorNumber);
                if (log) Log(3, "Intermediate output: " + Utils.ByteArrayToHexString(plaintext));
                if (log) Log(3, "Running " + EncryptionEngineFriendlyName(primaryTransform1) + " " + (decrypting ? "decryption" : "encryption"));
                plaintext = XtsTransformSectorBC(primaryTransform1, secondaryTransform1, plaintext, sectorNumber);
            }
            else if (primaryTransform2 != null)
            {
                if (log) Log(3, "Running " + EncryptionEngineFriendlyName(primaryTransform2) + " " + (decrypting ? "decryption" : "encryption"));
                plaintext = XtsTransformSectorBC(primaryTransform2, secondaryTransform2, ciphertext, sectorNumber);
                if (log) Log(3, "Intermediate output: " + Utils.ByteArrayToHexString(plaintext));
                if (log) Log(3, "Running " + EncryptionEngineFriendlyName(primaryTransform1) + " " + (decrypting ? "decryption" : "encryption"));
                plaintext = XtsTransformSectorBC(primaryTransform1, secondaryTransform1, plaintext, sectorNumber);
            }
            else
            {
                if (log) Log(3, "Running " + EncryptionEngineFriendlyName(primaryTransform1) + " " + (decrypting ? "decryption" : "encryption"));
                plaintext = XtsTransformSectorBC(primaryTransform1, secondaryTransform1, ciphertext, sectorNumber);
            }

            if (log) Log(3, (decrypting ? "Plaintext" : "Ciphertext") + ": " + Utils.ByteArrayToHexString(plaintext));

            return plaintext;
        }

        static void ProcessSectors(FileStream inputFile, FileStream outputFile, long startOffset, long startSectorNumber, long sectorsToProcess, byte[] key, TDEncryptionAlgorithm ea, bool decrypt)
        {

            IBlockCipher primaryTransform1 = null;
            IBlockCipher secondaryTransform1 = null;
            IBlockCipher primaryTransform2 = null;
            IBlockCipher secondaryTransform2 = null;
            IBlockCipher primaryTransform3 = null;
            IBlockCipher secondaryTransform3 = null;

            byte[] primaryKey1 = new byte[32];
            byte[] secondaryKey1 = new byte[32];
            byte[] primaryKey2 = new byte[32];
            byte[] secondaryKey2 = new byte[32];
            byte[] primaryKey3 = new byte[32];
            byte[] secondaryKey3 = new byte[32];

            Log(2, "Preparing to " + (decrypt ? "decrypt" : "encrypt") + " " + sectorsToProcess.ToString() + " sectors...");

            switch (ea)
            {
                case TDEncryptionAlgorithm.AES:
                    primaryTransform1 = new RijndaelEngine();
                    secondaryTransform1 = new RijndaelEngine();
                    break;
                case TDEncryptionAlgorithm.SERPENT:
                    primaryTransform1 = new SerpentEngine();
                    secondaryTransform1 = new SerpentEngine();
                    primaryKey1 = Utils.ByteArrayReverse(primaryKey1);
                    secondaryKey1 = Utils.ByteArrayReverse(secondaryKey1);
                    break;
                case TDEncryptionAlgorithm.TWOFISH:
                    primaryTransform1 = new TwofishEngine();
                    secondaryTransform1 = new TwofishEngine();
                    break;
                case TDEncryptionAlgorithm.AES_TWOFISH:
                    primaryTransform2 = new RijndaelEngine();
                    secondaryTransform2 = new RijndaelEngine();
                    primaryTransform1 = new TwofishEngine();
                    secondaryTransform1 = new TwofishEngine();
                    break;
                case TDEncryptionAlgorithm.AES_TWOFISH_SERPENT:
                    primaryTransform3 = new RijndaelEngine();
                    secondaryTransform3 = new RijndaelEngine();
                    primaryTransform2 = new TwofishEngine();
                    secondaryTransform2 = new TwofishEngine();
                    primaryTransform1 = new SerpentEngine();
                    secondaryTransform1 = new SerpentEngine();
                    break;
                case TDEncryptionAlgorithm.SERPENT_AES:
                    primaryTransform1 = new RijndaelEngine();
                    secondaryTransform1 = new RijndaelEngine();
                    primaryTransform2 = new SerpentEngine();
                    secondaryTransform2 = new SerpentEngine();
                    break;
                case TDEncryptionAlgorithm.SERPENT_TWOFISH_AES:
                    primaryTransform1 = new RijndaelEngine();
                    secondaryTransform1 = new RijndaelEngine();
                    primaryTransform2 = new TwofishEngine();
                    secondaryTransform2 = new TwofishEngine();
                    primaryTransform3 = new SerpentEngine();
                    secondaryTransform3 = new SerpentEngine();
                    break;
                case TDEncryptionAlgorithm.TWOFISH_SERPENT:
                    primaryTransform2 = new TwofishEngine();
                    secondaryTransform2 = new TwofishEngine();
                    primaryTransform1 = new SerpentEngine();
                    secondaryTransform1 = new SerpentEngine();
                    break;
            }

            if (primaryTransform2 == null)
            {
                Array.Copy(key, 0, primaryKey1, 0, 32);
                Array.Copy(key, 32, secondaryKey1, 0, 32);
            }
            else if (primaryTransform3 == null)
            {
                Array.Copy(key, 0, primaryKey1, 0, 32);
                Array.Copy(key, 32, primaryKey2, 0, 32);
                Array.Copy(key, 64, secondaryKey1, 0, 32);
                Array.Copy(key, 96, secondaryKey2, 0, 32);
            }
            else
            {
                Array.Copy(key, 0, primaryKey1, 0, 32);
                Array.Copy(key, 32, primaryKey2, 0, 32);
                Array.Copy(key, 64, primaryKey3, 0, 32);
                Array.Copy(key, 96, secondaryKey1, 0, 32);
                Array.Copy(key, 128, secondaryKey2, 0, 32);
                Array.Copy(key, 160, secondaryKey3, 0, 32);
            }

            Log(3, "Initialising " + EncryptionEngineFriendlyName(primaryTransform1) + " for " + (decrypt ? "decryption" : "encryption") + " with primary key: " + Utils.ByteArrayToHexString(primaryKey1));
            Log(3, "Initialising " + EncryptionEngineFriendlyName(primaryTransform1) + " with secondary key: " + Utils.ByteArrayToHexString(secondaryKey1));
            if (primaryTransform1 is SerpentEngine)
            {
                primaryKey1 = Utils.ByteArrayReverse(primaryKey1);
                secondaryKey1 = Utils.ByteArrayReverse(secondaryKey1);
            }
            primaryTransform1.Init(!decrypt, new KeyParameter(primaryKey1));
            secondaryTransform1.Init(true, new KeyParameter(secondaryKey1));

            if (primaryTransform2 != null)
            {
                Log(3, "Initialising " + EncryptionEngineFriendlyName(primaryTransform2) + " for " + (decrypt ? "decryption" : "encryption") + " with primary key: " + Utils.ByteArrayToHexString(primaryKey2));
                Log(3, "Initialising " + EncryptionEngineFriendlyName(primaryTransform2) + " with secondary key: " + Utils.ByteArrayToHexString(secondaryKey2));
                if (primaryTransform2 is SerpentEngine)
                {
                    primaryKey2 = Utils.ByteArrayReverse(primaryKey2);
                    secondaryKey2 = Utils.ByteArrayReverse(secondaryKey2);
                }
                primaryTransform2.Init(!decrypt, new KeyParameter(primaryKey2));
                secondaryTransform2.Init(true, new KeyParameter(secondaryKey2));
            }
            if (primaryTransform3 != null)
            {
                Log(3, "Initialising " + EncryptionEngineFriendlyName(primaryTransform3) + " for " + (decrypt ? "decryption" : "encryption") + " with primary key: " + Utils.ByteArrayToHexString(primaryKey3));
                Log(3, "Initialising " + EncryptionEngineFriendlyName(primaryTransform3) + " with secondary key: " + Utils.ByteArrayToHexString(secondaryKey3));

                if (primaryTransform3 is SerpentEngine)
                {
                    primaryKey3 = Utils.ByteArrayReverse(primaryKey3);
                    secondaryKey3 = Utils.ByteArrayReverse(secondaryKey3);
                }
                primaryTransform3.Init(!decrypt, new KeyParameter(primaryKey3));
                secondaryTransform3.Init(true, new KeyParameter(secondaryKey3));
            }

            if (!decrypt)
            {
                if (primaryTransform3 != null)
                {
                    IBlockCipher tmp = primaryTransform1;
                    primaryTransform1 = primaryTransform3;
                    primaryTransform3 = tmp;
                    tmp = secondaryTransform1;
                    secondaryTransform1 = secondaryTransform3;
                    secondaryTransform3 = tmp;
                }
                else if (primaryTransform2 != null)
                {
                    IBlockCipher tmp = primaryTransform1;
                    primaryTransform1 = primaryTransform2;
                    primaryTransform2 = tmp;
                    tmp = secondaryTransform1;
                    secondaryTransform1 = secondaryTransform2;
                    secondaryTransform2 = tmp;
                }
            }

            inputFile.Seek(startOffset * 0x200, SeekOrigin.Begin);

            long sectorsDone = 0;

            long outerStep = 20480;

            byte[] ciphertext = new byte[outerStep * 0x200];
            byte[] plaintext = new byte[outerStep * 0x200];
            byte[] innerCiphertext = new byte[0x200];

            for (long outerCount = 0; outerCount < sectorsToProcess; outerCount += outerStep)
            {
                long todoThisTime = Math.Min(outerStep, sectorsToProcess - sectorsDone);
                int bytesRead = inputFile.Read(ciphertext, 0, (int)(todoThisTime * 0x200));

                if (bytesRead < ((int)(todoThisTime * 0x200)))
                {
                    break;
                }

                for (int innerCount = 0; innerCount < todoThisTime; innerCount++)
                {
                    Array.Copy(ciphertext, innerCount * 0x200, innerCiphertext, 0, 0x200);

                    bool v = false;

                    if (outerCount == 0 && innerCount == 0)
                    {
                        Log(3, "Processing first sector...");
                        v = true;
                    }

                    byte[] innerPlaintext = ProcessDiskSector(innerCiphertext, startSectorNumber + outerCount + innerCount, primaryTransform1, secondaryTransform1, primaryTransform2, secondaryTransform2, primaryTransform3, secondaryTransform3, v, decrypt);
                    Array.Copy(innerPlaintext, 0, plaintext, innerCount * 0x200, 0x200);
                }

                outputFile.Write(plaintext, 0, (int)(todoThisTime * 0x200));

                sectorsDone += todoThisTime;
                Log(1, "Sectors done: " + sectorsDone + " out of " + sectorsToProcess);
            }
        }

        static void Log(int logLevel, string s)
        {
            if (logLevel <= verbosity)
            {
                Console.WriteLine(s);
            }
        }

        static void Main(string[] args)
        {
            bool showHelp = false;
            bool showVersion = false;
            string password = null;
            string hexKey = null;
            string keyFilename = null;
            bool keyProvided = false;
            bool passwordCheckOnly = false;
            bool checkingPassword = true;
            bool decrypting = true;
            string volumeHeaderFilename = null;
            string volumeHeaderHex = null;
            long volumeHeaderLocation = -1;
            string inputFilename = null;
            string outputFilename = null;
            long firstDecryptSector = -1;
            long firstSectorOffset = -1;
            long sectorsToProcess = -1;
            bool decryptDirection = true;
            byte[] volumeHeaderBytes = null;
            
            VolumeHeaderResult passphraseCheckResult = null;
            bool encryptionAlgorithmSpecifiedOnCommandLine = false;
            bool hashAlgorithmSpecifiedOnCommandLine = false;
            Dictionary<TDEncryptionAlgorithm, bool> encryptionAlgorithmsEnabledCommandLine = new Dictionary<TDEncryptionAlgorithm, bool>();
            Dictionary<TDEncryptionAlgorithm, bool> encryptionAlgorithmsEnabled = new Dictionary<TDEncryptionAlgorithm, bool>();
            Dictionary<TDHashAlgorithm, bool> hashAlgorithmsEnabledCommandLine = new Dictionary<TDHashAlgorithm, bool>();
            Dictionary<TDHashAlgorithm, bool> hashAlgorithmsEnabled = new Dictionary<TDHashAlgorithm, bool>();
            TDEncryptionAlgorithm encryptionAlgorithmForProcessing = TDEncryptionAlgorithm.AES;

            foreach (TDHashAlgorithm ha in Enum.GetValues(typeof(TDHashAlgorithm)))
            {
                hashAlgorithmsEnabledCommandLine[ha] = false;
                hashAlgorithmsEnabled[ha] = false;
            }
            foreach (TDEncryptionAlgorithm ea in Enum.GetValues(typeof(TDEncryptionAlgorithm)))
            {
                encryptionAlgorithmsEnabledCommandLine[ea] = false;
                encryptionAlgorithmsEnabled[ea] = false;
            }

            var p = new OptionSet() 
            {
                { "h|help",  "Show usage information and exit", v => showHelp = v != null },
                { "V|version",  "Show version and exit", v => showVersion = v != null },
                { "v|verbose",  "Verbose mode", v => verbosity = 2 },
                { "d|debug",  "Debug mode", v => verbosity = 3 },
                { "q|quiet",  "Quiet mode", v => verbosity = 0 },
                { "p|password=", "TrueCrypt password", v => password = v},
                { "k|hex_key=", "Volume key as a hex string", v => hexKey = v},
                { "key_file=", "File containing volume key", v => keyFilename = v},
                { "i|input_file=", "Volume file for decryption", v => inputFilename = v},
                { "o|output_file=", "Destination file for decrypted data", v => outputFilename = v},
                { "e|encrypt", "Run in encryption direction instead", v => decryptDirection = false},
                { "password_check_only", "Check password but don't decrypt volume", v => passwordCheckOnly = v != null},
                { "volume_header_file=", "File containing volume header", v => volumeHeaderFilename = v},
                { "volume_header_hex=", "Volume header as a hex string", v => volumeHeaderHex = v},
                { "volume_header_location=", "Sector number of volume header in volume header file", v => volumeHeaderLocation = Utils.ConvertLongParameter( v)},
                { "first_decrypt_sector=", "Sector number in input file where decryption should begin", v => firstDecryptSector = Utils.ConvertLongParameter( v)},
                { "first_sector_offset=", "TrueCrypt logical sector number for first decrypted sector", v => firstSectorOffset = Utils.ConvertLongParameter( v)},
                { "sectors_to_process=", "Number of sectors to decrypt", v => sectorsToProcess = Utils.ConvertLongParameter( v)},
                { "aes", "Try AES encryption algorithm", v => {encryptionAlgorithmsEnabledCommandLine[TDEncryptionAlgorithm.AES] = true; encryptionAlgorithmSpecifiedOnCommandLine = true;}},
                { "serpent", "Try Serpent encryption algorithm", v => {encryptionAlgorithmsEnabledCommandLine[TDEncryptionAlgorithm.SERPENT] = true; encryptionAlgorithmSpecifiedOnCommandLine = true;}},
                { "twofish", "Try Twofish encryption algorithm", v => {encryptionAlgorithmsEnabledCommandLine[TDEncryptionAlgorithm.TWOFISH] = true; encryptionAlgorithmSpecifiedOnCommandLine = true;}},
                { "aes_twofish", "Try AES-Twofish encryption cascade", v => {encryptionAlgorithmsEnabledCommandLine[TDEncryptionAlgorithm.AES_TWOFISH] = true; encryptionAlgorithmSpecifiedOnCommandLine = true;}},
                { "aes_twofish_serpent", "Try AES-Twofish-Serpent encryption cascade", v => {encryptionAlgorithmsEnabledCommandLine[TDEncryptionAlgorithm.AES_TWOFISH_SERPENT] = true; encryptionAlgorithmSpecifiedOnCommandLine = true;}},
                { "serpent_aes", "Try Serpent-AES encryption cascade", v => {encryptionAlgorithmsEnabledCommandLine[TDEncryptionAlgorithm.SERPENT_AES] = true; encryptionAlgorithmSpecifiedOnCommandLine = true;}},
                { "serpent_twofish_aes", "Try Serpent-Twofish-AES encryption cascade", v => {encryptionAlgorithmsEnabledCommandLine[TDEncryptionAlgorithm.SERPENT_TWOFISH_AES] = true; encryptionAlgorithmSpecifiedOnCommandLine = true;}},
                { "twofish_serpent", "Try Twofish-Serpent encryption cascade", v => {encryptionAlgorithmsEnabledCommandLine[TDEncryptionAlgorithm.TWOFISH_SERPENT] = true; encryptionAlgorithmSpecifiedOnCommandLine = true;}},
                { "all_encryption_algorithms", "Try all encryption algorithms", v => { foreach (TDEncryptionAlgorithm ea in Enum.GetValues(typeof(TDEncryptionAlgorithm))) { encryptionAlgorithmsEnabledCommandLine[ea] = true; } encryptionAlgorithmSpecifiedOnCommandLine = true;}},
                { "ripemd160", "Try RIPEMD-160 hash algorithm", v => {hashAlgorithmsEnabledCommandLine[TDHashAlgorithm.RIPEMD] = true; hashAlgorithmSpecifiedOnCommandLine = true;}},
                { "ripemd160_system", "Try RIPEMD-160 hash algorithm (system encryption variant)", v => {hashAlgorithmsEnabledCommandLine[TDHashAlgorithm.RIPEMD_SYSTEM] = true; hashAlgorithmSpecifiedOnCommandLine = true;}},
                { "whirlpool", "Try Whirlpool hash algorithm", v => {hashAlgorithmsEnabledCommandLine[TDHashAlgorithm.WHIRLPOOL] = true; hashAlgorithmSpecifiedOnCommandLine = true;}},
                { "sha512", "Try SHA-512 hash algorithm", v => {hashAlgorithmsEnabledCommandLine[TDHashAlgorithm.SHA512] = true; hashAlgorithmSpecifiedOnCommandLine = true;}},
                { "all_hash_algorithms", "Try all hash algorithms", v => { foreach (TDHashAlgorithm ea in Enum.GetValues(typeof(TDHashAlgorithm))) { hashAlgorithmsEnabledCommandLine[ea] = true; } hashAlgorithmSpecifiedOnCommandLine = true;}},

            };

            List<string> extra;

            try
            {
                extra = p.Parse(args);

                foreach (string ee in extra)
                {
                    UsageError("Unrecognised option \"" + ee + "\"");
                }
            }
            catch (OptionException e)
            {
                UsageError(e.Message + "\n" + "Try 'Untrue --help' for more information");
            }

            if (showHelp)
            {
                ShowHelp(p);
                return;
            }

            if (showVersion)
            {
                ShowVersion();
                return;
            }

            if (hexKey != null || keyFilename != null)
            {
                keyProvided = true;
            }

            if (hexKey != null && keyFilename != null)
            {
                UsageError("You have provided a key in hex form and also a file containing the key. Please specify only one of these.");
            }

            if (keyProvided && passwordCheckOnly)
            {
                UsageWarning("You have asked to check the password only, but have also provided a volume key - the key will be ignored.");
                hexKey = keyFilename = null;
                keyProvided = false;
            }

            if (keyProvided && password != null)
            {
                UsageWarning("You have provided a volume key, but also provided a password. The password will be ignored.");
                password = null;
            }

            if (keyProvided)
            {
                checkingPassword = false;
            }

            if (passwordCheckOnly)
            {
                decrypting = false;
            }

            if (!checkingPassword && volumeHeaderFilename != null)
            {
                UsageWarning("Key has been supplied so volume_header_file parameter will be ignored.");
                volumeHeaderFilename = null;
            }

            if (!checkingPassword && volumeHeaderHex != null)
            {
                UsageWarning("Key has been supplied so volume_header_hex parameter will be ignored.");
                volumeHeaderHex = null;
            }

            if (!checkingPassword && volumeHeaderLocation != -1)
            {
                UsageWarning("Key has been supplied so volume_header_location parameter will be ignored.");
                volumeHeaderLocation = -1;
            }

            if (checkingPassword && volumeHeaderFilename != null && volumeHeaderHex != null)
            {
                UsageError("You have provided the volume header in hex form and also a file containing the volume header. Please specify only one of these.");
            }

            if (!decrypting && inputFilename != null)
            {
                UsageWarning("Not performing decryption (password_check_only) so input_file parameter will be ignored (use volume_header_file instead).");
                inputFilename = null;
            }

            if (!decrypting && outputFilename != null)
            {
                UsageWarning("Not performing decryption (password_check_only) so output_file parameter will be ignored (no decrypted output is generated).");
                outputFilename = null;
            }

            if (!decrypting && firstDecryptSector != -1)
            {
                UsageWarning("Not performing decryption (password_check_only) so first_decrypt_sector parameter will be ignored.");
                firstDecryptSector = -1;
            }

            if (!decrypting && firstSectorOffset != -1)
            {
                UsageWarning("Not performing decryption so first_sector_offset parameter will be ignored.");
                firstSectorOffset = -1;
            }

            if (checkingPassword)
            {
                if (!encryptionAlgorithmSpecifiedOnCommandLine)
                {
                    Log(2, "No encryption algorithms specified on command line, so trying them all");
                    foreach (TDEncryptionAlgorithm ea in Enum.GetValues(typeof(TDEncryptionAlgorithm)))
                    {
                        encryptionAlgorithmsEnabled[ea] = true;
                    }
                }
                else
                {
                    foreach (TDEncryptionAlgorithm ea in Enum.GetValues(typeof(TDEncryptionAlgorithm)))
                    {
                        encryptionAlgorithmsEnabled[ea] = encryptionAlgorithmsEnabledCommandLine[ea];
                    }
                }
                if (!hashAlgorithmSpecifiedOnCommandLine)
                {
                    Log(2, "No hash algorithms specified on command line, so trying them all");
                    foreach (TDHashAlgorithm ha in Enum.GetValues(typeof(TDHashAlgorithm)))
                    {
                        hashAlgorithmsEnabled[ha] = true;
                    }
                }
                else
                {
                    foreach (TDHashAlgorithm ea in Enum.GetValues(typeof(TDHashAlgorithm)))
                    {
                        hashAlgorithmsEnabled[ea] = hashAlgorithmsEnabledCommandLine[ea];
                    }
                }
            }

            if (decrypting)
            {
                // sort out encryption algorithms
                if (!checkingPassword)
                {
                    if (!encryptionAlgorithmSpecifiedOnCommandLine)
                    {
                        Log(2, "No encryption algorithm specified on command line, so using the default (AES)");
                        encryptionAlgorithmsEnabled[TDEncryptionAlgorithm.AES] = true;
                    }
                    else
                    {
                        int count = 0;
                        foreach (TDEncryptionAlgorithm ea in Enum.GetValues(typeof(TDEncryptionAlgorithm)))
                        {
                            if (encryptionAlgorithmsEnabledCommandLine[ea])
                            {
                                encryptionAlgorithmsEnabled[ea] = true;
                                encryptionAlgorithmForProcessing = ea;
                                count += 1;
                            }
                        }

                        if (count > 1)
                        {
                            UsageError("Please specify only one encryption algorithm");
                        }

                        if (hashAlgorithmSpecifiedOnCommandLine)
                        {
                            UsageWarning("Hash algorithms specified on command line will be ignored when not checking passwords.");
                        }
                    }
                }

                if( !checkingPassword && !keyProvided)
                {
                    UsageError("No volume key provided (use --hex_key or --key_file)");
                }

                if( !checkingPassword && keyFilename != null)
                {
                    try
                    {
                        keyFile = File.Open(keyFilename, FileMode.Open, FileAccess.Read);
                    }
                    catch (IOException)
                    {
                        UsageError(String.Format( "Couldn't open key file {0} for reading", keyFilename));
                    }
                }

                if (inputFilename == null)
                {
                    UsageError("No input file specified (use --input_file)");
                }
                else
                {
                    try
                    {
                        inputFile = File.Open(inputFilename, FileMode.Open, FileAccess.Read);
                    }
                    catch (IOException)
                    {
                        UsageError(String.Format( "Couldn't open input file {0} for reading", inputFilename));
                    }
                }

                if (outputFilename == null)
                {
                    UsageError("No output file specified (use --output_file)");
                }
                else
                {
                    if (File.Exists(outputFilename))
                    {
                        UsageError(String.Format("Output file {0} already exists, won't write to existing file.", outputFilename));
                    }
                }

                if (!checkingPassword && firstDecryptSector == -1)  // if we *are* checking the password then default to obtaining first decrypt sector from decrypted volume header
                {
                    firstDecryptSector = 0;
                }

                if (!checkingPassword && firstSectorOffset == -1)  
                {
                    Log(1, "Setting XTS secondary key offset to " + firstDecryptSector.ToString() + ". This might be right and it might not. Set it explicitly (using --first_sector_offset) if your input file doesn't contain the entire encrypted volume");
                    firstSectorOffset = firstDecryptSector;
                }

                if (!checkingPassword && sectorsToProcess == -1)  // we'll just process to the end of the input file... but if we *are* checking the password then we're going to default to obtaining number of sectors from decrypted volume header
                {
                    sectorsToProcess = (inputFile.Length / SECTOR_SIZE) - firstDecryptSector;
                }

                if (sectorsToProcess != -1 && (sectorsToProcess > ((inputFile.Length / SECTOR_SIZE) - firstDecryptSector)))
                {
                    UsageError("Number of specified sectors to process will go beyond end of input file.");
                }
            }

            if (checkingPassword)
            {
                if (password == null)
                {
                    UsageError("No volume password supplied.");
                }

                if (volumeHeaderHex == null)
                {
                    if (volumeHeaderFilename == null)
                    {
                        if (inputFile != null)
                        {
                            volumeHeaderFile = inputFile;
                        }
                        else
                        {
                            UsageError("No volume header file specified (and no input file).");
                        }
                    }
                    else
                    {
                        try
                        {
                            volumeHeaderFile = File.Open(volumeHeaderFilename, FileMode.Open, FileAccess.Read);
                        }
                        catch (IOException)
                        {
                            UsageError(String.Format("Couldn't open volume header file {0} for reading", volumeHeaderFilename));
                        }
                    }
                }

                if (volumeHeaderHex == null && volumeHeaderLocation == -1)
                {
                    byte[] volumeHeaderSector = Utils.ReadSector(volumeHeaderFile, 0);

                    SectorGuess guess = GuessSectorFormat(volumeHeaderSector);

                    string s = volumeHeaderFilename == null ? "input file" : "volume header file";

                    if (guess == SectorGuess.CIPHERTEXT)
                    {
                        Log(1, "Sector 0 of " + s + " appears to be encrypted - trying this as the volume header");
                        volumeHeaderLocation = 0;
                    }
                    else if (guess == SectorGuess.ZEROS)
                    {
                        Log(1, "Sector 0 of " + s + " is all zeros - assuming this to be a rescue file image, and reading volume header from sector " + VOLUME_HEADER_SECTOR_ON_RESCUE_DISK.ToString());
                        volumeHeaderLocation = VOLUME_HEADER_SECTOR_ON_RESCUE_DISK;
                    }
                    else if (guess == SectorGuess.TRUECRYPT_MBR)
                    {
                        Log(1, "Sector 0 of " + s + " is a TrueCrypt MBR - reading volume header from sector " + VOLUME_HEADER_SECTOR_ON_FIRST_TRACK);
                        volumeHeaderLocation = VOLUME_HEADER_SECTOR_ON_FIRST_TRACK;
                    }
                    else
                    {
                        Log(1, "Trying sector 0 of " + s + " as the volume header, although it does not appear to be encrypted and its format is not recognised");
                        volumeHeaderLocation = 0;
                    }
                }
                else
                {
                    byte[] volumeHeaderSector = Utils.ReadSector(volumeHeaderFile, volumeHeaderLocation);
                    SectorGuess guess = GuessSectorFormat(volumeHeaderSector);
                    string s = volumeHeaderFilename == null ? "input file" : "volume header file";

                    if (guess != SectorGuess.CIPHERTEXT)
                    {
                        Log(1, "Specified volume header sector does not appear to be encrypted - trying it anyway. Note that Untrue will attempt to locate volume header sector itself if you omit the volume_header_location parameter");
                    }
                }

                if (volumeHeaderHex != null)
                {
                    try
                    {
                        volumeHeaderBytes = Utils.ConvertHexStringToBytes(volumeHeaderHex);
                    }
                    catch (FormatException)
                    {
                        UsageError("Failed to parse volume_header_hex as hex string");
                    }

                    if (volumeHeaderBytes.Length != VOLUME_HEADER_SIZE)
                    {
                        UsageError(String.Format("volume_header_hex should be a hex string of exactly {0} bytes", VOLUME_HEADER_SIZE));
                    }

                    SectorGuess guess = GuessSectorFormat(volumeHeaderBytes);

                    if (guess != SectorGuess.CIPHERTEXT)
                    {
                        Log(1, "Volume header provided does not appear to be an encrypted sector - trying it anyway");
                    }
                }
                else
                {
                    if (volumeHeaderLocation * SECTOR_SIZE + VOLUME_HEADER_SIZE > volumeHeaderFile.Length)
                    {
                        UsageError("Specified volume header location will go beyond end of volume header file.");
                    }

                    try
                    {
                        volumeHeaderBytes = Utils.ReadSector(volumeHeaderFile, volumeHeaderLocation);
                    }
                    catch
                    {
                        UsageError("Failed to read volume header from file");
                    }
                }

                passphraseCheckResult = DecryptVolumeHeader(volumeHeaderBytes, password, hashAlgorithmsEnabled, encryptionAlgorithmsEnabled);
                encryptionAlgorithmForProcessing = passphraseCheckResult.ea;

                if (passphraseCheckResult.Success)
                {
                    Log(1, "Passphrase \"" + password + "\" was correct");
                    Log(1, "Encryption algorithm was " + EncryptionAlgorithmFriendlyName(passphraseCheckResult.ea));
                    Log(1, "Hash algorithm was " + HashAlgorithmFriendlyName(passphraseCheckResult.ha));
                }
                else
                {
                    Log(1, "Failed to decrypt volume header - incorrect passphrase?");
                    if (decrypting)
                    {
                        Log(1, (decrypting ? "Decryption" : "Encryption") + " cannot be performed.");
                    }
                }
            }

            if (decrypting && (passphraseCheckResult == null || passphraseCheckResult.Success))
            {
                if (firstDecryptSector == -1 && passphraseCheckResult != null && passphraseCheckResult.Success)
                {
                    
                    firstDecryptSector = passphraseCheckResult.CiphertextOffset / SECTOR_SIZE;
                }

                if (firstSectorOffset == -1 && passphraseCheckResult != null && passphraseCheckResult.Success)
                {
                    Log(2, String.Format("Setting first sector offset to 0x{0:x}", firstDecryptSector));
                    firstSectorOffset = firstDecryptSector;
                }

                if (sectorsToProcess == -1 && passphraseCheckResult != null && passphraseCheckResult.Success)
                {
                    Log(2, String.Format("Setting sectors to process to 0x{0:x}", Math.Min(passphraseCheckResult.CiphertextLength / SECTOR_SIZE, (inputFile.Length - firstDecryptSector * SECTOR_SIZE) / SECTOR_SIZE)));
                    sectorsToProcess = Math.Min(passphraseCheckResult.CiphertextLength / SECTOR_SIZE, (inputFile.Length - firstDecryptSector * SECTOR_SIZE) / SECTOR_SIZE);
                }

                if ((firstDecryptSector + sectorsToProcess) * SECTOR_SIZE > inputFile.Length)
                {
                    UsageError("Going to read beyond end of input file, use a smaller sectors_to_process value");
                    return;
                }

                byte[] firstCiphertextSector = Utils.ReadSector(inputFile, firstDecryptSector);
                SectorGuess guess = GuessSectorFormat(firstCiphertextSector);

                if (guess != SectorGuess.CIPHERTEXT)
                {
                    Log(1, "First sector for processing does not appear to be encrypted, trying anyway");
                }

                int keyLengthRequired = KeyLengthForEncryptionAlgorithm(encryptionAlgorithmForProcessing);
                byte[] volumeKey = new byte[keyLengthRequired];

                if (passphraseCheckResult != null)
                {
                    volumeKey = passphraseCheckResult.VolumeKey;
                }
                else
                {
                    if (hexKey != null)
                    {
                        if (hexKey.Length != keyLengthRequired * 2)
                        {
                            UsageError( "Hexadecimal key should be " + keyLengthRequired + " bytes");
                        }
                        else
                        {
                            volumeKey = Utils.ConvertHexStringToBytes(hexKey);
                        }
                    }
                    else
                    {
                        int keyBytesRead = keyFile.Read( volumeKey, 0, keyLengthRequired);

                        if( keyBytesRead < keyLengthRequired)
                        {
                            UsageError( "Failed to read " + keyLengthRequired + " key bytes from file");
                        }
                    }
                }

                try
                {
                    outputFile = File.Open(outputFilename, FileMode.CreateNew, FileAccess.Write);
                }
                catch (IOException)
                {
                    UsageError(String.Format("Couldn't open output file {0} for writing", outputFilename));
                }

                ProcessSectors(inputFile, outputFile, firstDecryptSector, firstSectorOffset, sectorsToProcess, volumeKey, encryptionAlgorithmForProcessing, decryptDirection);
            }
        }
    }
}
