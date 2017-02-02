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
using System.Text.RegularExpressions;
using System.IO;

namespace Untrue
{
    public class Utils
    {
        public static int SECTOR_SIZE = 0x200;

        // check if the given string represents valid hex-encoded data
        public static bool IsValidHexString(string s)
        {
            // remove all whitespace (we don't care if hex inputs contain whitespace)
            s = Regex.Replace(s, @"\s", "");

            // we allow hyphen characters, but only on byte boundaries (where obviously a byte is represented by two hex digits)
            int hyphenIndex;
            int hyphensSoFar = 0;
            while ((hyphenIndex = s.IndexOf('-')) != -1)
            {
                if (((hyphenIndex - hyphensSoFar) % 2) != 0)
                {
                    return false;
                }
            }
            s = s.Replace("-", "");

            // check we have an even number of characters
            if (s.Length % 2 != 0)
            {
                return false;
            }

            // now check it's all hex digits
            s = s.ToLower();
            foreach (char c in s)
            {
                if (!Char.IsLetterOrDigit(c))
                {
                    return false;
                }
                if (c > 'f')
                {
                    return false;
                }
            }

            return true;
        }

        public static byte[] ConvertHexStringToBytes(string s)
        {
            if (!IsValidHexString(s))
            {
                throw new FormatException("Hex string passed to ConvertHexStringToBytes() was invalid");
            }

            // remove all whitespace (we don't care if hex inputs contain whitespace)
            s = Regex.Replace(s, @"\s", "");
            s = s.Replace("-", "");

            byte[] b = new byte[s.Length / 2];

            for (int ii = 0; ii < s.Length; ii += 2)
            {
                b[ii / 2] = Convert.ToByte(s.Substring(ii, 2), 16);
            }

            return b;
        }

        public static string ByteArrayToHexString(byte[] bytes)
        {
            string s = "";
            foreach (byte b in bytes)
            {
                s += String.Format("{0:x2}", b);
            }
            return s;
        }

        public static byte[] ReadSector(FileStream fs, long sectorNumber)
        {
            fs.Seek(sectorNumber * SECTOR_SIZE, SeekOrigin.Begin);
            byte[] data = new byte[SECTOR_SIZE];

            int bytesRead = fs.Read(data, 0, (int)SECTOR_SIZE);

            if (bytesRead < SECTOR_SIZE)
            {
                throw new Exception("Failed to read full sector in ReadSector");
            }

            return data;
        }

        public static long ConvertLongParameter(string input)
        {
            input = input.Trim();
            if (input.StartsWith("0x"))
            {
                return Convert.ToInt64(input, 16);
            }
            else
            {
                return Convert.ToInt64(input);
            }
        }

        public static long ReadLongFromByteArray(byte[] input, int offset)
        {
            long ret = 0;
            ret += (((long)input[offset]) << 56);
            ret += (((long)input[offset + 1]) << 48);
            ret += (((long)input[offset + 2]) << 40);
            ret += (((long)input[offset + 3]) << 32);
            ret += (((long)input[offset + 4]) << 24);
            ret += (((long)input[offset + 5]) << 16);
            ret += (((long)input[offset + 6]) << 8);
            ret += (((long)input[offset + 7]));

            return ret;
        }

        public static double CalculateChiSquareTestStatisticOnBytes(byte[] bytes)
        {
            int[] counts = new int[256];
            for (int ii = 0; ii < 256; ii++)
            {
                counts[ii] = 0;
            }
            foreach (byte b in bytes)
            {
                counts[b]++;
            }

            double Ei = ((double)bytes.Length) / 256.0;

            double total = 0.0;

            for (int ii = 0; ii < 256; ii++)
            {
                double zz = ((double)counts[ii]) - Ei;
                total += (zz * zz);
            }

            return total / Ei;
        }

        public static byte[] ByteArrayReverse(byte[] input)
        {
            byte[] output = new byte[input.Length];

            for (int ii = 0; ii < input.Length; ii++)
            {
                output[output.Length - 1 - ii] = input[ii];
            }

            return output;
        }

        public static bool? IsDirFile(string path)
        {
            if (!Directory.Exists(path) && !File.Exists(path))
                return null;
            var fileAttr = File.GetAttributes(path);
            return !fileAttr.HasFlag(FileAttributes.Directory);
        }

    }
}
