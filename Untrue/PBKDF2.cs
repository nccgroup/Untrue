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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Macs;

namespace Untrue
{
    // this is a modified version of the Bouncy Castle PBKDF2 routine (which only supports SHA-1 digests - we need more flexibility here)
    // based on code from https://stackoverflow.com/questions/3210795/pbkdf2-in-bouncy-castle-c-sharp
    public class PBKDF2
    {
        private IMac hMac;

        public PBKDF2(IDigest digest)
        {
            hMac = new HMac(digest);
        }

        private void F(
            byte[] P,
            byte[] S,
            int c,
            byte[] iBuf,
            byte[] outBytes,
            int outOff)
        {
            byte[] state = new byte[hMac.GetMacSize()];
            ICipherParameters param = new KeyParameter(P);

            hMac.Init(param);

            if (S != null)
            {
                hMac.BlockUpdate(S, 0, S.Length);
            }

            hMac.BlockUpdate(iBuf, 0, iBuf.Length);

            hMac.DoFinal(state, 0);

            Array.Copy(state, 0, outBytes, outOff, state.Length);

            for (int count = 1; count != c; count++)
            {
                hMac.Init(param);
                hMac.BlockUpdate(state, 0, state.Length);
                hMac.DoFinal(state, 0);

                for (int j = 0; j != state.Length; j++)
                {
                    outBytes[outOff + j] ^= state[j];
                }
            }
        }

        private static void IntToOctet(
            byte[] Buffer,
            int i)
        {
            Buffer[0] = (byte)((uint)i >> 24);
            Buffer[1] = (byte)((uint)i >> 16);
            Buffer[2] = (byte)((uint)i >> 8);
            Buffer[3] = (byte)i;
        }

        public byte[] GetBytes(int outputLength, byte[] password, byte[] salt, int iterationsCount)
        {
            int hLen = hMac.GetMacSize();
            int l = (outputLength + hLen - 1) / hLen;
            byte[] iBuf = new byte[4];
            byte[] keyBuffer = new byte[l * hLen];

            for (int ii = 1; ii <= l; ii++)
            {
                IntToOctet(iBuf, ii);

                F(password, salt, iterationsCount, iBuf, keyBuffer, (ii - 1) * hLen);
            }

            byte[] outBytes = new byte[outputLength];
            Array.Copy(keyBuffer, outBytes, outputLength);

            return outBytes;
        }
    }
}
