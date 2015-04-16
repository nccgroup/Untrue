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

namespace Untrue
{
    public class VolumeHeaderResult
    {
        public bool Success
        {
            get;
            set;
        }

        public TDHashAlgorithm ha
        {
            get;
            set;
        }

        public TDEncryptionAlgorithm ea
        {
            get;
            set;
        }

        public byte[] VolumeKey
        {
            get;
            set;
        }

        public long CiphertextOffset
        {
            get;
            set;
        }

        public long CiphertextLength
        {
            get;
            set;
        }
    }
}
