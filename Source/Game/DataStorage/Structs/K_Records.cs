// Copyright (c) CypherCore <http://github.com/CypherCore> All rights reserved.
// Licensed under the GNU GENERAL PUBLIC LICENSE. See LICENSE file in the project root for full license information.

namespace Game.DataStorage
{
    public sealed class KeyChainRecord
    {
        public uint Id;
        //public byte Key1;
        //public byte Key2;
        //public byte Key3;
        //public byte Key4;
        //public byte Key5;
        //public byte Key6;
        //public byte Key7;
        //public byte Key8;
        //public byte Key9;
        //public byte Key10;
        //public byte Key11;
        //public byte Key12;
        //public byte Key13;
        //public byte Key14;
        //public byte Key15;
        //public byte Key16;
        //public byte Key17;
        //public byte Key18;
        //public byte Key19;
        //public byte Key20;
        //public byte Key21;
        //public byte Key22;
        //public byte Key23;
        //public byte Key24;
        //public byte Key25;
        //public byte Key26;
        //public byte Key27;
        //public byte Key28;
        //public byte Key29;
        //public byte Key30;
        //public byte Key31;
        //public byte Key32;
        public byte[] Key = new byte[32];
    }

    public sealed class KeystoneAffixRecord
    {
        public LocalizedString Name;
        public LocalizedString Description;
        public uint Id;
        public int FiledataID;
    }
}