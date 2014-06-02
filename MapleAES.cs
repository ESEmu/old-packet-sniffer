using System;
using System.IO;
using System.Security.Cryptography;

namespace MapleShark
{
    public sealed class MapleDES
    {
        private static byte[] sSecretKey = new byte[] {
            0xC7, 0xD8, 0xC4, 0xBF, 0xB5, 0xE9, 0xC0, 0xFD
        };

        private static byte[] sDynamicKey = new byte[] {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        
        private ushort mBuild = 0;
        private DES mDES = DES.Create();
        private ICryptoTransform mTransformer = null;
        public byte[] mIV { get; private set; }

        internal MapleDES(ushort pBuild, byte pLocale)
        {
            mBuild = pBuild;
            if ((short)pBuild < 0) { // Second one
                pBuild = (ushort)(0xFFFF - pBuild);
            }
            mDES.Key = sSecretKey;
            mDES.Mode = CipherMode.CBC;
            mTransformer = mDES.CreateEncryptor();
        }

        public ushort GetHeaderLength(byte[] pBuffer, int pStart)
        {
			return BitConverter.ToUInt16(pBuffer, pStart);

        }

        public byte[] GetIV(byte[] pBuffer)
        {
            byte[] packetiv;
            packetiv = new byte[8];
            for (int i = 8; i < 16; i++)
            {
                packetiv[i-8] = pBuffer[i];
            }
            for (int i = 0; i < packetiv.Length; i++)
            {
                Console.Write("0x");
                if (packetiv[i] < 16)
                {
                    Console.Write("0");
                    Console.Write(packetiv[i].ToString("X"));
                }
                else
                {
                    Console.Write(packetiv[i].ToString("X"));
                }
                Console.Write(" ");
            }
            return packetiv;
        }

        public void SetIV(byte[] iv)
        {
            mDES.IV = iv;
        }

        public void SetKey(byte[] pBuffer)
        {
            for (int i = 49; i < 57; i++)
            {
                sDynamicKey[i - 49] = pBuffer[i];
            }
            for (int i = 0; i < sDynamicKey.Length; i++)
            {
                Console.Write("0x");
                if (sSecretKey[i] < 16)
                {
                    Console.Write("0");
                    Console.Write(sDynamicKey[i].ToString("X"));
                }
                else
                {
                    Console.Write(sDynamicKey[i].ToString("X"));
                }
                Console.Write(" ");
            }
        }

        public byte[] Decrypt(byte[] pBuffer, bool firstPacket, bool useStandardIV, byte[] nonStandardIV)
        {
            if (firstPacket)
            {
                mDES.Key = sSecretKey;
            }
            else
            {
                mDES.Key = sDynamicKey;
            }
            if (!useStandardIV)
            {
                mDES.IV = nonStandardIV;
            }
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms,
            mDES.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(pBuffer, 0, pBuffer.Length-18);
            return ms.ToArray();
        }
    }
}
