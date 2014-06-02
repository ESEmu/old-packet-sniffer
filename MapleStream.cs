using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace MapleShark
{
    public enum TransformLocale
    {
        SPECIAL,
        AES,
        AES_MCRYPTO,
        MCRYPTO,
        OLDEST_MCRYPTO,
        NONE,
    }

    public sealed class MapleStream
    {
        private const int DEFAULT_SIZE = 4096;

        private bool mOutbound = false;
        private MapleDES mDES = null;
        private byte[] mBuffer = new byte[DEFAULT_SIZE];
        private int mCursor = 0;

        public MapleStream(bool pOutbound, ushort pBuild, byte pLocale, byte[] pIV) { 
            mOutbound = pOutbound; 
            mDES = new MapleDES(pBuild, pLocale);
        }

        public void Append(byte[] packetBuffer, ref byte[] dataBuffer)
        {
            byte[] temp = new byte[dataBuffer.Length + packetBuffer.Length];
            dataBuffer.CopyTo(temp, 0);
            packetBuffer.CopyTo(temp, dataBuffer.Length);
            dataBuffer = new byte[temp.Length];
            temp.CopyTo(dataBuffer, 0);
            Console.WriteLine("APPENDED: " + dataBuffer.Length);
        }
        
        public MaplePacket Read(DateTime pTransmitted, ushort pBuild, byte pLocale, ref bool firstPacket, ref byte[] dataBuffer, ref byte[] curIV)
        {
            Console.WriteLine(dataBuffer.Length);
            Console.WriteLine("BUFFER DATA:\n--------");
            for (int i = 0; i < dataBuffer.Length; i++)
            {
                Console.Write("0x");
                if (dataBuffer[i] < 16)
                {
                    Console.Write("0");
                    Console.Write(dataBuffer[i].ToString("X"));
                }
                else
                {
                    Console.Write(dataBuffer[i].ToString("X"));
                }
                Console.Write(" ");
            }
            Console.WriteLine("-------");
            if (dataBuffer.Length == 0)
            {
                return null;
            }
            ushort packetSize = mDES.GetHeaderLength(dataBuffer, 0);
            if (packetSize > dataBuffer.Length)
            {
                Console.WriteLine("INCOMPLETE PACKET:" + packetSize + "Buffer Size: " + dataBuffer.Length);
                for (int i = 0; i < dataBuffer.Length; i++)
                {
                    Console.Write("0x");
                    if (dataBuffer[i] < 16)
                    {
                        Console.Write("0");
                        Console.Write(dataBuffer[i].ToString("X"));
                    }
                    else
                    {
                        Console.Write(dataBuffer[i].ToString("X"));
                    }
                    Console.Write(" ");
                }
                return null;
            }

            curIV = mDES.GetIV(dataBuffer);
            mDES.SetIV(curIV);

            byte[] packetBuffer = new byte[packetSize];
            Buffer.BlockCopy(dataBuffer, 16, packetBuffer, 0, packetSize - 26); // last two bytes not needed(18) + 8

            //bool byteheader = false;

            byte[] decryptedBuffer = mDES.Decrypt(packetBuffer, firstPacket, true, null);
            if (firstPacket)
            {
                Console.Write("\nCHANGING KEY");
                mDES.SetKey(decryptedBuffer);
                firstPacket = false;

            }

            byte[] temp = new byte[dataBuffer.Length - packetSize];
            Buffer.BlockCopy(dataBuffer, packetSize, temp, 0, dataBuffer.Length - packetSize);
            dataBuffer = new byte[temp.Length];
            temp.CopyTo(dataBuffer, 0);
            
            ushort opcode=1;
            
            Definition definition = Config.Instance.GetDefinition(pBuild, pLocale, mOutbound, opcode);
            return new MaplePacket(pTransmitted, mOutbound, pBuild, pLocale, opcode, definition == null ? "" : definition.Name, decryptedBuffer);
        }
       
    }
}