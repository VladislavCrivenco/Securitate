using System;

/**
 * To use this class:
 *
 * 1. set the initial vector (IV) using DES.setIv(ulong iv)
 * 2. to Encrypt use DES.encryptCBC(byte[] plaintext, byte[] key)
 * 3. to Decrypt use DES.decryptCBC(byte[] ciphertext, byte[] key)
 *
 */

/**
 * Super-slow DES implementation for the overly patient.
 * <p/>
 * The following resources proved valuable in developing and testing
 * this code:
 * <p/>
 * "Data Encryption Standard" from Wikipedia, the free encyclopedia
 * http://en.wikipedia.org/wiki/Data_Encryption_Standard
 * <p/>
 * "The DES Algorithm Illustrated" by J. Orlin Grabbe
 * http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
 * <p/>
 * "DES Calculator" by Lawrie Brown
 * http://www.unsw.adfa.edu.au/~lpb/src/DEScalc/DEScalc.html
 * <p/>
 * April 6, 2011
 *
 * @author David Simmons - http://cafbit.com/
 */

namespace Securitate_Informationala
{
    public class DES
    {
        private static byte[] IPTable = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

        private static byte[] FPTable = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };


        private static byte[] ETable = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
    };

        private static byte[,] STable = new byte[,]{{
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    }, {
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    }, {
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
            1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    }, {
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
            3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    }, {
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
            4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    }, {
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    }, {
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    }, {
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    }};


        private static byte[] PTable = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
    };

        private static byte[] PC1Table = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
    };

        private static byte[] PC2Table = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };


        private static byte[] rotationsTable = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };


        private static ulong IP(ulong src)
        {
            return permute(IPTable, 64, src);
        } // 64-bit output

        private static ulong FP(ulong src)
        {
            return permute(FPTable, 64, src);
        } // 64-bit output

        private static ulong E(uint src)
        {
            return permute(ETable, 32, src & 0xFFFFFFFFUL);
        } // 48-bit output

        private static uint P(uint src)
        {
            return (uint)permute(PTable, 32, src & 0xFFFFFFFFUL);
        } // 32-bit output

        private static ulong PC1(ulong src)
        {
            return permute(PC1Table, 64, src);
        } // 56-bit output

        private static ulong PC2(ulong src)
        {
            return permute(PC2Table, 56, src);
        } // 48-bit output

        private static ulong permute(byte[] table, int srcWidth, ulong src)
        {
            ulong dst = 0;
            for (int i = 0; i < table.Length; i++)
            {
                int srcPos = srcWidth - table[i];
                dst = (dst << 1) | (src >> srcPos & 0x01);
            }
            return dst;
        }


        private static byte S(int boxNumber, byte src)
        {

            src = (byte)(src & 0x20 | ((src & 0x01) << 4) | ((src & 0x1E) >> 1));
            return STable[boxNumber - 1, src];
        }

        private static ulong getulongFromBytes(byte[] ba, int offset)
        {
            ulong l = 0;
            for (int i = 0; i < 8; i++)
            {
                byte value;
                if ((offset + i) < ba.Length)
                {

                    value = ba[offset + i];
                }
                else
                {
                    value = 0;
                }
                l = l << 8 | (value & 0xFFUL);
            }
            return l;
        }

        private static void getBytesFromulong(byte[] ba, int offset, ulong l)
        {
            for (int i = 7; i > -1; i--)
            {
                if ((offset + i) < ba.Length)
                {
                    ba[offset + i] = (byte)(l & 0xFF);
                    l = l >> 8;
                }
                else
                {
                    break;
                }
            }
        }

        private static uint feistel(uint r, /* 48 bits */ ulong subkey)
        {
            // 1. expansion
            ulong e = E(r);
            // 2. key mixing
            ulong x = e ^ subkey;
            // 3. substitution
            uint dst = 0;
            for (int i = 0; i < 8; i++)
            {
                dst >>= 4;
                uint s = S(8 - i, (byte)(x & 0x3F));
                dst |= s << 28;
                x >>= 6;
            }
            // 4. permutation
            return P(dst);
        }

        private static ulong[] createSubkeys(/* 64 bits */ ulong key)
        {
            ulong[] subkeys = new ulong[16];

            key = PC1(key);

            uint c = (uint)(key >> 28);
            uint d = (uint)(key & 0x0FFFFFFF);

            for (int i = 0; i < 16; i++)
            {

                if (rotationsTable[i] == 1)
                {

                    c = ((c << 1) & 0x0FFFFFFF) | (c >> 27);
                    d = ((d << 1) & 0x0FFFFFFF) | (d >> 27);
                }
                else
                {

                    c = ((c << 2) & 0x0FFFFFFF) | (c >> 26);
                    d = ((d << 2) & 0x0FFFFFFF) | (d >> 26);
                }
                ulong cd = (c & 0xFFFFFFFFUL) << 28 | (d & 0xFFFFFFFFUL);

                subkeys[i] = PC2(cd);
            }
            return subkeys;
        }
        public static ulong processBlock(ulong m, /* 64 bits */ ulong key, bool encrypt)
        {
            ulong[] subkeys = createSubkeys(key);
            ulong ip = IP(m);
            uint l = (uint)(ip >> 32);
            uint r = (uint)(ip & 0xFFFFFFFFUL);

            if (encrypt)
            {
                for (int i = 0; i < 16; i++)
                {
                    uint previous_l = l;
                    l = r;
                    r = previous_l ^ feistel(r, subkeys[i]);
                }
            }
            else
            {
                for (int i = 15; i >= 0; i--)
                {
                    uint previous_l = l;
                    l = r;
                    r = previous_l ^ feistel(r, subkeys[i]);
                }
            }

            ulong rl = (r & 0xFFFFFFFFUL) << 32 | (l & 0xFFFFFFFFUL);

            ulong fp = FP(rl);

            return fp;
        }

        public static void processBlock(
                byte[] message,
                int messageOffset,
                byte[] ciphertext,
                int ciphertextOffset,
                byte[] key,
                bool encrypt
        )
        {
            ulong m = getulongFromBytes(message, messageOffset);
            ulong k = getulongFromBytes(key, 0);
            ulong c = processBlock(m, k, encrypt);
            getBytesFromulong(ciphertext, ciphertextOffset, c);
        }

        private static byte[] ToBytes(String s)
        {
            return System.Text.Encoding.Unicode.GetBytes(s);
        }
        private static string FromBytes(byte[] bytes)
        {
            return System.Text.Encoding.Unicode.GetString(bytes);
        }

        private static String ToHex(byte[] bytes)
        {
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append(String.Format("{0:X2} ", bytes[i]));
            }
            return sb.ToString();
        }


        public static byte[] encrypt(byte[] message, byte[] key)
        {
            return des(message, key, true);
        }
        public static byte[] decrypt(byte[] ciphertext, byte[] key)
        {
            return des(ciphertext, key, false);
        }

        public static byte[] des(byte[] ciphertext, byte[] key, bool encrypt)
        {
            byte[] message = new byte[ciphertext.Length];
            ulong k = getulongFromBytes(key, 0);

            for (int i = 0; i < ciphertext.Length; i += 8)
            {

                ulong cipherBlock = getulongFromBytes(ciphertext, i);

                ulong messageBlock = processBlock(cipherBlock, k, encrypt);

                getBytesFromulong(message, i, messageBlock);
            }

            return message;
        }
        public static void Main(String[] args)
        {
            String oriText = "Some nice plain text";
            String key = "mypass";
            byte[] keys = ToBytes(key);
            byte[] test = ToBytes(oriText);

            Console.WriteLine("Key:  " + ToHex(keys));
            Console.WriteLine("Key:  " + key);
            Console.WriteLine("ORIGINAL TEXT:  " + ToHex(test));
            Console.WriteLine("ORIGINAL TEXT:  " + oriText);

            Console.WriteLine();

            var encResult = encrypt(test, keys);
            Console.WriteLine("Encryption result:  " + ToHex(encResult));
            Console.WriteLine("ENCRYPTED TEXT: " + FromBytes(encResult));

            var decResult = decrypt(encResult, keys);
            Console.WriteLine("Decryption result:  " + ToHex(decResult));
            Console.WriteLine("DECRYPTED TEXT: " + FromBytes(decResult));
        }
    }
}