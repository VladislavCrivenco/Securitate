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

 namespace Securitate_Informationala{
public class DES {
    //permutarea de la inceputul algoritmului
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
//permutarea finala, pentru ca sa generam "ciphertext" / textu criptat

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

//functia Feistel. Impartirea la jumatatea blocului de 32 bits si crearea
    //valorii extinse 48 bits.

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
// 48bits a lui Feistel impartim in 6 seectii. Fiecare sectie
// este permutata in  6biti diferiti conform la 8 tabele de jos.
    // tabele = S-boxuri, fara ele textul criptat este linear si usor de stricat.

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

    //P permutatii. Aplicarea permutarilor pe 32 bits dupa ce am facut S-box de mai sus.

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


// PC permutari. Key de 64 bits este permutata dupa tabelul de jos in 56.(?)

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

    //PC2 permutari. Rezultatul de 56 bits este transformat intr-un set de
    // 16 key de 48 bits.

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

    //miscam bitii in stinga. Specificam cu cit sa ii miscam.

    private static byte[] rotationsTable = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };


    private static ulong IP(ulong src) {
        return permute(IPTable, 64, src);
    } // 64-bit output

    private static ulong FP(ulong src) {
        return permute(FPTable, 64, src);
    } // 64-bit output

    private static ulong E(uint src) {
        return permute(ETable, 32, src & 0xFFFFFFFFUL);
    } // 48-bit output

    private static uint P(uint src) {
        return (uint) permute(PTable, 32, src & 0xFFFFFFFFUL);
    } // 32-bit output

    private static ulong PC1(ulong src) {
        return permute(PC1Table, 64, src);
    } // 56-bit output

    private static ulong PC2(ulong src) {
        return permute(PC2Table, 56, src);
    } // 48-bit output


    private static ulong permute(byte[] table, int srcWidth, ulong src) {
        ulong dst = 0;
        for (int i = 0; i < table.Length; i++) {
            int srcPos = srcWidth - table[i];
            dst = (dst << 1) | (src >> srcPos & 0x01);
        }
        return dst;
    }


    private static byte S(int boxNumber, byte src) {

        src = (byte) (src & 0x20 | ((src & 0x01) << 4) | ((src & 0x1E) >> 1));
        return STable[boxNumber - 1, src];
    }

    //convertam 8 biti intr-o singura valoarea de 64 biti.

    private static ulong getulongFromBytes(byte[] ba, int offset) {
        ulong l = 0;
        for (int i = 0; i < 8; i++) {
            byte value;
            if ((offset + i) < ba.Length) {

                value = ba[offset + i];
            } else {
                value = 0;
            }
            l = l << 8 | (value & 0xFFUL);
        }
        return l;
    }

    //Convertam valoarea de 64 biti in 8 bytes, care sunt scrisi
    //intr-un array specificat de offset.

    private static void getBytesFromulong(byte[] ba, int offset, ulong l) {
        for (int i = 7; i > -1; i--) {
            if ((offset + i) < ba.Length) {
                ba[offset + i] = (byte) (l & 0xFF);
                l = l >> 8;
            } else {
                break;
            }
        }
    }

    // FUNCTIA FEISTEL !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    private static uint feistel(uint r, /* 48 bits */ ulong subkey) {
        // 1. expansion
        ulong e = E(r);
        // 2. key mixing
        ulong x = e ^ subkey;
        // 3. substitution
        uint dst = 0;
        for (int i = 0; i < 8; i++) {
            dst >>= 4;
            uint s = S(8 - i, (byte) (x & 0x3F));
            dst |= s << 28;
            x >>= 6;
        }
        // 4. permutation
        return P(dst);
    }


    //generam 16 subeky-uri de 48-biti bazate pe 64 biti key prevazute

    private static ulong[] createSubkeys(/* 64 bits */ ulong key) {
        ulong[] subkeys = new ulong[16];

        key = PC1(key);

        uint c = (uint) (key >> 28);
        uint d = (uint) (key & 0x0FFFFFFF);

        for (int i = 0; i < 16; i++) {

            if (rotationsTable[i] == 1) {

                c = ((c << 1) & 0x0FFFFFFF) | (c >> 27);
                d = ((d << 1) & 0x0FFFFFFF) | (d >> 27);
            } else {

                c = ((c << 2) & 0x0FFFFFFF) | (c >> 26);
                d = ((d << 2) & 0x0FFFFFFF) | (d >> 26);
            }
            ulong cd = (c & 0xFFFFFFFFUL) << 28 | (d & 0xFFFFFFFFUL);

            subkeys[i] = PC2(cd);
        }
        return subkeys;
    }

    //Criptam un block de 64 biti de mesaj intr-un cripto text de 64 biti

    public static ulong encryptBlock(ulong m, /* 64 bits */ ulong key) {
        ulong []subkeys = createSubkeys(key);
        ulong ip = IP(m);
        uint l = (uint) (ip >> 32);
        uint r = (uint) (ip & 0xFFFFFFFFUL);
        for (int i = 0; i < 16; i++) {
            uint previous_l = l;
            l = r;
            r = previous_l ^ feistel(r, subkeys[i]);
        }

        ulong rl = (r & 0xFFFFFFFFUL) << 32 | (l & 0xFFFFFFFFUL);

        ulong fp = FP(rl);

        return fp;
    }
//Byte de arrays dar nu ulongs.

    public static void encryptBlock(
            byte[] message,
            int messageOffset,
            byte[] ciphertext,
            int ciphertextOffset,
            byte[] key
    ) {
        ulong m = getulongFromBytes(message, messageOffset);
        ulong k = getulongFromBytes(key, 0);
        ulong c = encryptBlock(m, k);
        getBytesFromulong(ciphertext, ciphertextOffset, c);
    }

    public static byte[] encrypt(byte[] message, byte[] key) {
        byte[] ciphertext = new byte[message.Length];

        // encrypt each 8-byte (64-bit) block of the message.
        for (int i = 0; i < message.Length; i += 8) {
            encryptBlock(message, i, ciphertext, i, key);
        }

        return ciphertext;
    }

    public static byte[] encrypt(byte[] challenge, String password) {
        return encrypt(challenge, passwordToKey(password));
    }

    private static byte[] passwordToKey(String password) {
        byte[] pwbytes = System.Text.Encoding.Unicode.GetBytes(password);
        byte[] key = new byte[8];
        for (int i = 0; i < 8; i++) {
            if (i < pwbytes.Length) {
                byte b = pwbytes[i];

                byte b2 = 0;
                for (int j = 0; j < 8; j++) {
                    b2 <<= 1;
                    b2 |= (byte)(b & 0x01);
                    b >>= 1;
                }
                key[i] = b2;
            } else {
                key[i] = 0;
            }
        }
        return key;
    }

    private static int charToNibble(char c) {
        if (c >= '0' && c <= '9') {
            return (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            return (10 + c - 'a');
        } else if (c >= 'A' && c <= 'F') {
            return (10 + c - 'A');
        } else {
            return 0;
        }
    }

    private static byte[] parseBytes(String s) {
        return System.Text.Encoding.Unicode.GetBytes(s);
    }

    private static String hex(byte[] bytes) {
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < bytes.Length; i++) {
            sb.Append(String.Format("{0:X2} ", bytes[i]));
        }
        return sb.ToString();
    }

    public static bool test(byte[] message, byte[] expected, String password) {
        return test(message, expected, passwordToKey(password));
    }

    private static int testCount = 0;

    public static bool test(byte[] message, byte[] expected, byte[] key) {
        Console.WriteLine("Test #" + (++testCount) + ":");
        Console.WriteLine("\tmessage:  " + hex(message));
        Console.WriteLine("\tkey:      " + hex(key));
        Console.WriteLine("\texpected: " + hex(expected));
        byte[] received = encrypt(message, key);
        Console.WriteLine("\treceived: " + hex(received));
        bool result = Array.Equals(expected, received);
        Console.WriteLine("\tverdict: " + (result ? "PASS" : "FAIL"));
        return result;
    }
    public static String convertStringToHex(String str){

        var sb = new System.Text.StringBuilder();

        var bytes = System.Text.Encoding.Unicode.GetBytes(str);
        foreach (var t in bytes)
        {
            sb.Append(t.ToString("X2"));
        }

        return sb.ToString(); // returns: "48656C6C6F20776F726C64" for "Hello world"
    }
    public static void Main(String[] args) {
        String oriText = "Some nice plain text";
        String key = "mypass";
        byte[] keys = parseBytes(key);
        byte[] test = parseBytes(oriText);

        Console.WriteLine("Key:  " + hex(keys));

        var encResult = encryptCBC(test, keys);
        Console.WriteLine("Encryption result:  " + hex(encResult));

        Console.WriteLine("ORIGINAL TEXT:  " + hex(test));
        Console.WriteLine("ENCRYPTED TEXT: " + System.Text.Encoding.Unicode.GetString(encResult));

        var decResult = decryptCBC(encResult,keys);
        Console.WriteLine("Decryption result:  " + hex(decResult));
        Console.WriteLine("DECRYPTED TEXT: " + System.Text.Encoding.Unicode.GetString(decResult));
    }

    private static ulong IV;

    public static ulong getIv() {
        return IV;
    }

    public static void setIv(ulong iv) {
        IV = iv;
    }


    public static byte[] encryptCBC(byte[] message, byte[] key) {
        byte[] ciphertext = new byte[message.Length];
        ulong k = getulongFromBytes(key, 0);
        ulong previousCipherBlock = IV;

        for (int i = 0; i < message.Length; i += 8) {

            ulong messageBlock = getulongFromBytes(message, i);

            ulong cipherBlock = encryptBlock(messageBlock ^ previousCipherBlock, k);

            getBytesFromulong(ciphertext, i, cipherBlock);

            previousCipherBlock = cipherBlock;
        }

        return ciphertext;
    }

    public static ulong decryptBlock(ulong c, /* 64 bits */ ulong key) {

        ulong[] subkeys = createSubkeys(key);

        ulong ip = IP(c);

        uint l = (uint) (ip >> 32);
        uint r = (uint) (ip & 0xFFFFFFFFUL);

        for (int i = 15; i > -1; i--) {
            uint previous_l = l;
            l = r;

            r = previous_l ^ feistel(r, subkeys[i]);
        }

        ulong rl = (r & 0xFFFFFFFFUL) << 32 | (l & 0xFFFFFFFFUL);

        ulong fp = FP(rl);

        return fp;
    }

    public static void decryptBlock(
            byte[] ciphertext,
            int ciphertextOffset,
            byte[] message,
            int messageOffset,
            byte[] key
    ) {
        ulong c = getulongFromBytes(ciphertext, ciphertextOffset);
        ulong k = getulongFromBytes(key, 0);
        ulong m = decryptBlock(c, k);
        getBytesFromulong(message, messageOffset, m);
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key) {
        byte[] message = new byte[ciphertext.Length];

        for (int i = 0; i < ciphertext.Length; i += 8) {
            decryptBlock(ciphertext, i, message, i, key);
        }
        return message;
    }

    public static byte[] decryptCBC(byte[] ciphertext, byte[] key) {
        byte[] message = new byte[ciphertext.Length];
        ulong k = getulongFromBytes(key, 0);
        ulong previousCipherBlock = IV;

        for (int i = 0; i < ciphertext.Length; i += 8) {

            ulong cipherBlock = getulongFromBytes(ciphertext, i);

            ulong messageBlock = decryptBlock(cipherBlock, k);
            messageBlock = messageBlock ^ previousCipherBlock;

            getBytesFromulong(message, i, messageBlock);

            previousCipherBlock = cipherBlock;
        }

        return message;
    }
}


}