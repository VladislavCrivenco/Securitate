using System;
using System.Collections.Generic;

namespace Crypto
{
    public class DES
    {
        private static readonly int BlockSize = 64;
        private static int[] initial_key_permutaion = {
                                57, 49,  41, 33,  25,  17,  9,
                                 1, 58,  50, 42,  34,  26, 18,
                                10,  2,  59, 51,  43,  35, 27,
                                19, 11,   3, 60,  52,  44, 36,
                                63, 55,  47, 39,  31,  23, 15,
                                 7, 62,  54, 46,  38,  30, 22,
                                14,  6,  61, 53,  45,  37, 29,
                                21, 13,   5, 28,  20,  12, 4};

        private static int[] final_key_permutaion = {
                                57, 49,  41, 33,  25,  17,  9,
                                 1, 58,  50, 42,  34,  26, 18,
                                10,  2,  59, 51,  43,  35, 27,
                                19, 11,   3, 60,  52,  44, 36,
                                63, 55,  47, 39,  31,  23, 15,
                                 7, 62,  54, 46,  38,  30, 22,
                                14,  6,  61, 53,  45,  37, 29,
                                21, 13,   5, 28,  20,  12, 4};

        public static bool[] Encrypt(bool[] input, bool[] key)
        {
            input = Permute(input, initial_key_permutaion);

            var keys = GenerateKeys(key);

            var result = Split(input);

            for (int i = 0; i < 15; i++)
            {
                var temp = result.right;

                result.right = Xor(Feistel.Compute(result.right, keys[i]), result.left);
                result.left = temp;
            }

            result.left = Xor(Feistel.Compute(result.right, keys[15]), result.left);
            input = Combine(result.left, result.right);

            input = Permute(input, final_key_permutaion);

            return input;
        }

        private static List<bool[]> GenerateKeys(bool[] key)
        {
            return new List<bool[]>();
        }

        private static bool[] Permute(bool[] input, int[] permuteTable)
        {
            var result = new bool[BlockSize];

            for (int i = 0; i < permuteTable.Length; i++)
            {
                result[i] = input[permuteTable[i]];
            }

            return result;
        }

        private static bool[] Xor(bool[] first, bool[] second)
        {
            var result = new bool[BlockSize / 2];

            for (int i = 0; i < result.Length; i++)
            {
                result[i] = (bool)(first[i] ^ second[i]);
            }

            return result;
        }
        private static (bool[] left, bool[] right) Split(bool[] input)
        {
            bool[] left = new bool[BlockSize / 2];
            bool[] right = new bool[BlockSize / 2];

            for (int i = 0; i < BlockSize / 2; i++)
            {
                left[i] = input[i];
            }

            for (int i = BlockSize / 2; i < BlockSize; i++)
            {
                right[i] = input[i];
            }

            return (left, right);
        }

        private static bool[] Combine(bool[] left, bool[] right)
        {
            var result = new bool[BlockSize];

            for (int i = 0; i < left.Length; i++)
            {
                result[i] = left[i];
            }

            for (int i = 0; i < right.Length; i++)
            {
                result[i] = right[i + 15];
            }

            return result;
        }
    }
}