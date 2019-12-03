using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
namespace Test3rdPartyEncryptionKey
{
    static class Program
    {
        static void Main(string[] args)
        {
            //Generate an api key with the following pattern - SubscriptionID + ':' + cosmosdb guid id + ':' + randomizer (Use randomizer so that we cant reverse engineer)
            //Store the hash of the api key generated in cosmosdb

            var keySize = 256;
            //var privateKey = GenerateKey(keySize);
            //Console.WriteLine($"private key = {privateKey}");
            var privateKey = "MC9ES3pTQU4xNU55WUowdlBncitpZz09LEhDcDlYWXphN0FVOUQ2UVJPMDlCNGRiZ290NVFFMGxCZC9abXJFMUV0eDA9";

            //Encryption
            var stopwatch1 = Stopwatch.StartNew();
            var str = "316afb2a-c00c-4c3d-861a-2b70b54fd2b5:e9ab1758-37be-48f4-93d3-2561d8d3f3b6:" + GenerateString(5);
            var encryptedString = Encrypt(str, privateKey, keySize);
            stopwatch1.Stop(); //Measure code execution time for encryption
            Console.WriteLine($"encrypted string = {encryptedString}");
            Console.WriteLine($"encryption execution time = {stopwatch1.ElapsedMilliseconds}");

            //Decryption
            var stopwatch2 = Stopwatch.StartNew();
            var decryptedString = Decrypt(encryptedString, privateKey, keySize);
            stopwatch2.Stop();
            Console.WriteLine($"decrypted string = {decryptedString}");
            Console.WriteLine($"decryption execution time = {stopwatch2.ElapsedMilliseconds}");

            //Create a new SHA 256 hash of the key for storage in cosmosdb
            var stopwatch3 = Stopwatch.StartNew();
            var hashString = ComputeHash("test", encryptedString);
            stopwatch3.Stop();
            Console.WriteLine($"hash string1 = {hashString}");
            Console.WriteLine($"hashing execution time = {stopwatch3.ElapsedMilliseconds}");
        }

        private static string GenerateKey(int iKeySize)
        {
            RijndaelManaged aesEncryption = new RijndaelManaged();
            aesEncryption.KeySize = iKeySize;
            aesEncryption.BlockSize = 128;
            aesEncryption.Mode = CipherMode.CBC;
            aesEncryption.Padding = PaddingMode.PKCS7;
            aesEncryption.GenerateIV();
            string ivStr = Convert.ToBase64String(aesEncryption.IV);
            aesEncryption.GenerateKey();
            string keyStr = Convert.ToBase64String(aesEncryption.Key);
            string completeKey = ivStr + "," + keyStr;

            return Convert.ToBase64String(ASCIIEncoding.UTF8.GetBytes(completeKey));
        }

        private static string Encrypt(string iPlainStr, string iCompleteEncodedKey, int iKeySize)
        {
            RijndaelManaged aesEncryption = new RijndaelManaged();
            aesEncryption.KeySize = iKeySize;
            aesEncryption.BlockSize = 128;
            aesEncryption.Mode = CipherMode.CBC;
            aesEncryption.Padding = PaddingMode.PKCS7;
            aesEncryption.IV = Convert.FromBase64String(ASCIIEncoding.UTF8.GetString(Convert.FromBase64String(iCompleteEncodedKey)).Split(',')[0]);
            aesEncryption.Key = Convert.FromBase64String(ASCIIEncoding.UTF8.GetString(Convert.FromBase64String(iCompleteEncodedKey)).Split(',')[1]);
            byte[] plainText = ASCIIEncoding.UTF8.GetBytes(iPlainStr);
            ICryptoTransform crypto = aesEncryption.CreateEncryptor();
            byte[] cipherText = crypto.TransformFinalBlock(plainText, 0, plainText.Length);
            return Convert.ToBase64String(cipherText);
        }

        private static string Decrypt(string iEncryptedText, string iCompleteEncodedKey, int iKeySize)
        {
            RijndaelManaged aesEncryption = new RijndaelManaged();
            aesEncryption.KeySize = iKeySize;
            aesEncryption.BlockSize = 128;
            aesEncryption.Mode = CipherMode.CBC;
            aesEncryption.Padding = PaddingMode.PKCS7;
            aesEncryption.IV = Convert.FromBase64String(ASCIIEncoding.UTF8.GetString(Convert.FromBase64String(iCompleteEncodedKey)).Split(',')[0]);
            aesEncryption.Key = Convert.FromBase64String(ASCIIEncoding.UTF8.GetString(Convert.FromBase64String(iCompleteEncodedKey)).Split(',')[1]);
            ICryptoTransform decrypto = aesEncryption.CreateDecryptor();
            byte[] encryptedBytes = Convert.FromBase64CharArray(iEncryptedText.ToCharArray(), 0, iEncryptedText.Length);
            return ASCIIEncoding.UTF8.GetString(decrypto.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length));
        }

        private static string ComputeHash(string hashedPassword, string message)
        {
            var key = Encoding.UTF8.GetBytes(hashedPassword.ToUpper());
            string hashString;

            using (var hmac = new HMACSHA256(key))
            {
                var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
                hashString = Convert.ToBase64String(hash);
            }

            return hashString;
        }

        private static string GenerateString(int size)
        {
            var rand = new Random();
            const string Alphabet = "abcdefghijklmnopqrstuvwyxzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            char[] chars = new char[size];
            for (int i = 0; i < size; i++)
            {
                chars[i] = Alphabet[rand.Next(Alphabet.Length)];
            }
            return new string(chars);
        }
    }
}
