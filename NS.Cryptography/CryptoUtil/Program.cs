using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NS.Cryptography;

namespace CryptoUtil
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string password = "abcd1234";
                string salt = "sample1234!@#*";

                var encryptedText = CryptographyRepository.Encrypt(password, salt, "sample0");
                Console.WriteLine("Encrypted text : " + encryptedText);
                var decryptedText = CryptographyRepository.Decrypt(password, salt, encryptedText);
                Console.WriteLine(decryptedText);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
