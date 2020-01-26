using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace NS.Cryptography
{
    public class CryptographyRepository
    {

        public static string Encrypt(string password, string salt, string messageToEncrypt)
        {
            DeriveBytes rgb = new Rfc2898DeriveBytes(password, Encoding.Unicode.GetBytes(salt));

            SymmetricAlgorithm alg = new AesManaged();
            alg.Padding = PaddingMode.PKCS7;
            byte[] rgbKey = rgb.GetBytes(alg.KeySize >> 3);
            byte[] rgbIV = rgb.GetBytes(alg.BlockSize >> 3);

            ICryptoTransform transform = alg.CreateEncryptor(rgbKey, rgbIV);

            using (MemoryStream buffer = new MemoryStream())
            {
                using (CryptoStream stream = new CryptoStream(buffer, transform, CryptoStreamMode.Write))
                {
                    using (StreamWriter writer = new StreamWriter(stream, Encoding.Unicode))
                    {
                        writer.Write(messageToEncrypt);
                    }
                }
                return Convert.ToBase64String(buffer.ToArray());
            }
        }

        public static string Decrypt(string password, string salt, string messageToDecrypt)
        {
            DeriveBytes rgb = new Rfc2898DeriveBytes(password, Encoding.Unicode.GetBytes(salt));

            SymmetricAlgorithm alg = new AesManaged();

            byte[] rgbKey = rgb.GetBytes(alg.KeySize >> 3);
            byte[] rgbIV = rgb.GetBytes(alg.BlockSize >> 3);
            string decryptedMessage = string.Empty;
            ICryptoTransform transform = alg.CreateDecryptor(rgbKey, rgbIV);
            alg.Padding = PaddingMode.PKCS7;
            using (MemoryStream buffer = new MemoryStream(Convert.FromBase64String(messageToDecrypt)))
            {
                using (CryptoStream stream = new CryptoStream(buffer, transform, CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(stream, Encoding.Unicode))
                    {
                        decryptedMessage= reader.ReadToEnd();
                    }
                }
            }
            return decryptedMessage;
           

        }

    }
}