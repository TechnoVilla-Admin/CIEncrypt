using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Utils
{
    public class CIEncrypt
    {
        string key;
        public CIEncrypt(string key)
        {
            this.key = key;
        }

        public static string Encode(string data, string key)
        {
            string result = null;
            var rijndaelManaged = new RijndaelManaged
            {
                Mode = CipherMode.CBC,
                KeySize = 256,
                BlockSize = 256,
                Key = MD5Hash(Encoding.UTF8.GetBytes(key)),
                Padding = PaddingMode.Zeros
            };

            rijndaelManaged.GenerateIV();

            try
            {
                var ms = new MemoryStream();                

                using (var cs = new CryptoStream(ms, rijndaelManaged.CreateEncryptor(rijndaelManaged.Key, rijndaelManaged.IV), CryptoStreamMode.Write))
                {
                    using(var writer = new StreamWriter(cs))
                        writer.Write(data);
                }

                var encryptedData = AddCipherNoise(rijndaelManaged.IV.Concat(ms.ToArray()).ToArray(), rijndaelManaged.Key);
                result = Convert.ToBase64String(encryptedData);
                ms.Dispose();

            }
            catch (Exception ex)
            {
                throw new InvalidDataException("Unable to encrypt the data, see inner exception for more details.", ex);
            }
            finally
            {
                rijndaelManaged.Clear();
            }

            return result;
        }

        public static string Decode(string data, string key)
        {
            string result = null;
            var rijndaelManaged = new RijndaelManaged
            {
                Mode = CipherMode.CBC,
                KeySize = 256,
                BlockSize = 256,
                Key = MD5Hash(Encoding.UTF8.GetBytes(key)),
                Padding = PaddingMode.Zeros
            };

            if (rijndaelManaged.IV.Length > data.Length)
                throw new InvalidDataException("Invalid data.");

            var dataBytes = RemoveCipherNoise(Convert.FromBase64String(data), rijndaelManaged.Key);

            rijndaelManaged.IV = dataBytes.Take(rijndaelManaged.IV.Length).ToArray();
            dataBytes = dataBytes.Skip(rijndaelManaged.IV.Length).ToArray();

            try
            {
                var ms = new MemoryStream(dataBytes);

                using (var cs = new CryptoStream(ms, rijndaelManaged.CreateDecryptor(rijndaelManaged.Key, rijndaelManaged.IV), CryptoStreamMode.Read))
                {
                    using (var sr = new StreamReader(cs))
                    {
                        result = sr.ReadLine();
                    }
                }

                result = result.TrimEnd('\0');
                ms.Dispose();
            }
            catch(Exception ex)
            {
                throw new InvalidDataException("Unable to decrypt the data, see inner exception for more details.", ex);
            }
            finally
            {
                rijndaelManaged.Clear();
            }

            return result;
        }

        public string Encode(string data)
        {
            return Encode(data, key);
        }

        public string Decode(string data)
        {
            return Decode(data, key);
        }

        private static byte[] SHA1Hash(byte[] data)
        {
            using (SHA1 hash = SHA1.Create())
            {
                // Convert the input string to a byte array and compute the hash.
                return hash.ComputeHash(data)
                    .SelectMany(b => Encoding.UTF8.GetBytes(b.ToString("x2")))
                    .ToArray();
            }
        }

        private static byte[] MD5Hash(byte[] data)
        {
            using (MD5 hash = MD5.Create())
            {
                // Convert the input string to a byte array and compute the hash.
                return hash.ComputeHash(data)
                    .SelectMany(b => Encoding.UTF8.GetBytes(b.ToString("x2")))
                    .ToArray();
            }
        }

        private static byte[] RemoveCipherNoise(byte[] data, byte[] key)
        {
            var keyhash = SHA1Hash(key);
            var keylen = keyhash.Length;

            MemoryStream ms = new MemoryStream();

            for (int i = 0, j = 0, len = data.Length; i < len; ++i, ++j)
            {
                if (j >= keylen)
                {
                    j = 0;
                }

                var temp = data[i] - keyhash[j];

                if (temp < 0)
                {
                    temp = temp + 256;
                }

                ms.WriteByte((byte)temp);
            }

            return ms.ToArray();
        }

        private static byte[] AddCipherNoise(byte[] data, byte[] key)
        {
            var keyhash = SHA1Hash(key);
            var keylen = keyhash.Length;
            MemoryStream ms = new MemoryStream();

            for (int i = 0, j = 0, len = data.Length; i < len; ++i, ++j)
            {
                if (j >= keylen)
                {
                    j = 0;
                }

                ms.WriteByte((byte)((data[i] + keyhash[j]) % 256));
            }

            return ms.ToArray();
        }
    }
}
