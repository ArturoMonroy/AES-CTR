using RGiesecke.DllExport;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AES_CBC_PKC7
{
    [ComVisible(true)]
    [Guid("9971C5E0-B296-4AB8-AEE7-F2553BACB730"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IAES_CBC_PKC7
    {
        [return: MarshalAs(UnmanagedType.I4)]
        int Encripta(string base64Data, string base64Llave, [MarshalAs(UnmanagedType.BStr)] out string base64Resultado);

        [return: MarshalAs(UnmanagedType.I4)]
        int Desencripta(string base64Data, string base64Llave, [MarshalAs(UnmanagedType.BStr)] out string base64Resultado);

        [return: MarshalAs(UnmanagedType.BStr)]
        string GetID();

        void SetID(string v);

        [return: MarshalAs(UnmanagedType.BStr)]
        string Version();
    }

    /// <summary>
    /// Clase compatible con cifrado en JAVA con el siguiente estilo
    /// 
    /// byte[] key =DatatypeConverter.parseBase64Binary(AES_LLAVE);
    /// SecretKeySpec clientKey = new SecretKeySpec(key, 0, key.length, "AES");
    /// Cipher pwdcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    /// pwdcipher.init(Cipher.ENCRYPT_MODE, clientKey);
    /// byte[] ivBytes= pwdcipher.getIV();                      
    /// byte[] dataBytes = pwdcipher.doFinal(VALOR_A_ENCRIPTAR.getBytes("UTF-8"));
    /// byte[] concat = new byte[ivBytes.length + dataBytes.length];
    /// System.arraycopy(ivBytes, 0, concat, 0, ivBytes.length);
    /// System.arraycopy(dataBytes, 0, concat, ivBytes.length,  dataBytes.length);
    /// VALOR_ENC =DatatypeConverter.printBase64Binary(concat);//Esta es la cadena cifrada
    /// </summary>
    /// <remarks>
    /// NOTA 1: El vector de inicializacion (IV) es concatenado al resultado (IV) + (ENC)
    /// NOTA 2: Lo anterior genera un resultado distinto cada ocasion
    /// NOTA 3: PKCS5 y PKCS7 son compatibles
    /// </remarks>
    public class AES_CBC_PKC7 : IAES_CBC_PKC7
    {
        #region private
        private byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");
            byte[] encrypted;
            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption. 
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream. 
            return encrypted;

        }

        private string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }
        private RijndaelManaged _myRijndael;

        #endregion

        private string _VERSION_ = "1.0.0.0";
        static private string _S_VERSION_ = "1.0.0.0";

        public string Version() { return this._VERSION_; }

        public string ID { get; set; }

        public void SetID(string v) { ID = v; }

        public string GetID() { return ID; }

        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static void CreaObjeto([MarshalAs(UnmanagedType.Interface)] out IAES_CBC_PKC7 miAES)
        {
            miAES = new AES_CBC_PKC7();
            miAES.SetID("_UNDEF_");
        }
        public int Desencripta(string base64Data, string base64Llave, out string base64Resultado)
        {
            int result = -1;
            base64Resultado = "";
            try
            {
                using (_myRijndael = new RijndaelManaged())
                {
                    byte[] losBytes = Convert.FromBase64String(base64Data);
                    byte[] elIV = new byte[16];
                    byte[] elENC = new byte[losBytes.Length - 16];

                    Array.Copy(losBytes, 0, elIV, 0, 16);
                    Array.Copy(losBytes, 16, elENC, 0, losBytes.Length - 16);

                    _myRijndael.Key = Convert.FromBase64String(base64Llave);
                    _myRijndael.IV = elIV;
                    _myRijndael.Mode = CipherMode.CBC;
                    _myRijndael.Padding = PaddingMode.PKCS7;

                    Byte[] ourEnc = elENC;

                    base64Resultado = DecryptStringFromBytes(ourEnc, _myRijndael.Key, _myRijndael.IV);
                    
                    //Esta de mas el Base64, pero lo hago para dejar un estandar con AES_CTR
                    base64Resultado = Convert.ToBase64String( Encoding.UTF8.GetBytes(base64Resultado) );
                    
                    result = base64Resultado.Length;
                }
            }
            catch (Exception e)
            {
                base64Resultado = e.Message;
            }

            return result;
        }

        public int Encripta(string base64Data, string base64Llave, out string base64Resultado)
        {
            int result = -1;
            base64Resultado = "";
            try
            {
                string data = Encoding.UTF8.GetString(Convert.FromBase64String(base64Data));

                using (_myRijndael = new RijndaelManaged())
                {

                    _myRijndael.Key = Convert.FromBase64String(base64Llave);
                    _myRijndael.GenerateIV();
                    _myRijndael.Mode = CipherMode.CBC;
                    _myRijndael.Padding = PaddingMode.PKCS7;

                    byte[] encrypted = EncryptStringToBytes(data, _myRijndael.Key, _myRijndael.IV);
                    string encString = Convert.ToBase64String(encrypted);

                    byte[] ENC_IV = new byte[_myRijndael.IV.Length + encrypted.Length];

                    Array.Copy(_myRijndael.IV, 0, ENC_IV, 0, 16);
                    Array.Copy(encrypted, 0, ENC_IV, 16, ENC_IV.Length - 16);

                    base64Resultado = Convert.ToBase64String(ENC_IV);
                }
                result = base64Resultado.Length;
            }
            catch (Exception e)
            {

                base64Resultado = e.Message;
            }

            return result;

        }

        [DllExport("VersionNTS", CallingConvention = CallingConvention.Cdecl)]
        public static void VersionNTS([MarshalAs(UnmanagedType.BStr)] out string version)
        {
            version = _S_VERSION_;
        }

        [DllExport("DesencriptaNTS", CallingConvention = CallingConvention.Cdecl)]
        public static int DesencriptaNTS(string base64Data, string base64Llave, out string base64Resultado) {
            var AES = new AES_CBC_PKC7();

            return AES.Desencripta(base64Data, base64Llave, out base64Resultado);
        }
        
        [DllExport("EncriptaNTS", CallingConvention = CallingConvention.Cdecl)]
        public static int EncriptaNTS(string base64Data, string base64Llave, out string base64Resultado) {
            var AES = new AES_CBC_PKC7();

            return AES.Encripta(base64Data, base64Llave, out base64Resultado);
        }

    }
}
