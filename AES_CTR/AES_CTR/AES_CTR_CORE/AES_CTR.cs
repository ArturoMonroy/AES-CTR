using System;
using System.Security.Cryptography;
using System.Text;

namespace AES_CTR_CORE
{
    public class AES_CTR
    {

        private string _VERSION_ = "1.0.0.1";
        
        public string Version() { return this._VERSION_; }

        public string ID { get; set; }

        public void SetID(string v) { ID = v; }

        public string GetID() { return ID; }

        /// <summary>
        ///     Encripta un valor en AES_CTR
        /// </summary>
        /// <param name="base64Data">Cadena de texto en Base64 a encriptar</param>
        /// <param name="llave">Llave en claro</param>
        /// <param name="resultado">Cadena de texto en Base64 obtenida del arreglo de bytes</param>
        /// <returns> Cantidad de Bytes obtenido al encriptar</returns>       
        public int Encripta(string base64Data, string llave, out string base64Resultado)
        {

            int result = -1;
            base64Resultado = "";
            byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] outData = null;
            byte[] llaveB = null;
            byte[] data = null;
            try
            {
                #region Validaciones
                try
                {
                    Encoding.UTF8.GetString(Convert.FromBase64String(base64Data));
                }
                catch (Exception)
                {
                    throw new Exception(string.Format("La data a encriptar NO es un Base64 Valido [{0}]", base64Data));
                }

                try
                {
                    Encoding.UTF8.GetString(Convert.FromBase64String(llave));
                }
                catch (Exception)
                {
                    throw new Exception(string.Format("La llave NO es un Base64 Valido [{0}]", llave));
                }
                #endregion

                data = Encoding.UTF8.GetBytes(base64Data);
                outData = new byte[base64Data.Length];
                llaveB = Encoding.UTF8.GetBytes(llave);// Convert.FromBase64String(base64Llave);

                Aes128CounterMode am = new Aes128CounterMode(iv);
                ICryptoTransform ict = am.CreateEncryptor(llaveB, null);
                ict.TransformBlock(data, 0, outData.Length, outData, 0);

                base64Resultado = Convert.ToBase64String(outData);

                result = outData.Length;

            }
            catch (Exception e)
            {
                base64Resultado = e.Message;
            }


            return result;
        }       /// <summary>

        /// <summary>
        ///     Encripta un valor en AES_CTR
        /// </summary>
        /// <param name="data">Cadena de texto en Base64 a encriptar</param>
        /// <param name="llave">Llave en claro</param>
        /// <param name="resultado">Cadena de texto en Base64 obtenida del arreglo de bytes</param>
        /// <returns> Cantidad de Bytes obtenido al encriptar</returns>       
        public int Encripta(byte[] data, byte[] llave, out byte[] resultado)
        {

            int result = -1;
            byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            resultado = null;
            try
            {
                resultado = new byte[data.Length];

                Aes128CounterMode am = new Aes128CounterMode(iv);
                ICryptoTransform ict = am.CreateEncryptor(llave, null);
                ict.TransformBlock(data, 0, resultado.Length, resultado, 0);

                result = resultado.Length;

            }
            catch (Exception e)
            {
                resultado = Encoding.UTF8.GetBytes(e.Message);
            }


            return result;
        }

        /// <summary>
        ///     Desencripta un valor en AES_CTR
        /// </summary>
        /// <param name="base64Data">Data Encriptada</param>
        /// <param name="llave">Llave en claro</param>
        /// <param name="resultado">Cadena de texto obtenida del arreglo de bytes</param>
        /// <returns> Cantidad de Bytes obtenido al desencriptar </returns>
        public int Desencripta(string base64Data, string llave, out string resultado)
        {

            int result = -1;
            resultado = "";
            byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] outData = null;
            byte[] llaveB = null;
            byte[] data = null;

            try
            {

                #region Validaciones
                try
                {
                    Encoding.UTF8.GetString(Convert.FromBase64String(base64Data));
                }
                catch (Exception)
                {
                    throw new Exception(string.Format("La data a desencriptar NO es un Base64 Valido [{0}]", base64Data));
                }

                try
                {
                    Encoding.UTF8.GetString(Convert.FromBase64String(llave));
                }
                catch (Exception)
                {
                    throw new Exception(string.Format("La llave NO es un Base64 Valido [{0}]", llave));
                }
                #endregion

                data = Convert.FromBase64String(base64Data);
                outData = new byte[data.Length];
                llaveB = Encoding.UTF8.GetBytes(llave);// Convert.FromBase64String(base64Llave);

                Aes128CounterMode am = new Aes128CounterMode(iv);
                ICryptoTransform ict = am.CreateDecryptor(llaveB, null);
                ict.TransformBlock(data, 0, data.Length, outData, 0);

                resultado = Encoding.UTF8.GetString(outData);

                result = outData.Length;

            }
            catch (Exception e)
            {
                resultado = e.Message;
            }

            return result;
        }/// <summary>
         ///     Desencripta un valor en AES_CTR
         /// </summary>
         /// <param name="dataIn">Data Encriptada</param>
         /// <param name="llave">Arreglo de bytes (32 bytes)</param>
         /// <param name="resultado">Cadena de texto obtenida del arreglo de bytes</param>
         /// <returns> Cantidad de Bytes obtenido al desencriptar </returns>
        public int Desencripta(byte[] data, byte[] llave, out byte[] resultado)
        {

            int result = -1;
            byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            resultado = null;

            try
            {
                resultado = new byte[data.Length];

                Aes128CounterMode am = new Aes128CounterMode(iv);
                ICryptoTransform ict = am.CreateDecryptor(llave, null);
                ict.TransformBlock(data, 0, data.Length, resultado, 0);


                result = resultado.Length;

            }
            catch (Exception e)
            {
                resultado = Encoding.UTF8.GetBytes(e.Message);
            }

            return result;
        }
    }
}
