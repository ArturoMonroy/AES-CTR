using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace AES_EXE
{
    class AES_EXE
    {

        static void Main(string[] args)
        {


            /*
             Ejemplo tomado de un script Python 
             */

            string operacion = "";
            string textoAEncriptar = "" ;            
            string llave = "" ;
            string resultadoBase64 = "";

            //Si no hay suficientes argumentos crea los de prueba
            if (args.Length < 3 ){

                //Por algun motivo en Python al ejecutar "base64.encodestring", agrega un salto de linea
                //QXJ0dXJv
                textoAEncriptar = Convert.ToBase64String( Encoding.UTF8.GetBytes("Arturo") ); 
                //MTJFOUYwOEI2QjBDQ0MzNkRGNjg4QkYxNjdGQUY3QkY=
                llave           = "12E9F08B6B0CCC36DF688BF167FAF7BF"; 

                //El resultado deberia ser "/kBla0qifPZV"
            }else{
                operacion = args[0];
                textoAEncriptar = args[1];
                llave = args[2];
            }
            
            if ( AES_CTR_NET.AES_CTR.EncriptaNTS( textoAEncriptar, llave, out resultadoBase64  ) > 0 )
                Console.WriteLine(resultadoBase64);
            else 
                Console.WriteLine( string.Format("Error NO esperado {0} ", resultadoBase64) );            
            
            if (AES_CTR_NET.AES_CTR.DesencriptaNTS(resultadoBase64, llave, out resultadoBase64) > 0 )
                Console.WriteLine( resultadoBase64 + " ==> " + Encoding.UTF8.GetString( Convert.FromBase64String(resultadoBase64) ) );
            else
                Console.WriteLine( string.Format("Error NO esperado el desencriptar {0}", resultadoBase64));

            
             Console.ReadKey();

        }
    }
}
