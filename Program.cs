using System;
using System.Security.Cryptography;

namespace Security_Lab_1
{
    class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length > 2 || )
            {
                Console.WriteLine("Wrong number of aruments, please try again.");
                return;
            }


        }
        //This method hashes a provided file and signs it with the private key of the sender.
        //Then the method encrypts the signed hash with a symmetric key, and encrypts the symmetric key with the public key of the receiver.
        static void encrypt(String filepath)
        {

            System.IO.FileStream MyStream = System.IO.File.Open(filepath, FileMode.default);
            RijndaelManaged RMCrypto = new RijndaelManaged();
            CryptoStream CryptStream = new CryptoStream(MyStream, RMCrypto.CreateEncryptor(), CryptoStreamMode.Write);

            //Generate a public/private key pair.  
            RSACryptoServiceProvider SenderKeys = new RSACryptoServiceProvider();

            //Generate a second public/private key pair.  
            RSACryptoServiceProvider ReceiverKeys = new RSACryptoServiceProvider();

            //Save the public key information to an RSAParameters structure.  
            RSAParameters SenderKeyInfo = SenderKeys.ExportParameters(true);


            byte[] HashValue;

            //Create a new instance of the SHA1Managed class to create 
            //the hash value.
            SHA1Managed SHhash = new SHA1Managed();

            //Create the hash value from the array of bytes.
            HashValue = SHhash.ComputeHash(MyStream);

            //The value to hold the signed value.  
            byte[] SignedHashValue;


            //Create an RSAPKCS1SignatureFormatter object and pass it the   
            //RSACryptoServiceProvider to transfer the private key.  
            RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(ReceiverKeys);

            //Set the hash algorithm to SHA1.  
            RSAFormatter.SetHashAlgorithm("SHA1");
            
            //Create a signature for HashValue and assign it to   
            //SignedHashValue.  
            SignedHashValue = RSAFormatter.CreateSignature(HashValue);          

            Console.WriteLine("Hello World!");

        }
        //This method accepts an encrypted file. It decrypts a symmetric key using the receiver's private key,
        //then uses the decrypted key to decrypt the file into a signed hash. The signed is then verified using the sender's public key.
        static void decrypt(String filepath)
        {

        }
    }
}
