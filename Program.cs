using System;
using System.Security.Cryptography;
using System.Xml;

namespace Security_Lab_1
{
    class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                SyntaxError();
            }
            //Call the appropriate function based on first argument
            switch (args[0])
            {
                case "initialize":
                    initialize();
                    break;
                case "encrypt":
                    if (args.Length < 2) {SyntaxError();}
                    encrypt(args[1]);
                    break;
                case "decrypt":
                    if (args.Length < 2) {SyntaxError();}
                    decrypt(args[1]);
                    break;
                default:
                    return;
            }
        }
        static void SyntaxError()
        {
            Console.WriteLine("Syntax error! Accepted syntax:");
            Console.WriteLine("initialize");
            Console.WriteLine("encrypt [filepath]");
            Console.WriteLine("decrypt [encrypted file path]");
            Environment.Exit(0);
        }

        //This method creates the public, private and secret keys and saves them to XML files to be used later.
        static void initialize()
        {
            //Generate a public/private key pair.  
            RSACryptoServiceProvider SenderKeys = new RSACryptoServiceProvider();

            //Generate a second public/private key pair.  
            RSACryptoServiceProvider ReceiverKeys = new RSACryptoServiceProvider();

            //Generate a symmetric binary key
            RijndaelManaged SymmetricKey = new RijndaelManaged();

            //Convert the keys into xml strings
            String SenderKeyXML = RSACryptoServiceProviderExtensions.ToXmlString(SenderKeys);
            String ReceiverKeyXML = RSACryptoServiceProviderExtensions.ToXmlString(ReceiverKeys);
            String SymmetricKeyXML = "<root><key value='" + Convert.ToBase64String(SymmetricKey.Key) + "'/></root>";

            //Save the xml strings to respective files
            XmlDocument xmlDoc = new XmlDocument();

            xmlDoc.LoadXml(SenderKeyXML);
            xmlDoc.Save("SenderKeys.xml");

            xmlDoc.LoadXml(ReceiverKeyXML);
            xmlDoc.Save("ReceiverKeys.xml");

            xmlDoc.LoadXml(SymmetricKeyXML);
            xmlDoc.Save("SymmetricKey.xml");
        }

        //This method creates a signed hash of a provided file.
        //TIt encrypts that with a symmetric key, and encrypts the symmetric key with the public key of the receiver.
        static void encrypt(String filepath)
        {
            try
            {
                //Load all the keys             
                XmlDocument xmlDoc = new XmlDocument();

                //Sender keys
                xmlDoc.Load("SenderKeys.xml");
                String SenderKeysXML = xmlDoc.OuterXml;
                RSACryptoServiceProvider SenderKeys = new RSACryptoServiceProvider();
                RSACryptoServiceProviderExtensions.FromXmlString(SenderKeys, SenderKeysXML);

                //Receiver keys
                xmlDoc.Load("ReceiverKeys.xml");
                String ReceiverKeysXML = xmlDoc.OuterXml;
                RSACryptoServiceProvider ReceiverKeys = new RSACryptoServiceProvider();
                RSACryptoServiceProviderExtensions.FromXmlString(ReceiverKeys, ReceiverKeysXML);

                //Symmetric key
                xmlDoc.Load("SymmetricKey.xml");
                RijndaelManaged SymmetricKey = new RijndaelManaged();
                SymmetricKey.Key = Convert.FromBase64String(xmlDoc.GetElementById("key").GetAttribute("value"));

                byte[] HashValue;

                //Create a new instance of the SHA1Managed class to create 
                //the hash value.
                SHA1Managed SHhash = new SHA1Managed();

                //Create the hash value from the array of bytes.
                //HashValue = SHhash.ComputeHash(MyStream);

                //The value to hold the signed value.  
                byte[] SignedHashValue;


                //Create an RSAPKCS1SignatureFormatter object and pass it the   
                //RSACryptoServiceProvider to transfer the private key.  
                RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(ReceiverKeys);

                //Set the hash algorithm to SHA1.  
                RSAFormatter.SetHashAlgorithm("SHA1");

                //Create a signature for HashValue and assign it to   
                //SignedHashValue.  
                //SignedHashValue = RSAFormatter.CreateSignature(HashValue);

                Console.WriteLine("Hello World!");
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: " + e.ToString());
            }
        }
        //This method accepts an encrypted file. It decrypts a symmetric key using the receiver's private key,
        //then uses the decrypted key to decrypt the file into a signed hash. The signed is then verified using the sender's public key.
        static void decrypt(String encryptedFilePath)
        {

        }
    }
}
