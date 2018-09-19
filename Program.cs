using System;
using System.IO;
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
                    if (args.Length < 2) { SyntaxError(); }
                    encrypt(args[1]);
                    break;
                case "decrypt":
                    if (args.Length < 2) { SyntaxError(); }
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

        //This method creates the public, private and secret (symmetric) keys and saves them to XML files to be used later.
        static void initialize()
        {
            //Generate a public/private key pair.  
            RSACryptoServiceProvider SenderKeys = new RSACryptoServiceProvider();

            //Generate a second public/private key pair.  
            RSACryptoServiceProvider ReceiverKeys = new RSACryptoServiceProvider();

            //Generate a symmetric binary key
            RijndaelManaged SymmetricKey = new RijndaelManaged();
            SymmetricKey.KeySize = 128;
            SymmetricKey.BlockSize = 128;
            SymmetricKey.Mode = CipherMode.CBC;

            //Convert the keys into xml strings
            String SenderKeyXML = RSACryptoServiceProviderExtensions.ToXmlString(SenderKeys);
            String ReceiverKeyXML = RSACryptoServiceProviderExtensions.ToXmlString(ReceiverKeys);
            String SymmetricKeyXML = "<root><mykey>'" + Convert.ToBase64String(SymmetricKey.Key) + "'</mykey><IV>'" +
            Convert.ToBase64String(SymmetricKey.IV) + "'</IV></root>";

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
        //It encrypts that with a symmetric key, and encrypts the symmetric key with the public key of the receiver.
        static void encrypt(String filepath)
        {
            try
            {
                //Load all the keys
                RSACryptoServiceProvider SenderKeys = new RSACryptoServiceProvider();
                RSACryptoServiceProvider ReceiverKeys = new RSACryptoServiceProvider();
                RijndaelManaged SymmetricKey = new RijndaelManaged();
                loadKeys(SenderKeys, ReceiverKeys, SymmetricKey);

                //Load the provided file and generate a signed hash from it using the sender's private key
                byte[] fileBytes = File.ReadAllBytes(filepath);
                byte[] SignedHashValue = SenderKeys.SignData(fileBytes, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

                //Export the signed hash value
                File.WriteAllBytes("SignedHash", SignedHashValue);

                ICryptoTransform transform = SymmetricKey.CreateEncryptor();

                // Use the receiver's public key to encrypt the symmetric key
                byte[] keyEncrypted = ReceiverKeys.Encrypt(SymmetricKey.Key, false);

                // Create byte arrays to contain the symmetric key and IV
                byte[] LenK = new byte[4];
                byte[] LenIV = new byte[4];

                int lKey = keyEncrypted.Length;
                LenK = BitConverter.GetBytes(lKey);
                int lIV = SymmetricKey.IV.Length;
                LenIV = BitConverter.GetBytes(lIV);

                // Write the following to the ouput
                // - length of the key
                // - length of the IV
                // - encrypted key
                // - the IV
                // - the encrypted cipher content
                using (FileStream outFs = new FileStream("encrypted_" + filepath, FileMode.Create))
                {
                    outFs.Write(LenK, 0, 4);
                    outFs.Write(LenIV, 0, 4);
                    outFs.Write(keyEncrypted, 0, lKey);
                    outFs.Write(SymmetricKey.IV, 0, lIV);

                    // Now write the cipher text using
                    // a CryptoStream for encrypting.
                    using (CryptoStream outStreamEncrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                    {
                        // By encrypting one block at a time, we save memory and accomodate large files.
                        int count = 0;
                        int offset = 0;

                        // Set the block size - arbitrary value
                        int blockSizeBytes = SymmetricKey.BlockSize / 8;
                        byte[] data = new byte[blockSizeBytes];
                        int bytesRead = 0;

                        //Block by block, read bytes from the file and write them to the output via the symmetric cryptostream.
                        using (FileStream inFs = new FileStream(filepath, FileMode.Open))
                        {
                            do
                            {
                                count = inFs.Read(data, 0, blockSizeBytes);
                                offset += count;
                                outStreamEncrypted.Write(data, 0, count);
                                bytesRead += blockSizeBytes;
                            }
                            while (count > 0);
                            inFs.Close();
                        }
                        outStreamEncrypted.FlushFinalBlock();
                        outStreamEncrypted.Close();
                    }
                    outFs.Close();
                }

                Console.WriteLine("Your file was encrypted.");
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
            try
            {
                RSACryptoServiceProvider SenderKeys = new RSACryptoServiceProvider();
                RSACryptoServiceProvider ReceiverKeys = new RSACryptoServiceProvider();
                RijndaelManaged SymmetricKey = new RijndaelManaged();
                loadKeys(SenderKeys, ReceiverKeys, SymmetricKey);

                // Construct the file name for the decrypted file.
                string outFile = "decrypted_" + encryptedFilePath;

                // Use FileStream objects to read the encrypted file (inFs) and save the decrypted file (outFs)
                using (FileStream inFs = new FileStream(encryptedFilePath, FileMode.Open))
                {
                    // Create byte arrays to contain the length values of the key and IV.
                    byte[] LenK = new byte[4];
                    byte[] LenIV = new byte[4];

                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Read(LenK, 0, 3);
                    inFs.Seek(4, SeekOrigin.Begin);
                    inFs.Read(LenIV, 0, 3);

                    // Convert the lengths to integer values.
                    int lenK = BitConverter.ToInt32(LenK, 0);
                    int lenIV = BitConverter.ToInt32(LenIV, 0);

                    // Determine the start postition of the cipher text (startC) and its length(lenC).                    
                    int startC = lenK + lenIV + 8;
                    int lenC = (int)inFs.Length - startC;

                    // Create the byte arrays for the encrypted symmetric key and IV, and the ciphertext.
                    byte[] KeyEncrypted = new byte[lenK];
                    byte[] IV = new byte[lenIV];

                    // Extract the key and IV starting from index 8 after the length values.
                    inFs.Seek(8, SeekOrigin.Begin);
                    inFs.Read(KeyEncrypted, 0, lenK);
                    inFs.Seek(8 + lenK, SeekOrigin.Begin);
                    inFs.Read(IV, 0, lenIV);

                    // Use the receiver's private key to decrypt the symmetric key
                    byte[] KeyDecrypted = ReceiverKeys.Decrypt(KeyEncrypted, false);
                    ICryptoTransform transform = SymmetricKey.CreateDecryptor(KeyDecrypted, IV);

                    // Decrypt the ciphertext from the encrypted file using an output cryptostream
                    using (FileStream outFs = new FileStream(outFile, FileMode.Create))
                    {
                        int count = 0;
                        int offset = 0;

                        // Arbitrary block size
                        int blockSizeBytes = SymmetricKey.BlockSize / 8;
                        byte[] data = new byte[blockSizeBytes];

                        // Start at the beginning of the ciphertext and decrypt it block by block.
                        inFs.Seek(startC, SeekOrigin.Begin);
                        using (CryptoStream outStreamDecrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                        {
                            do
                            {
                                count = inFs.Read(data, 0, blockSizeBytes);
                                offset += count;
                                outStreamDecrypted.Write(data, 0, count);
                            }
                            while (count > 0);

                            outStreamDecrypted.FlushFinalBlock();
                            outStreamDecrypted.Close();
                        }
                        outFs.Close();

                        //Grab the signature from the file and verify it using the receiver's public key.
                        byte[] signedHashValue = File.ReadAllBytes("SignedHash");
                        byte[] decryptedData = File.ReadAllBytes(outFile);

                        bool verify = SenderKeys.VerifyData(decryptedData, signedHashValue, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

                        if (verify)
                        {
                            Console.WriteLine("Your file was verified.");
                        }
                        else
                        {
                            Console.WriteLine("Your file FAILED to be verified.");
                        }

                    }
                    inFs.Close();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: " + e.ToString());
            }
        }
        //This method loads the stored keys from the xml where they are saved
        static void loadKeys(RSACryptoServiceProvider SenderKeys, RSACryptoServiceProvider ReceiverKeys, RijndaelManaged SymmetricKey)
        {
            //Load all the keys
            XmlDocument xmlDoc = new XmlDocument();

            //Sender keys
            xmlDoc.Load("SenderKeys.xml");
            String SenderKeysXML = xmlDoc.OuterXml;
            RSACryptoServiceProviderExtensions.FromXmlString(SenderKeys, SenderKeysXML);

            //Receiver keys
            xmlDoc.Load("ReceiverKeys.xml");
            String ReceiverKeysXML = xmlDoc.OuterXml;
            RSACryptoServiceProviderExtensions.FromXmlString(ReceiverKeys, ReceiverKeysXML);

            //Symmetric key
            xmlDoc.Load("SymmetricKey.xml");
            string keyString = xmlDoc.FirstChild.FirstChild.InnerText;
            string ivString = xmlDoc.FirstChild.LastChild.InnerText;
            SymmetricKey.KeySize = 128;
            SymmetricKey.BlockSize = 128;
            SymmetricKey.Mode = CipherMode.CBC;
            SymmetricKey.Key = Convert.FromBase64String(keyString.Substring(1, keyString.Length - 2));
            SymmetricKey.IV = Convert.FromBase64String(ivString.Substring(1, keyString.Length - 2));
        }
    }
}