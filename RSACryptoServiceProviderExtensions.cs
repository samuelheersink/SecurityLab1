using System;
using System.Security.Cryptography;
using System.Xml;

///Code taken from Jargon64 on GitHub, with modifications
///https://gist.github.com/Jargon64/5b172c452827e15b21882f1d76a94be4/
namespace Security_Lab_1
{
    public static class RSACryptoServiceProviderExtensions
    {
        public static void FromXmlString(this RSACryptoServiceProvider rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus":     parameters.Modulus =    Convert.FromBase64String(node.InnerText.Substring(1, node.InnerText.Length - 2)); break;
                        case "Exponent":    parameters.Exponent =   Convert.FromBase64String(node.InnerText.Substring(1, node.InnerText.Length - 2)); break;
                        case "P":           parameters.P =          Convert.FromBase64String(node.InnerText.Substring(1, node.InnerText.Length - 2)); break;
                        case "Q":           parameters.Q =          Convert.FromBase64String(node.InnerText.Substring(1, node.InnerText.Length - 2)); break;
                        case "DP":          parameters.DP =         Convert.FromBase64String(node.InnerText.Substring(1, node.InnerText.Length - 2)); break;
                        case "DQ":          parameters.DQ =         Convert.FromBase64String(node.InnerText.Substring(1, node.InnerText.Length - 2)); break;
                        case "InverseQ":    parameters.InverseQ =   Convert.FromBase64String(node.InnerText.Substring(1, node.InnerText.Length - 2)); break;
                        case "D":           parameters.D =          Convert.FromBase64String(node.InnerText.Substring(1, node.InnerText.Length - 2)); break;
                    }
                }
            } else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        public static string ToXmlString(this RSACryptoServiceProvider rsa)
        {
            RSAParameters parameters = rsa.ExportParameters(true);

            return string.Format("<RSAKeyValue><Modulus>'{0}'</Modulus><Exponent>'{1}'</Exponent><P>'{2}'</P><Q>'{3}'</Q><DP>'{4}'</DP><DQ>'{5}'</DQ><InverseQ>'{6}'</InverseQ><D>'{7}'</D></RSAKeyValue>",
                Convert.ToBase64String(parameters.Modulus),
                Convert.ToBase64String(parameters.Exponent),
                Convert.ToBase64String(parameters.P),
                Convert.ToBase64String(parameters.Q),
                Convert.ToBase64String(parameters.DP),
                Convert.ToBase64String(parameters.DQ),
                Convert.ToBase64String(parameters.InverseQ),
                Convert.ToBase64String(parameters.D));
        }
    }
}