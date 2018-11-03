using System;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

using Rubeus.lib;

namespace Rubeus
{
    public class Networking
    {
        internal static string GetDCName()
        {
            // retrieves the current domain controller name
            // adapted from https://www.pinvoke.net/default.aspx/netapi32.dsgetdcname
            Interop.DOMAIN_CONTROLLER_INFO domainInfo;
            IntPtr pDCI = IntPtr.Zero;

            try {
                NativeReturnCode val = Interop.DsGetDcName("", "", 0, "",
                    Interop.DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED |
                    Interop.DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
                    Interop.DSGETDCNAME_FLAGS.DS_IP_REQUIRED, out pDCI);
                if (NativeReturnCode.ERROR_SUCCESS == val) {
                    domainInfo = (Interop.DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(pDCI, typeof(Interop.DOMAIN_CONTROLLER_INFO));
                    return domainInfo.DomainControllerName.Trim('\\');
                }
                Console.WriteLine("\r\n  [X] Error {0} retrieving domain controller : {1}", val,
                    new Win32Exception((int)val).Message);
                return string.Empty;
            }
            finally {
                if (IntPtr.Zero != pDCI) {
                    Interop.NetApiBufferFree(pDCI);
                }
            }
        }

        public static string GetDCIP(string DCName, bool display = true)
        {
            if (string.IsNullOrEmpty(DCName)) {
                DCName = GetDCName();
            }
            Match match = Regex.Match(DCName, @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");
            if (match.Success) {
                if (display) {
                    Console.WriteLine("[*] Using domain controller: {0}", DCName);
                }
                return DCName;
            }
            try {
                IPAddress[] dcIPs = Dns.GetHostAddresses(DCName);

                foreach (IPAddress dcIP in dcIPs) {
                    if (dcIP.AddressFamily == AddressFamily.InterNetwork) {
                        if (display) {
                            Console.WriteLine("[*] Using domain controller: {0} ({1})", DCName, dcIP);
                        }
                        return String.Format("{0}", dcIP);
                    }
                }
                Console.WriteLine("[X] Error resolving hostname '{0}' to an IP address: no IPv4 address found", DCName);
            }
            catch(Exception e) {
                Console.WriteLine("[X] Error resolving hostname '{0}' to an IP address: {1}", DCName, e.Message);
            }
            return null;
        }

        public static byte[] SendBytes(string server, int port, byte[] data, bool noHeader = false)
        {
            // send the byte array to the specified server/port
            // TODO: try/catch for IPAddress parse
            Console.WriteLine("[*] Connecting to {0}:{1}", server, port);
            IPEndPoint endPoint = new IPEndPoint(IPAddress.Parse(server), port);
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Ttl = 128;
            byte[] totalRequestBytes;

            if (noHeader) {
                // used for MS Kpasswd
                totalRequestBytes = data;
            }
            else {
                byte[] lenBytes = BitConverter.GetBytes(data.Length);
                Array.Reverse(lenBytes);

                // build byte[req len + req bytes]
                totalRequestBytes = new byte[lenBytes.Length + data.Length];
                Array.Copy(lenBytes, totalRequestBytes, lenBytes.Length);
                Array.Copy(data, 0, totalRequestBytes, lenBytes.Length, data.Length);
            }
            try {
                // connect to the srever over The specified port
                socket.Connect(endPoint);
            }
            catch (Exception e) {
                Console.WriteLine("[X] Error connecting to {0}:{1} : {2}", server, port, e.Message);
                return null;
            }
            // actually send the bytes
            int bytesSent = socket.Send(totalRequestBytes);
            Console.WriteLine("[*] Sent {0} bytes", bytesSent);
            byte[] responseBuffer = new byte[2500];
            int bytesReceived = socket.Receive(responseBuffer);
            Console.WriteLine("[*] Received {0} bytes", bytesReceived);
            byte[] response;
            if (noHeader) {
                response = new byte[bytesReceived];
                Array.Copy(responseBuffer, 0, response, 0, bytesReceived);
            }
            else {
                response = new byte[bytesReceived - 4];
                Array.Copy(responseBuffer, 4, response, 0, bytesReceived - 4);
            }
            socket.Close();
            return response;
        }
    }
}