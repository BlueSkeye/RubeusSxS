using System;
using System.Collections.Generic;
using System.IO;

namespace Rubeus.Commands
{
    public class RenewCommand : ICommand
    {
        public static string CommandName => "renew";

        public void Execute(Dictionary<string, string> arguments)
        {
            bool ptt = arguments.ContainsKey("/ptt");
            string dc = arguments.ContainsKey("/dc") ? arguments["/dc"] : string.Empty;

            if (arguments.ContainsKey("/ticket")) {
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64)) {
                    KRB_CRED kirbi = new KRB_CRED(Convert.FromBase64String(kirbi64));
                    if (arguments.ContainsKey("/autorenew")) {
                        // if we want to auto-renew the TGT up until the renewal limit
                        Renew.TGTAutoRenew(kirbi, dc);
                    }
                    else {
                        // otherwise a single renew operation
                        byte[] blah = Renew.TGT(kirbi, ptt, dc);
                    }
                }
                else if (File.Exists(kirbi64)) {
                    KRB_CRED kirbi = new KRB_CRED(File.ReadAllBytes(kirbi64));
                    if (arguments.ContainsKey("/autorenew")) {
                        // if we want to auto-renew the TGT up until the renewal limit
                        Renew.TGTAutoRenew(kirbi, dc);
                    }
                    else {
                        // otherwise a single renew operation
                        byte[] blah = Renew.TGT(kirbi, ptt, dc);
                    }
                }
                else {
                    Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                }
            }
            else {
                Console.WriteLine("\r\n[X] A /ticket:X needs to be supplied!\r\n");
            }
        }
    }
}