using System;
using System.Collections.Generic;
using System.IO;

namespace Rubeus.Commands
{
    public class Describe : ICommand
    {
        public static string CommandName => "describe";

        public void Execute(Dictionary<string, string> arguments)
        {
            string kirbi64;
            if (!arguments.TryGetValue("/ticket", out kirbi64)) {
                Console.WriteLine("\r\n[X] A /ticket:X needs to be supplied!\r\n");
                return;
            }
            if (Helpers.IsBase64String(kirbi64)) {
                LSA.DisplayTicket(new KRB_CRED(Convert.FromBase64String(kirbi64)));
            }
            else if (File.Exists(kirbi64)) {
                LSA.DisplayTicket(new KRB_CRED(File.ReadAllBytes(kirbi64)));
            }
            else {
                Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
            }
        }
    }
}
