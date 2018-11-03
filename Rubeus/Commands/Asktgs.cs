using System;
using System.Collections.Generic;
using System.IO;

namespace Rubeus.Commands
{
    public class Asktgs : ICommand
    {
        public static string CommandName => "asktgs";

        public void Execute(Dictionary<string, string> arguments)
        {
            string service;

            if (!arguments.TryGetValue("/service", out service) || (string.Empty == service)) {
                Console.WriteLine("[X] One or more '/service:sname/server.domain.com' specifications are needed");
                return;
            }
            string kirbi64;
            if (!arguments.TryGetValue("/ticket", out kirbi64)) {
                Console.WriteLine("\r\n[X] A /ticket:X needs to be supplied!\r\n");
                return;
            }
            byte[] credentials;
            if (Helpers.IsBase64String(kirbi64)) {
                credentials = Convert.FromBase64String(kirbi64);
            }
            else if (File.Exists(kirbi64)) {
                credentials = File.ReadAllBytes(kirbi64);
            }
            else {
                Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                return;
            }
            string dc;

            if (!arguments.TryGetValue("/dc", out dc)) {
                dc = string.Empty;
            }
            Ask.TGS(new KRB_CRED(credentials), service, arguments.ContainsKey("/ptt"), dc, true);
            return;
        }
    }
}