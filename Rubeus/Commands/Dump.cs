using System;
using System.Collections.Generic;

namespace Rubeus.Commands
{
    public class Dump : ICommand
    {
        public static string CommandName => "dump";

        public void Execute(Dictionary<string, string> arguments)
        {
            string luidString;

            if (arguments.TryGetValue("/luid", out luidString)) {
                string service = arguments.GetArgument("/service", string.Empty);
                Interop.LUID luid;
                int fromBase;
                if (luidString.StartsWith("0x", StringComparison.InvariantCultureIgnoreCase)) {
                    luidString = (2 == luidString.Length) ? string.Empty : luidString.Substring(2);
                    fromBase = 16;
                }
                else {
                    fromBase = 10;
                }
                try {
                    luid = new Interop.LUID(luidString, fromBase);
                }
                catch {
                    Console.WriteLine("[X] Invalid LUID format ({0})\r\n", luidString);
                    return;
                }
                LSA.ListKerberosTicketData(luid, service);
                return;
            }
            if (arguments.ContainsKey("/service")) {
                LSA.ListKerberosTicketData(Interop.LUID.Empty, arguments["/service"]);
                return;
            }
            LSA.ListKerberosTicketData(Interop.LUID.Empty);
            return;
        }
    }
}