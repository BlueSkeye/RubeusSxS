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

            if (arguments.TryGetValue("/luid",out luidString)) {
                string service = arguments.GetArgument("/service", string.Empty);
                uint luid = 0;
                if (!uint.TryParse(luidString, out luid)) {
                    try {
                        luid = Convert.ToUInt32(luidString, 16);
                    }
                    catch {
                        Console.WriteLine("[X] Invalid LUID format ({0})\r\n", luidString);
                        return;
                    }
                }
                LSA.ListKerberosTicketData(luid, service);
                return;
            }
            if (arguments.ContainsKey("/service")) {
                LSA.ListKerberosTicketData(0, arguments["/service"]);
                return;
            }
            LSA.ListKerberosTicketData();
            return;
        }
    }
}