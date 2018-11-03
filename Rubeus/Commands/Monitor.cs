using System;
using System.Collections.Generic;

namespace Rubeus.Commands
{
    public class Monitor : ICommand
    {
        public static string CommandName => "monitor";

        public void Execute(Dictionary<string, string> arguments)
        {
            string targetUser = arguments.ContainsKey("/filteruser") ? arguments["/filteruser"] : string.Empty;
            int interval = 60;
            if (arguments.ContainsKey("/interval")) {
                interval = Int32.Parse(arguments["/interval"]);
            }
            Harvest.Monitor4624(interval, targetUser);
        }
    }
}