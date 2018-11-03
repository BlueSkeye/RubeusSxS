using System.Collections.Generic;

namespace Rubeus.Commands
{
    public class Tgtdeleg : ICommand
    {
        public static string CommandName => "tgtdeleg";

        public void Execute(Dictionary<string, string> arguments)
        {
            if (arguments.ContainsKey("/target")) {
                LSA.RequestFakeDelegTicket(arguments["/target"]);
            }
            else {
                LSA.RequestFakeDelegTicket();
            }
        }
    }
}