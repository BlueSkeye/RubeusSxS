using System;
using System.Collections.Generic;

namespace Rubeus.Commands
{
    public class Createnetonly : ICommand
    {
        public static string CommandName => "createnetonly";

        public void Execute(Dictionary<string, string> arguments)
        {
            if (arguments.ContainsKey("/program")) {
                LSA.CreateProcessNetOnly(arguments["/program"], arguments.ContainsKey("/show"));
            }
            else {
                Console.WriteLine("\r\n[X] A /program needs to be supplied!\r\n");
            }
        }
    }
}
