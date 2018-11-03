﻿using System;
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

            if (arguments.ContainsKey("/user")) {
                string[] parts = arguments["/user"].Split('\\');
                if (parts.Length == 2) {
                    domain = parts[0];
                    user = parts[1];
                }
                else {
                    user = arguments["/user"];
                }
            }
            if (arguments.ContainsKey("/domain")) {
                domain = arguments["/domain"];
            }
            if (arguments.ContainsKey("/dc")) {
                dc = arguments["/dc"];
            }
            if (arguments.ContainsKey("/format")) {
                format = arguments["/format"];
            }

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