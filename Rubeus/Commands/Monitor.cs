using System.Collections.Generic;

namespace Rubeus.Commands
{
    public class Monitor : ICommand
    {
        public static string CommandName => "monitor";

        public void Execute(Dictionary<string, string> arguments)
        {
            string targetUser;

            if (!arguments.TryGetValue("/filteruser", out targetUser)) {
                targetUser = string.Empty;
            }
            int interval;
            string intervalValue;
            interval = arguments.TryGetValue("/interval", out intervalValue)
                ? int.Parse(intervalValue)
                : 60;
            Harvest.Monitor4624(interval, targetUser);
        }
    }
}