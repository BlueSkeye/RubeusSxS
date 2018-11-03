using Rubeus.Domain;

namespace Rubeus
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Info.ShowLogo();

            // try to parse the command line arguments, show usage on failure and then bail
            ArgumentParserResult parsed = ArgumentParser.Parse(args);
            if (!parsed.ParsedOk) {
                Info.ShowUsage();
                return;
            }
            // Try to execute the command using the arguments passed in
            string commandName = (0 != args.Length) ? args[0] : string.Empty;
            bool commandFound = new CommandCollection().ExecuteCommand(commandName, parsed.Arguments);
            // show the usage if no commands were found for the command name
            if (!commandFound) {
                Info.ShowUsage();
            }
        }
    }
}
