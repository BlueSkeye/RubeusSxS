using System.Collections.Generic;

namespace Rubeus.Domain
{
    public class ArgumentParserResult
    {
        private ArgumentParserResult(bool parsedOk, Dictionary<string, string> arguments)
        {
            ParsedOk = parsedOk;
            Arguments = arguments;
        }

        public Dictionary<string, string> Arguments { get; }

        public bool ParsedOk { get; }

        public static ArgumentParserResult Success(Dictionary<string, string> arguments)
            => new ArgumentParserResult(true, arguments);

        public static ArgumentParserResult Failure()
            => new ArgumentParserResult(false, null);

    }
}