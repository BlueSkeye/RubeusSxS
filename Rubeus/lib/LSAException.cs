using System;

namespace Rubeus.lib
{
    internal class LSAException : ApplicationException
    {
        internal LSAException(LSAReturnCode lsaRetCode)
        {
            LSARetCode = lsaRetCode;
        }

        internal LSAException(LSAReturnCode lsaRetCode, string message)
            : base(message)
        {
            LSARetCode = lsaRetCode;
        }

        internal LSAException(LSAReturnCode lsaRetCode, string message, Exception innerException)
            : base(message, innerException)
        {
            LSARetCode = lsaRetCode;
        }

        internal LSAReturnCode LSARetCode { get; private set; }
    }
}
