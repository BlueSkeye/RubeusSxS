using System;

namespace Rubeus.lib
{
    internal class LSAException : ApplicationException
    {
        internal LSAException(NativeReturnCode lsaRetCode)
        {
            LSARetCode = lsaRetCode;
        }

        internal LSAException(NativeReturnCode lsaRetCode, string message)
            : base(message)
        {
            LSARetCode = lsaRetCode;
        }

        internal LSAException(NativeReturnCode lsaRetCode, string message, Exception innerException)
            : base(message, innerException)
        {
            LSARetCode = lsaRetCode;
        }

        internal NativeReturnCode LSARetCode { get; private set; }
    }
}
