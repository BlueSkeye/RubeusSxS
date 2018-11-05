
namespace Rubeus.lib
{
    internal enum NativeReturnCode : uint
    {
        ERROR_SUCCESS = 0,
        STATUS_SUCCESS = 0,
        /// <summary>The specified logon process name exceeds 127 bytes.</summary>
        STATUS_NAME_TOO_LONG = 0xC0000106,
        /// <summary>A specified authetication package is unknown.</summary>
        STATUS_NO_SUCH_PACKAGE = 0xC00000FD,
        /// <summary>The caller does not have the SeTcbPrivilege privilege, which is required to
        /// call this function. You can set this privilege by calling LsaAddAccountRights.</summary>
        STATUS_PORT_CONNECTION_REFUSED = 0xC0000041,
    }
}
