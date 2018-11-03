
namespace Rubeus.lib
{
    internal enum LSAReturnCode : uint
    {
        STATUS_SUCCESS = 0,
        /// <summary>The specified logon process name exceeds 127 bytes.</summary>
        STATUS_NAME_TOO_LONG = 0xC0000106,
        /// <summary>The caller does not have the SeTcbPrivilege privilege, which is required to
        /// call this function. You can set this privilege by calling LsaAddAccountRights.</summary>
        STATUS_PORT_CONNECTION_REFUSED = 0xC0000041,
    }
}
