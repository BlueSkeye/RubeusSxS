﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using Rubeus.lib;

namespace Rubeus
{
    public class Interop
    {
        // constants

        // From https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L61
        public const int KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP = 1;
        public const int KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3;
        public const int KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR = 7;
        public const int KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8;
        public const int KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR = 11;
        public const int KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART = 13;
        public const int KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART = 14;

        // Enums

        [Flags]
        public enum TicketFlags : UInt32
        {
            reserved = 2147483648,
            forwardable = 0x40000000,
            forwarded = 0x20000000,
            proxiable = 0x10000000,
            proxy = 0x08000000,
            may_postdate = 0x04000000,
            postdated = 0x02000000,
            invalid = 0x01000000,
            renewable = 0x00800000,
            initial = 0x00400000,
            pre_authent = 0x00200000,
            hw_authent = 0x00100000,
            ok_as_delegate = 0x00040000,
            name_canonicalize = 0x00010000,
            //cname_in_pa_data = 0x00040000,
            enc_pa_rep = 0x00010000,
            reserved1 = 0x00000001
            // TODO: constrained delegation?
        }

        // TODO: order flipped? https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/KerberosV5Spec2.asn#L167-L190
        [Flags]
        public enum KdcOptions : uint
        {
            VALIDATE = 0x00000001,
            RENEW = 0x00000002,
            UNUSED29 = 0x00000004,
            ENCTKTINSKEY = 0x00000008,
            RENEWABLEOK = 0x00000010,
            DISABLETRANSITEDCHECK = 0x00000020,
            UNUSED16 = 0x0000FFC0,
            CANONICALIZE = 0x00010000,
            CNAMEINADDLTKT = 0x00020000,
            OK_AS_DELEGATE = 0x00040000,
            UNUSED12 = 0x00080000,
            OPTHARDWAREAUTH = 0x00100000,
            PREAUTHENT = 0x00200000,
            INITIAL = 0x00400000,
            RENEWABLE = 0x00800000,
            UNUSED7 = 0x01000000,
            POSTDATED = 0x02000000,
            ALLOWPOSTDATE = 0x04000000,
            PROXY = 0x08000000,
            PROXIABLE = 0x10000000,
            FORWARDED = 0x20000000,
            FORWARDABLE = 0x40000000,
            RESERVED = 0x80000000
        }

        // from https://tools.ietf.org/html/rfc3961
        public enum KERB_ETYPE : uint
        {
            des_cbc_crc = 1,
            des_cbc_md4 = 2,
            des_cbc_md5 = 3,
            des3_cbc_md5 = 5,
            des3_cbc_sha1 = 7,
            dsaWithSHA1_CmsOID = 9,
            md5WithRSAEncryption_CmsOID = 10,
            sha1WithRSAEncryption_CmsOID = 11,
            rc2CBC_EnvOID = 12,
            rsaEncryption_EnvOID = 13,
            rsaES_OAEP_ENV_OID = 14,
            des_ede3_cbc_Env_OID = 15,
            des3_cbc_sha1_kd = 16,
            aes128_cts_hmac_sha1 = 17,
            aes256_cts_hmac_sha1 = 18,
            rc4_hmac = 23,
            rc4_hmac_exp = 24,
            subkey_keymaterial = 65
        }

        public enum KADMIN_PASSWD_ERR : uint
        {
            KRB5_KPASSWD_SUCCESS = 0,
            KRB5_KPASSWD_MALFORMED = 1,
            KRB5_KPASSWD_HARDERROR = 2,
            KRB5_KPASSWD_AUTHERROR = 3,
            KRB5_KPASSWD_SOFTERROR = 4,
            KRB5_KPASSWD_ACCESSDENIED = 5,
            KRB5_KPASSWD_BAD_VERSION = 6,
            KRB5_KPASSWD_INITIAL_FLAG_NEEDED = 7
        }

        public enum KERB_CHECKSUM_ALGORITHM
        {
            KERB_CHECKSUM_HMAC_SHA1_96_AES128 = 15,
            KERB_CHECKSUM_HMAC_SHA1_96_AES256 = 16,
            KERB_CHECKSUM_DES_MAC = -133,
            KERB_CHECKSUM_HMAC_MD5 = -138,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct KERB_CHECKSUM
        {
            public int Type;
            public int Size;
            public int Flag;
            public IntPtr Initialize;
            public IntPtr Sum;
            public IntPtr Finalize;
            public IntPtr Finish;
            public IntPtr InitializeEx;
            public IntPtr unk0_null;

            // https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1760-L1767
            internal delegate int FinalizeDelegate(IntPtr pContext, byte[] Buffer);
            internal delegate int FinishDelegate(ref IntPtr pContext);
            internal delegate int InitializeDelegate(int unk0, out IntPtr pContext);
            internal delegate int InitializeExDelegate(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);
            internal delegate int SumDelegate(IntPtr pContext, int Size, byte[] Buffer);
        }

        // from https://github.com/ps4dev/freebsd-include-mirror/blob/master/krb5_asn1.h
        public enum PADATA_TYPE : uint
        {
            NONE = 0,
            TGS_REQ = 1,
            AP_REQ = 1,
            ENC_TIMESTAMP = 2,
            PW_SALT = 3,
            ENC_UNIX_TIME = 5,
            SANDIA_SECUREID = 6,
            SESAME = 7,
            OSF_DCE = 8,
            CYBERSAFE_SECUREID = 9,
            AFS3_SALT = 10,
            ETYPE_INFO = 11,
            SAM_CHALLENGE = 12,
            SAM_RESPONSE = 13,
            PK_AS_REQ_19 = 14,
            PK_AS_REP_19 = 15,
            PK_AS_REQ_WIN = 15,
            PK_AS_REQ = 16,
            PK_AS_REP = 17,
            PA_PK_OCSP_RESPONSE = 18,
            ETYPE_INFO2 = 19,
            USE_SPECIFIED_KVNO = 20,
            SVR_REFERRAL_INFO = 20,
            SAM_REDIRECT = 21,
            GET_FROM_TYPED_DATA = 22,
            SAM_ETYPE_INFO = 23,
            SERVER_REFERRAL = 25,
            TD_KRB_PRINCIPAL = 102,
            PK_TD_TRUSTED_CERTIFIERS = 104,
            PK_TD_CERTIFICATE_INDEX = 105,
            TD_APP_DEFINED_ERROR = 106,
            TD_REQ_NONCE = 107,
            TD_REQ_SEQ = 108,
            PA_PAC_REQUEST = 128,
            S4U2SELF = 129,
            PA_PAC_OPTIONS = 167,
            PK_AS_09_BINDING = 132,
            CLIENT_CANONICALIZED = 133
        }

        // adapted from https://github.com/skelsec/minikerberos/blob/master/minikerberos/kerberoserror.py#L18-L76
        public enum KERBEROS_ERROR : uint
        {
            KDC_ERR_NONE = 0x0, //No error
            KDC_ERR_NAME_EXP = 0x1, //Client's entry in KDC database has expired
            KDC_ERR_SERVICE_EXP = 0x2, //Server's entry in KDC database has expired
            KDC_ERR_BAD_PVNO = 0x3, //Requested Kerberos version number not supported
            KDC_ERR_C_OLD_MAST_KVNO = 0x4, //Client's key encrypted in old master key
            KDC_ERR_S_OLD_MAST_KVNO = 0x5, //Server's key encrypted in old master key
            KDC_ERR_C_PRINCIPAL_UNKNOWN = 0x6, //Client not found in Kerberos database
            KDC_ERR_S_PRINCIPAL_UNKNOWN = 0x7, //Server not found in Kerberos database
            KDC_ERR_PRINCIPAL_NOT_UNIQUE = 0x8, //Multiple principal entries in KDC database
            KDC_ERR_NULL_KEY = 0x9, //The client or server has a null key (master key)
            KDC_ERR_CANNOT_POSTDATE = 0xA, // Ticket (TGT) not eligible for postdating
            KDC_ERR_NEVER_VALID = 0xB, // Requested start time is later than end time
            KDC_ERR_POLICY = 0xC, //Requested start time is later than end time
            KDC_ERR_BADOPTION = 0xD, //KDC cannot accommodate requested option
            KDC_ERR_ETYPE_NOTSUPP = 0xE, // KDC has no support for encryption type
            KDC_ERR_SUMTYPE_NOSUPP = 0xF, // KDC has no support for checksum type
            KDC_ERR_PADATA_TYPE_NOSUPP = 0x10, //KDC has no support for PADATA type (pre-authentication data)
            KDC_ERR_TRTYPE_NO_SUPP = 0x11, //KDC has no support for transited type
            KDC_ERR_CLIENT_REVOKED = 0x12, // Client’s credentials have been revoked
            KDC_ERR_SERVICE_REVOKED = 0x13, //Credentials for server have been revoked
            KDC_ERR_TGT_REVOKED = 0x14, //TGT has been revoked
            KDC_ERR_CLIENT_NOTYET = 0x15, // Client not yet valid—try again later
            KDC_ERR_SERVICE_NOTYET = 0x16, //Server not yet valid—try again later
            KDC_ERR_KEY_EXPIRED = 0x17, // Password has expired—change password to reset
            KDC_ERR_PREAUTH_FAILED = 0x18, //Pre-authentication information was invalid
            KDC_ERR_PREAUTH_REQUIRED = 0x19, // Additional preauthentication required
            KDC_ERR_SERVER_NOMATCH = 0x1A, //KDC does not know about the requested server
            KDC_ERR_SVC_UNAVAILABLE = 0x1B, // KDC is unavailable
            KRB_AP_ERR_BAD_INTEGRITY = 0x1F, // Integrity check on decrypted field failed
            KRB_AP_ERR_TKT_EXPIRED = 0x20, // The ticket has expired
            KRB_AP_ERR_TKT_NYV = 0x21, //The ticket is not yet valid
            KRB_AP_ERR_REPEAT = 0x22, // The request is a replay
            KRB_AP_ERR_NOT_US = 0x23, //The ticket is not for us
            KRB_AP_ERR_BADMATCH = 0x24, //The ticket and authenticator do not match
            KRB_AP_ERR_SKEW = 0x25, // The clock skew is too great
            KRB_AP_ERR_BADADDR = 0x26, // Network address in network layer header doesn't match address inside ticket
            KRB_AP_ERR_BADVERSION = 0x27, // Protocol version numbers don't match (PVNO)
            KRB_AP_ERR_MSG_TYPE = 0x28, // Message type is unsupported
            KRB_AP_ERR_MODIFIED = 0x29, // Message stream modified and checksum didn't match
            KRB_AP_ERR_BADORDER = 0x2A, // Message out of order (possible tampering)
            KRB_AP_ERR_BADKEYVER = 0x2C, // Specified version of key is not available
            KRB_AP_ERR_NOKEY = 0x2D, // Service key not available
            KRB_AP_ERR_MUT_FAIL = 0x2E, // Mutual authentication failed
            KRB_AP_ERR_BADDIRECTION = 0x2F, // Incorrect message direction
            KRB_AP_ERR_METHOD = 0x30, // Alternative authentication method required
            KRB_AP_ERR_BADSEQ = 0x31, // Incorrect sequence number in message
            KRB_AP_ERR_INAPP_CKSUM = 0x32, // Inappropriate type of checksum in message (checksum may be unsupported)
            KRB_AP_PATH_NOT_ACCEPTED = 0x33, // Desired path is unreachable
            KRB_ERR_RESPONSE_TOO_BIG = 0x34, // Too much data
            KRB_ERR_GENERIC = 0x3C, // Generic error; the description is in the e-data field
            KRB_ERR_FIELD_TOOLONG = 0x3D, // Field is too long for this implementation
            KDC_ERR_CLIENT_NOT_TRUSTED = 0x3E, // The client trust failed or is not implemented
            KDC_ERR_KDC_NOT_TRUSTED = 0x3F, // The KDC server trust failed or could not be verified
            KDC_ERR_INVALID_SIG = 0x40, // The signature is invalid
            KDC_ERR_KEY_TOO_WEAK = 0x41, //A higher encryption level is needed
            KRB_AP_ERR_USER_TO_USER_REQUIRED = 0x42, // User-to-user authorization is required
            KRB_AP_ERR_NO_TGT = 0x43, // No TGT was presented or available
            KDC_ERR_WRONG_REALM = 0x44, //Incorrect domain or principal
        }

        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            /// <summary>The buffer receives a TOKEN_USER structure that contains the user account
            /// of the token.</summary>
            TokenUser = 1,
            /// <summary>The buffer receives a TOKEN_GROUPS structure that contains the group
            /// accounts associated with the token.</summary>
            TokenGroups,
            /// <summary>The buffer receives a TOKEN_PRIVILEGES structure that contains the
            /// privileges of the token.</summary>
            TokenPrivileges,
            /// <summary>The buffer receives a TOKEN_OWNER structure that contains the default
            /// owner security identifier (SID) for newly created objects.</summary>
            TokenOwner,
            /// <summary>The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the
            /// default primary group SID for newly created objects.</summary>
            TokenPrimaryGroup,
            /// <summary>The buffer receives a TOKEN_DEFAULT_DACL structure that contains the
            /// default DACL for newly created objects.</summary>
            TokenDefaultDacl,
            /// <summary>The buffer receives a TOKEN_SOURCE structure that contains the source of
            /// the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.</summary>
            TokenSource,
            /// <summary>The buffer receives a TOKEN_TYPE value that indicates whether the token
            /// is a primary or impersonation token.</summary>
            TokenType,
            /// <summary>The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates
            /// the impersonation level of the token. If the access token is not an impersonation
            /// token, the function fails.</summary>
            TokenImpersonationLevel,
            /// <summary>The buffer receives a TOKEN_STATISTICS structure that contains various
            /// token statistics.</summary>
            TokenStatistics,
            /// <summary>The buffer receives a TOKEN_GROUPS structure that contains the list of
            /// restricting SIDs in a restricted token.</summary>
            TokenRestrictedSids,
            /// <summary>The buffer receives a DWORD value that indicates the Terminal Services
            /// session identifier that is associated with the token. </summary>
            TokenSessionId,
            /// <summary>The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains
            /// the user SID, the group accounts, the restricted SIDs, and the authentication ID
            /// associated with the token.</summary>
            TokenGroupsAndPrivileges,
            /// <summary>Reserved.</summary>
            TokenSessionReference,
            /// <summary>The buffer receives a DWORD value that is nonzero if the token includes
            /// the SANDBOX_INERT flag.</summary>
            TokenSandBoxInert,
            /// <summary>Reserved.</summary>
            TokenAuditPolicy,
            /// <summary>The buffer receives a TOKEN_ORIGIN value. </summary>
            TokenOrigin,
            /// <summary>The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the
            /// elevation level of the token.</summary>
            TokenElevationType,
            /// <summary>The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle
            /// to another token that is linked to this token.</summary>
            TokenLinkedToken,
            /// <summary>The buffer receives a TOKEN_ELEVATION structure that specifies whether
            /// the token is elevated.</summary>
            TokenElevation,
            /// <summary>The buffer receives a DWORD value that is nonzero if the token has ever
            /// been filtered.</summary>
            TokenHasRestrictions,
            /// <summary>The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies
            /// security information contained in the token.</summary>
            TokenAccessInformation,
            /// <summary>The buffer receives a DWORD value that is nonzero if virtualization is
            /// allowed for the token.</summary>
            TokenVirtualizationAllowed,
            /// <summary>The buffer receives a DWORD value that is nonzero if virtualization is
            /// enabled for the token.</summary>
            TokenVirtualizationEnabled,
            /// <summary>The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the
            /// token's integrity level. </summary>
            TokenIntegrityLevel,
            /// <summary>The buffer receives a DWORD value that is nonzero if the token has the
            /// UIAccess flag set.</summary>
            TokenUIAccess,
            /// <summary>The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the
            /// token's mandatory integrity policy.</summary>
            TokenMandatoryPolicy,
            /// <summary>The buffer receives the token's logon security identifier (SID).</summary>
            TokenLogonSid,
            /// <summary>The maximum value for this enumeration</summary>
            MaxTokenInfoClass
        }

        [Flags]
        public enum KERB_CACHE_OPTIONS : UInt64
        {
            KERB_RETRIEVE_TICKET_DEFAULT = 0x0,
            KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 0x1,
            KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 0x2,
            KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 0x4,
            KERB_RETRIEVE_TICKET_AS_KERB_CRED = 0x8,
            KERB_RETRIEVE_TICKET_WITH_SEC_CRED = 0x10,
            KERB_RETRIEVE_TICKET_CACHE_TICKET = 0x20,
            KERB_RETRIEVE_TICKET_MAX_LIFETIME = 0x40,
        }

        public enum KERB_PROTOCOL_MESSAGE_TYPE : uint
        {
            KerbDebugRequestMessage = 0,
            KerbQueryTicketCacheMessage = 1,
            KerbChangeMachinePasswordMessage = 2,
            KerbVerifyPacMessage = 3,
            KerbRetrieveTicketMessage = 4,
            KerbUpdateAddressesMessage = 5,
            KerbPurgeTicketCacheMessage = 6,
            KerbChangePasswordMessage = 7,
            KerbRetrieveEncodedTicketMessage = 8,
            KerbDecryptDataMessage = 9,
            KerbAddBindingCacheEntryMessage = 10,
            KerbSetPasswordMessage = 11,
            KerbSetPasswordExMessage = 12,
            KerbVerifyCredentialsMessage = 13,
            KerbQueryTicketCacheExMessage = 14,
            KerbPurgeTicketCacheExMessage = 15,
            KerbRefreshSmartcardCredentialsMessage = 16,
            KerbAddExtraCredentialsMessage = 17,
            KerbQuerySupplementalCredentialsMessage = 18,
            KerbTransferCredentialsMessage = 19,
            KerbQueryTicketCacheEx2Message = 20,
            KerbSubmitTicketMessage = 21,
            KerbAddExtraCredentialsExMessage = 22,
            KerbQueryKdcProxyCacheMessage = 23,
            KerbPurgeKdcProxyCacheMessage = 24,
            KerbQueryTicketCacheEx3Message = 25,
            KerbCleanupMachinePkinitCredsMessage = 26,
            KerbAddBindingCacheEntryExMessage = 27,
            KerbQueryBindingCacheMessage = 28,
            KerbPurgeBindingCacheMessage = 29,
            KerbQueryDomainExtendedPoliciesMessage = 30,
            KerbQueryS4U2ProxyCacheMessage = 31
        }

        public enum SECURITY_LOGON_TYPE : uint
        {
            Interactive = 2,        // logging on interactively.
            Network,                // logging using a network.
            Batch,                  // logon for a batch process.
            Service,                // logon for a service account.
            Proxy,                  // Not supported.
            Unlock,                 // Tattempt to unlock a workstation.
            NetworkCleartext,       // network logon with cleartext credentials
            NewCredentials,         // caller can clone its current token and specify new credentials for outbound connections
            RemoteInteractive,      // terminal server session that is both remote and interactive
            CachedInteractive,      // attempt to use the cached credentials without going out across the network
            CachedRemoteInteractive,// same as RemoteInteractive, except used internally for auditing purposes
            CachedUnlock            // attempt to unlock a workstation
        }

        public enum LOGON_PROVIDER
        {
            LOGON32_PROVIDER_DEFAULT,
            LOGON32_PROVIDER_WINNT35,
            LOGON32_PROVIDER_WINNT40,
            LOGON32_PROVIDER_WINNT50
        }

        // from https://github.com/alexbrainman/sspi/blob/master/syscall.go#L113-L129
        [Flags]
        public enum ISC_REQ : int
        {
            DELEGATE = 1,
            MUTUAL_AUTH = 2,
            REPLAY_DETECT = 4,
            SEQUENCE_DETECT = 8,
            CONFIDENTIALITY = 16,
            USE_SESSION_KEY = 32,
            PROMPT_FOR_CREDS = 64,
            USE_SUPPLIED_CREDS = 128,
            ALLOCATE_MEMORY = 256,
            USE_DCE_STYLE = 512,
            DATAGRAM = 1024,
            CONNECTION = 2048,
            EXTENDED_ERROR = 16384,
            STREAM = 32768,
            INTEGRITY = 65536,
            MANUAL_CRED_VALIDATION = 524288,
            HTTP = 268435456
        }

        public enum SecBufferType
        {
            SECBUFFER_VERSION = 0,
            SECBUFFER_EMPTY = 0,
            SECBUFFER_DATA = 1,
            SECBUFFER_TOKEN = 2
        }

        // structs
        // From Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1773-L1794
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ECRYPT
        {
            int Type0;
            public int BlockSize;
            int Type1;
            public int KeySize;
            public int Size;
            int unk2;
            int unk3;
            public IntPtr AlgName;
            public IntPtr Initialize;
            public IntPtr Encrypt;
            public IntPtr Decrypt;
            public IntPtr Finish;
            IntPtr HashPassword;
            IntPtr RandomKey;
            IntPtr Control;
            IntPtr unk0_null;
            IntPtr unk1_null;
            IntPtr unk2_null;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ClientSiteName;
        }

        public struct SYSTEMTIME
        {
            public ushort wYear;
            public ushort wMonth;
            public ushort wDayOfWeek;
            public ushort wDay;
            public ushort wHour;
            public ushort wMinute;
            public ushort wSecond;
            public ushort wMilliseconds;
        }

        // LSA structures
        [StructLayout(LayoutKind.Sequential)]
        internal struct KERB_SUBMIT_TKT_REQUEST
        {
            internal KERB_SUBMIT_TKT_REQUEST(KERB_PROTOCOL_MESSAGE_TYPE messageType,
                int credentialSize)
            {
                MessageType = messageType;
                LogonId = LUID.Empty;
                Flags = 0;
                Key = new KERB_CRYPTO_KEY32();
                KerbCredSize = credentialSize;
                KerbCredOffset = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST));
            }

            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            internal LUID LogonId;
            public int Flags;
            internal KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
            public int KerbCredSize;
            public int KerbCredOffset;

            [StructLayout(LayoutKind.Sequential)]
            internal struct KERB_CRYPTO_KEY32
            {
                public int KeyType;
                public int Length;
                public int Offset;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct KERB_PURGE_TKT_CACHE_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            internal LUID LogonId;
            LSA_STRING_IN ServerName;
            LSA_STRING_IN RealmName;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID : IEquatable<LUID>
        {
            internal LUID(uint lowPart, int highPart = 0)
            {
                LowPart = lowPart;
                HighPart = highPart;
            }

            internal LUID(string value, int fromBase = 16)
            {
                switch (fromBase) {
                    case 10:
                    case 16:
                        break;
                    default:
                        throw new ArgumentOutOfRangeException("fromBase");
                }
                ulong rawValue = Convert.ToUInt64(value, fromBase);
                this.LowPart = (uint)(rawValue & uint.MaxValue);
                this.HighPart = (int)(uint)(rawValue >> 32);
            }

            public bool Equals(LUID other)
            {
                return (this.LowPart == other.LowPart) && (this.HighPart == other.HighPart);
            }

            internal bool IsEmpty
            {
                get
                {
                    return (0 == LowPart) && (0 == HighPart);
                }
            }

            internal uint LowPart;
            internal int HighPart;

            internal static readonly LUID Empty = new LUID() { LowPart = 0, HighPart = 0 };

            internal class EqualityComparer : IEqualityComparer<LUID>
            {
                static EqualityComparer()
                {
                    Singleton = new EqualityComparer();
                }

                private EqualityComparer()
                {
                    // Intentionally left empty.
                    return;
                }

                internal static EqualityComparer Singleton { get; private set; }

                public bool Equals(LUID x, LUID y)
                {
                    return (x.LowPart == y.LowPart) && (x.HighPart == y.HighPart);
                }

                public int GetHashCode(LUID obj)
                {
                    return ((ulong)((ulong)obj.LowPart | (((ulong)(uint)obj.HighPart) << 32))).GetHashCode();
                }
            }
        }

        //[StructLayout(LayoutKind.Sequential)]
        //public struct SECURITY_HANDLE
        //{
        //    public IntPtr LowPart;
        //    public IntPtr HighPart;
        //    public SECURITY_HANDLE(int dummy)
        //    {
        //        LowPart = HighPart = IntPtr.Zero;
        //    }
        //};

        //[StructLayout(LayoutKind.Sequential)]
        //public struct SECURITY_INTEGER
        //{
        //    public uint LowPart;
        //    public int HighPart;
        //    public SECURITY_INTEGER(int dummy)
        //    {
        //        LowPart = 0;
        //        HighPart = 0;
        //    }
        //};

        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_STRING_IN
        {
            internal LSA_STRING_IN(string name)
            {
                if (null == name) {
                    throw new ArgumentNullException("name");
                }
                int nameLength = name.Length;
                if ((ushort.MaxValue - 1) <= nameLength) {
                    throw new ArgumentOutOfRangeException("name.Length");
                }
                Length = (ushort)nameLength;
                MaximumLength = (ushort)(nameLength + 1);
                Buffer = name;
                return;
            }

            internal ushort Length;
            internal ushort MaximumLength;
            internal string Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_OUT
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            internal string GetValue()
            {
                return Marshal.PtrToStringUni(Buffer, Length / sizeof(char)).Trim();
            }
        }

        // BS : Unused
        //[StructLayout(LayoutKind.Sequential)]
        //public struct LSA_STRING
        //{
        //    public ushort Length;
        //    public ushort MaximumLength;
        //    public string Buffer;
        //}

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                if (IntPtr.Zero != Buffer) {
                    Marshal.FreeHGlobal(Buffer);
                }
                Buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(Buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct KERB_RETRIEVE_TKT_RESPONSE
        {
            internal KERB_EXTERNAL_TICKET Ticket;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct KERB_EXTERNAL_TICKET
        {
            private IntPtr ServiceName;
            public IntPtr TargetName;
            public IntPtr ClientName;
            public LSA_STRING_OUT DomainName;
            public LSA_STRING_OUT TargetDomainName;
            public LSA_STRING_OUT AltTargetDomainName;
            public KERB_CRYPTO_KEY SessionKey;
            public uint TicketFlags;
            public uint Flags;
            public long KeyExpirationTime;
            public long StartTime;
            public long EndTime;
            public long RenewUntil;
            public long TimeSkew;
            public int EncodedTicketSize;
            public IntPtr EncodedTicket;

            public string GetClientName()
            {
                if (IntPtr.Zero == this.ClientName) {
                    return string.Empty;
                }
                KERB_EXTERNAL_NAME clientNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(this.ClientName, typeof(KERB_EXTERNAL_NAME));
                return clientNameStruct.GetFormattedName();
            }

            public string GetServiceName()
            {
                if (IntPtr.Zero == this.ServiceName) {
                    return string.Empty;
                }
                KERB_EXTERNAL_NAME serviceNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(this.ServiceName, typeof(KERB_EXTERNAL_NAME));
                return serviceNameStruct.GetFormattedName();
            }

            internal string GetTargetName()
            {
                if (IntPtr.Zero == this.TargetName) {
                    return string.Empty;
                }
                KERB_EXTERNAL_NAME targetNameStruct = (KERB_EXTERNAL_NAME)Marshal.PtrToStructure(this.TargetName, typeof(KERB_EXTERNAL_NAME));
                return targetNameStruct.GetFormattedName();
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CRYPTO_KEY
        {
            public Int32 KeyType;
            public Int32 Length;
            public IntPtr Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct KERB_RETRIEVE_TKT_REQUEST
        {
            internal KERB_RETRIEVE_TKT_REQUEST(LUID logonId,
                KERB_PROTOCOL_MESSAGE_TYPE messageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbDebugRequestMessage)
            {
                MessageType = messageType;
                LogonId = logonId;
                TargetName = new UNICODE_STRING();
                TicketFlags = 0;
                CacheOptions = 0;
                EncryptionType = 0;
                CredentialsHandle = new SECURITY_HANDLE();
            }

            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            internal LUID LogonId;
            public UNICODE_STRING TargetName;
            public uint TicketFlags;
            public uint CacheOptions;
            public int EncryptionType;
            public SECURITY_HANDLE CredentialsHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct KERB_QUERY_TKT_CACHE_REQUEST
        {
            internal KERB_QUERY_TKT_CACHE_REQUEST(LUID logonId,
                KERB_PROTOCOL_MESSAGE_TYPE messageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbDebugRequestMessage)
            {
                LogonId = logonId;
                MessageType = messageType;
            }

            internal KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            internal LUID LogonId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_QUERY_TKT_CACHE_RESPONSE
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public int CountOfTickets;
            public IntPtr Tickets;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_TICKET_CACHE_INFO
        {
            public LSA_STRING_OUT ServerName;
            public LSA_STRING_OUT RealmName;
            public Int64 StartTime;
            public Int64 EndTime;
            public Int64 RenewTime;
            public Int32 EncryptionType;
            public UInt32 TicketFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_EXTERNAL_NAME
        {
            public short NameType;
            public ushort NameCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public LSA_STRING_OUT[] Names;

            internal string GetFormattedName()
            {
                LSA_STRING_OUT[] names = this.Names;
                switch(this.NameCount) {
                    case 1:
                        return names[0].GetValue();
                    case 2:
                        return string.Format("{0}/{1}", names[0].GetValue(), names[1].GetValue());
                    default:
                        return string.Empty;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_LOGON_SESSION_DATA
        {
            public UInt32 Size;
            internal LUID LoginID;
            public LSA_STRING_OUT Username;
            public LSA_STRING_OUT LoginDomain;
            public LSA_STRING_OUT AuthenticationPackage;
            public UInt32 LogonType;
            public UInt32 Session;
            public IntPtr PSiD;
            public UInt64 LoginTime;
            public LSA_STRING_OUT LogonServer;
            public LSA_STRING_OUT DnsDomainName;
            public LSA_STRING_OUT Upn;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct TOKEN_STATISTICS
        {
            internal LUID TokenId;
            internal LUID AuthenticationId;
            public long ExpirationTime;
            public uint TokenType;
            public uint ImpersonationLevel;
            public uint DynamicCharged;
            public uint DynamicAvailable;
            public uint GroupCount;
            public uint PrivilegeCount;
            public LUID ModifiedId;
        }

        // the following are adapted from https://www.pinvoke.net/default.aspx/secur32.InitializeSecurityContext
        [StructLayout(LayoutKind.Sequential)]
        public struct SecHandle //=PCtxtHandle
        {
            IntPtr dwLower; // ULONG_PTR translates to IntPtr not to uint
            IntPtr dwUpper; // this is crucial for 64-Bit Platforms
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SecBuffer : IDisposable
        {
            public int cbBuffer;
            public int BufferType;
            public IntPtr pvBuffer;


            public SecBuffer(int bufferSize)
            {
                cbBuffer = bufferSize;
                BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
                pvBuffer = Marshal.AllocHGlobal(bufferSize);
            }

            public SecBuffer(byte[] secBufferBytes)
            {
                cbBuffer = secBufferBytes.Length;
                BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public SecBuffer(byte[] secBufferBytes, SecBufferType bufferType)
            {
                cbBuffer = secBufferBytes.Length;
                BufferType = (int)bufferType;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public void Dispose()
            {
                if (pvBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pvBuffer);
                    pvBuffer = IntPtr.Zero;
                }
            }
        }

        public struct MultipleSecBufferHelper
        {
            public byte[] Buffer;
            public SecBufferType BufferType;

            public MultipleSecBufferHelper(byte[] buffer, SecBufferType bufferType)
            {
                if (buffer == null || buffer.Length == 0)
                {
                    throw new ArgumentException("buffer cannot be null or 0 length");
                }

                Buffer = buffer;
                BufferType = bufferType;
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecBufferDesc : IDisposable
        {
            public int ulVersion;
            public int cBuffers;
            public IntPtr pBuffers; //Point to SecBuffer

            public SecBufferDesc(int bufferSize)
            {
                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = 1;
                pBuffers = Helpers.AllocAndInit(new SecBuffer(bufferSize));
            }

            public SecBufferDesc(byte[] secBufferBytes)
            {
                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = 1;
                pBuffers = Helpers.AllocAndInit(new SecBuffer(secBufferBytes));
            }

            public SecBufferDesc(MultipleSecBufferHelper[] secBufferBytesArray)
            {
                if ((null == secBufferBytesArray) || (0 == secBufferBytesArray.Length)) {
                    throw new ArgumentException("secBufferBytesArray cannot be null or 0 length");
                }
                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = secBufferBytesArray.Length;
                //Allocate memory for SecBuffer Array....
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBuffer)) * cBuffers);
                for (int Index = 0; Index < secBufferBytesArray.Length; Index++) {
                    //Super hack: Now allocate memory for the individual SecBuffers
                    //and just copy the bit values to the SecBuffer array!!!
                    SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytesArray[Index].Buffer, secBufferBytesArray[Index].BufferType);

                    //We will write out bits in the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //Note that we won't be releasing the memory allocated by ThisSecBuffer until we
                    //are disposed...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    Marshal.WriteInt32(pBuffers, CurrentOffset, ThisSecBuffer.cbBuffer);
                    Marshal.WriteInt32(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer), ThisSecBuffer.BufferType);
                    Marshal.WriteIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer) + Marshal.SizeOf(ThisSecBuffer.BufferType), ThisSecBuffer.pvBuffer);
                }
            }

            public void Dispose()
            {
                if (IntPtr.Zero != pBuffers) {
                    return;
                }
                try {
                    if (1 == cBuffers) {
                        SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                        ThisSecBuffer.Dispose();
                        return;
                    }
                    for (int bufferIndex = 0; bufferIndex < cBuffers; bufferIndex++) {
                        //The bits were written out the following order:
                        //int cbBuffer;
                        //int BufferType;
                        //pvBuffer;
                        //What we need to do here is to grab a hold of the pvBuffer allocate by the individual
                        //SecBuffer and release it...
                        int CurrentOffset = bufferIndex * Marshal.SizeOf(typeof(SecBuffer));
                        IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                        Marshal.FreeHGlobal(SecBufferpvBuffer);
                    }
                }
                finally {
                    Marshal.FreeHGlobal(pBuffers);
                    pBuffers = IntPtr.Zero;
                }
            }

            public byte[] GetSecBufferByteArray()
            {
                byte[] result = null;

                if (IntPtr.Zero == pBuffers) {
                    throw new ObjectDisposedException("Object has already been disposed!!!");
                }
                if (1 == cBuffers) {
                    SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));

                    if (ThisSecBuffer.cbBuffer > 0) {
                        result = new byte[ThisSecBuffer.cbBuffer];
                        Marshal.Copy(ThisSecBuffer.pvBuffer, result, 0, ThisSecBuffer.cbBuffer);
                    }
                    return result;
                }
                int BytesToAllocate = 0;

                for (int Index = 0; Index < cBuffers; Index++) {
                    //The bits were written out the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //What we need to do here calculate the total number of bytes we need to copy...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    BytesToAllocate += Marshal.ReadInt32(pBuffers, CurrentOffset);
                }
                result = new byte[BytesToAllocate];

                for (int Index = 0, BufferIndex = 0; Index < cBuffers; Index++) {
                    //The bits were written out the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //Now iterate over the individual buffers and put them together into a
                    //byte array...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    int BytesToCopy = Marshal.ReadInt32(pBuffers, CurrentOffset);
                    IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                    Marshal.Copy(SecBufferpvBuffer, result, BufferIndex, BytesToCopy);
                    BufferIndex += BytesToCopy;
                }
                return result;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;

            // BS : Unused
            //public SECURITY_HANDLE(int dummy)
            //{
            //    LowPart = HighPart = IntPtr.Zero;
            //}
        }

        // BS : Unused
        //[StructLayout(LayoutKind.Sequential)]
        //public struct SecPkgContext_Sizes
        //{
        //    public uint cbMaxToken;
        //    public uint cbMaxSignature;
        //    public uint cbBlockSize;
        //    public uint cbSecurityTrailer;
        //};

        // functions
        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int CDLocateCSystem(KERB_ETYPE type, out IntPtr pCheckSum);

        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int CDLocateCheckSum(KERB_CHECKSUM_ALGORITHM type, out IntPtr pCheckSum);

        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1753-L1767
        public delegate int KERB_ECRYPT_Initialize(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);
        public delegate int KERB_ECRYPT_Encrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
        public delegate int KERB_ECRYPT_Decrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
        public delegate int KERB_ECRYPT_Finish(ref IntPtr pContext);

        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern NativeReturnCode DsGetDcName(
            [MarshalAs(UnmanagedType.LPTStr)] string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)] string DomainName,
            [In] int DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)] string SiteName,
            [MarshalAs(UnmanagedType.U4)] DSGETDCNAME_FLAGS flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO);

        [DllImport("Netapi32.dll", SetLastError = true)]
        public static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("kernel32.dll")]
        public extern static void GetSystemTime(ref SYSTEMTIME lpSystemTime);

        // LSA functions
        /// <summary>The LsaConnectUntrusted function establishes an untrusted connection to the
        /// LSA server.</summary>
        /// <param name="LsaHandle">Pointer to a handle that receives the connection handle, which
        /// must be provided in future authentication services.</param>
        /// <returns></returns>
        /// <remarks>LsaConnectUntrusted returns a handle to an untrusted connection; it does not
        /// verify any information about the caller. The handle should be closed using the
        /// LsaDeregisterLogonProcess function.
        /// If your application simply needs to query information from authentication packages,
        /// you can use the handle returned by this function in calls to
        /// LsaCallAuthenticationPackage and LsaLookupAuthenticationPackage.
        /// Applications with the SeTcbPrivilege privilege may create a trusted connection by
        /// calling LsaRegisterLogonProcess.</remarks>
        [DllImport("secur32.dll", SetLastError = false)]
        internal static extern NativeReturnCode LsaConnectUntrusted(
            [Out] out IntPtr LsaHandle
        );

        [DllImport("secur32.dll", SetLastError = false)]
        internal static extern NativeReturnCode LsaLookupAuthenticationPackage(
            [In] IntPtr LsaHandle,
            [In] LSA_STRING_IN PackageName,
            [Out] out int AuthenticationPackage
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalAlloc(
            uint uFlags,
            uint uBytes
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaNtStatusToWinError(
            uint status
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaFreeMemory(
            IntPtr buffer
        );

        [DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
        public static extern void CopyMemory(
            IntPtr dest,
            IntPtr src,
            uint count
        );

        [DllImport("secur32.dll", SetLastError = false)]
        internal static extern NativeReturnCode LsaCallAuthenticationPackage(
            IntPtr LsaHandle,
            int AuthenticationPackage,
            IntPtr ProtocolSubmitBuffer,
            int SubmitBufferLength,
            out IntPtr ProtocolReturnBuffer,
            out int ReturnBufferLength,
            out int ProtocolStatus
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaDeregisterLogonProcess(
            [In] IntPtr LsaHandle
        );

        /// <summary>The LsaRegisterLogonProcess function establishes a connection to the LSA
        /// server and verifies that the caller is a logon application.</summary>
        /// <param name="LogonProcessName">Pointer to an LSA_STRING structure identifying the
        /// logon application. This should be a printable name suitable for display to
        /// administrators. For example, the Windows logon application might use the name
        /// "User32LogonProcess". This name is used by the LSA during auditing.
        /// LsaRegisterLogonProcess does not check whether the name is already in use.
        /// This string must not exceed 127 bytes.</param>
        /// <param name="LsaHandle">Pointer that receives a handle used in future authentication
        /// function calls.</param>
        /// <param name="SecurityMode">The value returned is not meaningful and should be ignored.</param>
        /// <returns></returns>
        /// <remarks>This function must be called before a logon process may use any other logon
        /// authentication functions provided by the LSA. The LsaRegisterLogonProcess function
        /// verifies that the application making the function call is a logon process by checking
        /// that it has the SeTcbPrivilege privilege set.It also opens the application's process
        /// for PROCESS_DUP_HANDLE access in anticipation of future LSA authentication calls. For
        /// more information, see DuplicateHandle.
        /// When you have finished using the connection to the LSA server, delete the caller's
        /// logon application context and close the connection by calling the
        /// LsaDeregisterLogonProcess function.</remarks>
        [DllImport("secur32.dll", SetLastError = true)]
        internal static extern Rubeus.lib.NativeReturnCode LsaRegisterLogonProcess(
            LSA_STRING_IN LogonProcessName,
            out IntPtr LsaHandle,
            out ulong SecurityMode
        );

        // for GetSystem()
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll")]
        public static extern bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
            String userName,
            String domain,
            String password,
            UInt32 logonFlags,
            String applicationName,
            String commandLine,
            UInt32 creationFlags,
            UInt32 environment,
            String currentDirectory,
            ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(
            IntPtr hObject
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        internal static extern NativeReturnCode LsaEnumerateLogonSessions(
            out UInt64 LogonSessionCount,
            out IntPtr LogonSessionList
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        internal static extern NativeReturnCode LsaGetLogonSessionData(
            IntPtr luid,
            out IntPtr ppLogonSessionData
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaFreeReturnBuffer(
            IntPtr buffer
        );

        // adapted from https://www.pinvoke.net/default.aspx/secur32.InitializeSecurityContext
        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int AcquireCredentialsHandle(
            string pszPrincipal, //SEC_CHAR*
            string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
            int fCredentialUse,
            IntPtr PAuthenticationID,//_LUID AuthenticationID,//pvLogonID,//PLUID
            IntPtr pAuthData,//PVOID
            int pGetKeyFn, //SEC_GET_KEY_FN
            IntPtr pvGetKeyArgument, //PVOID
            ref SECURITY_HANDLE phCredential, //SecHandle //PCtxtHandle ref
            ref SECURITY_INTEGER ptsExpiry  //PTimeStamp //TimeStamp ref
        );

        [DllImport("secur32.dll", SetLastError = true)]
        internal static extern int InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential,//PCredHandle
            IntPtr phContext, //PCtxtHandle
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            IntPtr pInput, //PSecBufferDesc SecBufferDesc
            int Reserved2,
            out SECURITY_HANDLE phNewContext, //PCtxtHandle
            out SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
            out uint pfContextAttr, //managed ulong == 64 bits!!!
            out SECURITY_INTEGER ptsExpiry  //PTimeStamp
        );

        [DllImport("secur32.dll")]
        public static extern int DeleteSecurityContext(
            ref SECURITY_HANDLE phContext
        );

        [DllImport("secur32.dll", CharSet = CharSet.Auto)]
        public static extern int FreeCredentialsHandle(
            [In] ref SECURITY_HANDLE phCredential
        );

        [DllImport("Secur32.dll")]
        public static extern int FreeContextBuffer(
            ref IntPtr pvContextBuffer
        );
    }
}