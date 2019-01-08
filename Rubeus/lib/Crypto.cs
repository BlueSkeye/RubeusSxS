using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace Rubeus
{
    public class Crypto
    {
        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        public static byte[] KerberosChecksum(byte[] key, byte[] data)
        {
            IntPtr pCheckSumPtr;
            int status = Interop.CDLocateCheckSum(Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5, out pCheckSumPtr);
            Interop.KERB_CHECKSUM pCheckSum = (Interop.KERB_CHECKSUM)Marshal.PtrToStructure(pCheckSumPtr,
                typeof(Interop.KERB_CHECKSUM));
            if (0 != status) {
                throw new Win32Exception(status, "CDLocateCheckSum failed");
            }

            IntPtr Context;
            Interop.KERB_CHECKSUM.InitializeExDelegate pCheckSumInitializeEx = (Interop.KERB_CHECKSUM.InitializeExDelegate)Marshal.GetDelegateForFunctionPointer(pCheckSum.InitializeEx, typeof(Interop.KERB_CHECKSUM.InitializeExDelegate));
            Interop.KERB_CHECKSUM.SumDelegate pCheckSumSum = (Interop.KERB_CHECKSUM.SumDelegate)Marshal.GetDelegateForFunctionPointer(pCheckSum.Sum, typeof(Interop.KERB_CHECKSUM.SumDelegate));
            Interop.KERB_CHECKSUM.FinalizeDelegate pCheckSumFinalize = (Interop.KERB_CHECKSUM.FinalizeDelegate)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finalize, typeof(Interop.KERB_CHECKSUM.FinalizeDelegate));
            Interop.KERB_CHECKSUM.FinishDelegate pCheckSumFinish = (Interop.KERB_CHECKSUM.FinishDelegate)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finish, typeof(Interop.KERB_CHECKSUM.FinishDelegate));

            // initialize the checksum
            // KERB_NON_KERB_CKSUM_SALT = 17
            int status2 = pCheckSumInitializeEx(key, key.Length, 17, out Context);
            if (0 != status2) {
                throw new Win32Exception(status2);
            }
            // the output buffer for the checksum data
            byte[] result = new byte[pCheckSum.Size];
            // actually checksum all the supplied data
            pCheckSumSum(Context, data.Length, data);
            // finish everything up
            pCheckSumFinalize(Context, result);
            pCheckSumFinish(ref Context);
            return result;
        }

        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2235-L2262
        public static byte[] KerberosDecrypt(Interop.KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;
            
            // locate the crypto system
            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0) {
                throw new Win32Exception(status, "Error on CDLocateCSystem");
            }

            // initialize everything
            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Decrypt pCSystemDecrypt = (Interop.KERB_ECRYPT_Decrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Decrypt, typeof(Interop.KERB_ECRYPT_Decrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0) {
                throw new Win32Exception(status);
            }

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0) {
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);
            }
            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);
            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];
            // actually perform the decryption
            status = pCSystemDecrypt(pContext, data, data.Length, output, ref outputSize);
            pCSystemFinish(ref pContext);
            return output;
        }

        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2235-L2262
        public static byte[] KerberosEncrypt(Interop.KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system
            int status = Interop.CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0) {
                throw new Win32Exception(status, "Error on CDLocateCSystem");
            }

            // initialize everything
            IntPtr pContext;
            Interop.KERB_ECRYPT_Initialize pCSystemInitialize = (Interop.KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(Interop.KERB_ECRYPT_Initialize));
            Interop.KERB_ECRYPT_Encrypt pCSystemEncrypt = (Interop.KERB_ECRYPT_Encrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Encrypt, typeof(Interop.KERB_ECRYPT_Encrypt));
            Interop.KERB_ECRYPT_Finish pCSystemFinish = (Interop.KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(Interop.KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0) {
                throw new Win32Exception(status);
            }

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0) {
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);
            }
            string algName = Marshal.PtrToStringAuto(pCSystem.AlgName);
            outputSize += pCSystem.Size;
            byte[] result = new byte[outputSize];
            // actually perform the decryption
            status = pCSystemEncrypt(pContext, data, data.Length, result, ref outputSize);
            pCSystemFinish(ref pContext);
            return result;
        }
    }
}