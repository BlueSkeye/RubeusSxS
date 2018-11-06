using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;

using Asn1;
using Rubeus.lib;

namespace Rubeus
{
    internal static class Helpers
    {
        internal static IntPtr AllocAndInit<T>(T managed, int additionalSpace = 0)
        {
            int realSize;
            return AllocAndInit<T>(managed, out realSize, additionalSpace);
        }

        internal static IntPtr AllocAndInit<T>(T managed, out int realSize, int additionalSpace = 0)
        {
            if (0 > additionalSpace) {
                throw new ArgumentOutOfRangeException();
            }
            int baseStructureSize = Marshal.SizeOf(typeof(T));
            realSize = baseStructureSize + additionalSpace;
            IntPtr result = Marshal.AllocHGlobal(realSize);
            // marshal the struct from a managed object to an unmanaged block of memory.
            Marshal.StructureToPtr(managed, result, false);
            return result;
        }

        internal static void AppendUnicodeString<T>(IntPtr nativeBuffer, Interop.UNICODE_STRING data,
            string fieldName)
        {
            Type targetType = typeof(T);
            // Set pointer to end of T structure
            IntPtr nativeDataBuffer = (IntPtr)(nativeBuffer.ToInt64() + Marshal.SizeOf(targetType));
            // Copy unicode chars to the new location
            Interop.CopyMemory(nativeDataBuffer, data.Buffer, data.MaximumLength);
            // Update the target name buffer ptr            
            Marshal.WriteIntPtr(nativeBuffer,
                Marshal.OffsetOf(targetType, fieldName).ToInt32() +
                    Marshal.OffsetOf(typeof(Interop.UNICODE_STRING), "Buffer").ToInt32(),
                nativeDataBuffer);
        }

        internal static void DisplayKerberosError(AsnElt from)
        {
            long errorCode = new KRB_ERROR(from.FirstElement).ErrorCode;
            Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n",
                errorCode, (Interop.KERBEROS_ERROR)errorCode);
            return;
        }

        internal static void DisplayKerberosTicket(byte[] ticket)
        {
                string ticketString = Convert.ToBase64String(ticket);
                Console.WriteLine("[*] base64(ticket.kirbi):\r\n", ticketString);

                // display the .kirbi base64, columns of 80 chararacters
                foreach (string line in Helpers.Split(ticketString, 80)) {
                    Console.WriteLine("      {0}", line);
                }
        }

        internal static string GetArgument(this Dictionary<string, string> arguments, string argumentName,
            string defaultValue = null)
        {
            string result;
            return arguments.TryGetValue(argumentName, out result)
                ? result
                : defaultValue;
        }

        internal static bool GetSystem()
        {
            // helper to elevate to SYSTEM for Kerberos ticket enumeration via token impersonation
            if (!IsHighIntegrity()) {
                return false;
            }
            IntPtr hToken = IntPtr.Zero;
            IntPtr hDupToken = IntPtr.Zero;

            try {
                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy
                // of the token with DuplicateToken
                IntPtr handle = Process.GetProcessesByName("winlogon")[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                return TraceFailure(Interop.OpenProcessToken(handle, 0x0002, out hToken),
                    "OpenProcessToken failed!")
                    // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                    // 2 == SecurityImpersonation
                    && TraceFailure(Interop.DuplicateToken(hToken, 2, ref hDupToken),
                        "DuplicateToken failed!")
                    && TraceFailure(Interop.ImpersonateLoggedOnUser(hDupToken),
                        "ImpersonateLoggedOnUser failed!")
                    && (WindowsIdentity.GetCurrent().Name == "NT AUTHORITY\\SYSTEM");
            }
            finally {
                // clean up the handles we created
                if (IntPtr.Zero != hToken) {
                    Interop.CloseHandle(hToken);
                }
                if (IntPtr.Zero != hDupToken) {
                    Interop.CloseHandle(hDupToken);
                }
            }
        }

        internal static string GetNativeErrorMessage(uint nativeErrorCode)
        {
            return new Win32Exception((int)nativeErrorCode).Message;
        }

        public static bool IsBase64String(string s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }

        /// <summary>returns true if the current process is running with adminstrative privs
        /// in a high integrity context</summary>
        /// <returns></returns>
        internal static bool IsHighIntegrity()
        {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent())
                .IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>Parse a short integer from the buffer starting at index. The integer is expected to be stored in
        /// big endian order. On return the index is updated to point at the first byte in the buffer after bytes
        /// consumed by the parsing operation.</summary>
        /// <param name="buffer"></param>
        /// <param name="index"></param>
        /// <returns></returns>
        internal static short ParseBigEndianInt16(byte[] buffer, ref int index)
        {
            try {
                return BitConverter.ToInt16(
                    new byte[] { buffer[index + 1], buffer[index] }, 0);
            }
            finally {
                index += sizeof(short);
            }
        }

        /// <summary>Parse an integer from the buffer starting at index. The integer is expected to be stored in
        /// big endian order. On return the index is updated to point at the first byte in the buffer after bytes
        /// consumed by the parsing operation.</summary>
        /// <param name="buffer"></param>
        /// <param name="index"></param>
        /// <returns></returns>
        internal static int ParseBigEndianInt32(byte[] buffer, ref int index)
        {
            try {
                return BitConverter.ToInt32(
                    new byte[] { buffer[index + 3], buffer[index + 2], buffer[index + 1], buffer[index] }, 0);
            }
            finally {
                index += sizeof(int);
            }
        }

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        internal static int SearchBytePattern(byte[] pattern, byte[] bytes)
        {
            List<int> positions = new List<int>();
            int patternLength = pattern.Length;
            int totalLength = bytes.Length;
            byte firstMatchByte = pattern[0];
            for (int i = 0; i < totalLength; i++) {
                if (firstMatchByte == bytes[i] && totalLength - i >= patternLength) {
                    byte[] match = new byte[patternLength];
                    Array.Copy(bytes, i, match, 0, patternLength);
                    if (match.SequenceEqual<byte>(pattern)) {
                        return i;
                    }
                }
            }
            return 0;
        }

        public static IEnumerable<string> Split(string text, int partLength)
        {
            // splits a string into partLength parts
            if (text == null) { Console.WriteLine("[ERROR] Split() - singleLineString"); }
            if (partLength < 1) { Console.WriteLine("[ERROR] Split() - 'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2) {
                yield return text;
            }
            for (int i = 0; i < partCount; i++) {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }

        public static byte[] StringToByteArray(string hex)
        {
            // converts a rc4/AES/etc. string into a byte array representation

            if ((hex.Length % 32) != 0) {
                Console.WriteLine("\r\n[X] Hash must be 32 or 64 characters in length\r\n");
                System.Environment.Exit(1);
            }
            // yes I know this inefficient
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        private static bool TraceFailure(bool success, string errorMessage = null)
        {
            if (success) { return true; }
            if (string.IsNullOrEmpty(errorMessage)) { return false; }
            Console.WriteLine("\r\n[X] {0}\r\n", errorMessage);
            return false;
        }

        internal static void ValidateNativeCall(NativeReturnCode code)
        {
        }

        internal static readonly DateTime BaseDate = new DateTime(1601, 1, 1, 0, 0, 0, 0);
        private static Random random = new Random();
    }
}