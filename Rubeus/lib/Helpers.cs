﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;

using Asn1;

namespace Rubeus
{
    public class Helpers
    {
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

        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM for Kerberos ticket enumeration via token impersonation
            if (IsHighIntegrity()) {
                IntPtr hToken = IntPtr.Zero;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success) {
                    //Console.WriteLine("OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success) {
                    //Console.WriteLine("DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success) {
                    //Console.WriteLine("ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                string name = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                return (name == "NT AUTHORITY\\SYSTEM");
            }
            return false;
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

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
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

        private static Random random = new Random();
    }
}