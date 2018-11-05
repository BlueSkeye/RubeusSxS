using System;
using System.IO;
using System.Linq;
using Asn1;

namespace Rubeus
{
    public class Renew
    {
        public static void TGTAutoRenew(KRB_CRED kirbi, string domainController = "", bool display = true)
        {
            Console.WriteLine("[*] Action: Auto-Renew TGT");
            KRB_CRED currentKirbi = kirbi;

            while (true) {
                // extract out the info needed for the TGS-REQ/AP-REQ renewal
                string userName = currentKirbi.EncryptedPart.ticket_info[0].pname.name_string[0];
                string domain = currentKirbi.EncryptedPart.ticket_info[0].prealm;
                Console.WriteLine("\r\n\r\n[*] User       : {0}@{1}", userName, domain);

                DateTime endTime = TimeZone.CurrentTimeZone.ToLocalTime(currentKirbi.EncryptedPart.ticket_info[0].endtime);
                DateTime renewTill = TimeZone.CurrentTimeZone.ToLocalTime(currentKirbi.EncryptedPart.ticket_info[0].renew_till);
                Console.WriteLine("[*] endtime    : {0}", endTime);
                Console.WriteLine("[*] renew-till : {0}", renewTill);
                if (endTime > renewTill) {
                    Console.WriteLine("\r\n[*] renew-till window ({0}) has passed.\r\n", renewTill);
                    return;
                }
                double ticks = (endTime - DateTime.Now).Ticks;
                if (ticks < 0) {
                    Console.WriteLine("\r\n[*] endtime is ({0}) has passed, no renewal possible.\r\n", endTime);
                    return;
                }
                // get the window to sleep until the next endtime for the ticket, -30 minutes for a window
                double sleepMinutes = TimeSpan.FromTicks((endTime - DateTime.Now).Ticks).TotalMinutes - 30;
                Console.WriteLine("[*] Sleeping for {0} minutes (endTime-30) before the next renewal", (int)sleepMinutes);
                System.Threading.Thread.Sleep((int)sleepMinutes * 60 * 1000);
                Console.WriteLine("[*] Renewing TGT for {0}@{1}\r\n", userName, domain);
                currentKirbi = new KRB_CRED(TGT(currentKirbi, false, domainController, true));
            }
        }

        public static byte[] TGT(KRB_CRED kirbi, bool ptt = false, string domainController = "",
            bool display = true)
        {
            // extract out the info needed for the TGS-REQ/AP-REQ renewal
            string userName = kirbi.EncryptedPart.ticket_info[0].pname.name_string[0];
            string domain = kirbi.EncryptedPart.ticket_info[0].prealm;
            Ticket ticket = kirbi.Tickets[0];
            byte[] clientKey = kirbi.EncryptedPart.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)kirbi.EncryptedPart.ticket_info[0].key.keytype;
            // request the new TGT renewal
            return TGT(userName, domain, ticket, clientKey, etype, ptt, domainController, display);
        }

        public static byte[] TGT(string userName, string domain, Ticket providedTicket, byte[] clientKey,
            Interop.KERB_ETYPE etype, bool ptt, string domainController = "", bool display = true)
        {
            if (display) {
                Console.WriteLine("[*] Action: Renew TGT\r\n");
            }
            string dcIP = Networking.GetDCIP(domainController, display);
            if (string.IsNullOrEmpty(dcIP)) {
                return null;
            }
            if (display) {
                Console.WriteLine("[*] Building TGS-REQ renewal for: '{0}\\{1}'", domain, userName);
            }
            byte[] tgsBytes = TGS_REQ.NewTGSReq(userName, domain, "krbtgt", providedTicket, clientKey, etype, true);
            byte[] response = Networking.SendBytes(dcIP.ToString(), 88, tgsBytes);
            if (null == response) {
                return null;
            }
            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);
            // check the response value
            int responseTag = responseAsn.TagValue;
            switch (responseTag) {
                case 13:
                    Console.WriteLine("[+] TGT renewal request successful!");
                    // parse the response to an TGS-REP
                    TGS_REP rep = new TGS_REP(responseAsn);
                    // https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L62
                    EncKDCRepPart encRepPart = new EncKDCRepPart(
                        AsnElt.Decode(
                            Crypto.KerberosDecrypt(etype, 8, clientKey, rep.enc_part.cipher),
                            false)
                        .FirstElement);
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
                case 30:
                    Helpers.DisplayKerberosError(responseAsn);
                    return null;
                default:
                    Console.WriteLine("\r\n[X] Unknown application tag: {0}", responseTag);
                    return null;
            }
        }
    }
}