using System;

using Rubeus.Asn1;

namespace Rubeus
{
    //AP-REQ          ::= [APPLICATION 14] SEQUENCE {
    //        pvno            [0] INTEGER (5),
    //        msg-type        [1] INTEGER (14),
    //        ap-options      [2] APOptions,
    //        ticket          [3] Ticket,
    //        authenticator   [4] EncryptedData -- Authenticator
    //}
    
    public class AP_REQ : IAsnEncodable
    {
        public AP_REQ(string crealm, string cname, Ticket providedTicket, byte[] clientKey,
            Interop.KERB_ETYPE etype, int keyUsageSpec = Interop.KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR)
        {
            pvno = 5;
            msg_type = 14;
            ap_options = 0;
            ticket = providedTicket;

            // KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR   = 7
            // KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR       = 11
            keyUsage = keyUsageSpec;

            enctype = etype;
            key = clientKey;

            authenticator = new Authenticator();
            authenticator.crealm = crealm;
            authenticator.cname = new PrincipalName(cname);
        }

        public AsnElt Encode()
        {
            // authenticator [4] EncryptedData 
            if (null == key) {
                Console.WriteLine("  [X] A key for the authenticator is needed to build an AP-REQ");
                return null;
            }
            // create the EncryptedData structure to hold the authenticator bytes
            EncryptedData authenticatorEncryptedData = new EncryptedData() {
                etype = (int)enctype,
                cipher = Crypto.KerberosEncrypt(enctype, keyUsage, key,
                    authenticator.Encode().Encode())
            };
            // AP-REQ ::= [APPLICATION 14]
            // put it all together and tag it with 14
            return AsnElt.MakeImplicit(AsnElt.APPLICATION, 14,
                AsnElt.MakeSequence(
                    AsnElt.MakeSequence(
                        // pvno [0] INTEGER (5)
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                            AsnElt.MakeSequence(AsnElt.MakeInteger(pvno))),
                        // msg-type [1] INTEGER (14)
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                            AsnElt.MakeSequence(AsnElt.MakeInteger(msg_type))),
                        // ap-options [2] APOptions
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 2,
                            AsnElt.MakeSequence(AsnElt.MakeBitString(BitConverter.GetBytes(ap_options)))),
                        // ticket [3] Ticket
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 3,
                            AsnElt.MakeSequence(ticket.Encode())),
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 4,
                            AsnElt.MakeSequence(authenticatorEncryptedData.Encode()))
                )));
        }

        public long pvno { get; set;}

        public long msg_type { get; set; }

        public UInt32 ap_options { get; set; }

        public Ticket ticket { get; set; }

        public Authenticator authenticator { get; set; }

        public byte[] key { get; set; }

        private Interop.KERB_ETYPE enctype;

        private int keyUsage;
    }
}