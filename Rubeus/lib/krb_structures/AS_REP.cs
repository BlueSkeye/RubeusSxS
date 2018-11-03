using Asn1;
using System;
using System.Text;

namespace Rubeus
{
    public class AS_REP
    {
        //AS-REP          ::= [APPLICATION 11] KDC-REP

        //KDC-REP         ::= SEQUENCE {
        //        pvno            [0] INTEGER (5),
        //        msg-type        [1] INTEGER (11 -- AS),
        //        padata          [2] SEQUENCE OF PA-DATA OPTIONAL
        //                                -- NOTE: not empty --,
        //        crealm          [3] Realm,
        //        cname           [4] PrincipalName,
        //        ticket          [5] Ticket,
        //        enc-part        [6] EncryptedData
        //                                -- EncASRepPart
        //}

        public AS_REP(byte[] data)
        {
            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt asn_AS_REP = AsnElt.Decode(data, false);

            this.Decode(asn_AS_REP);
        }

        public AS_REP(AsnElt asn_AS_REP)
        {
            this.Decode(asn_AS_REP);
        }

        private void Decode(AsnElt asn_AS_REP)
        {
            // AS-REP::= [APPLICATION 11] KDC-REQ
            if (asn_AS_REP.TagValue != 11) {
                throw new System.Exception("AS-REP tag value should be 11");
            }
            if ((asn_AS_REP.Count != 1) || (asn_AS_REP.FirstElement.TagValue != 16)) {
                throw new System.Exception("First AS-REP sub should be a sequence");
            }

            // extract the KDC-REP out
            foreach (AsnElt s in asn_AS_REP.FirstElement.EnumerateElements()) {
                AsnElt firstElement = s.FirstElement;
                switch (s.TagValue) {
                    case 0:
                        pvno = firstElement.GetInteger();
                        break;
                    case 1:
                        msg_type = firstElement.GetInteger();
                        break;
                    case 2:
                        // sequence of pa-data
                        //padata = new PA_DATA(firstElement);
                        break;
                    case 3:
                        crealm = Encoding.ASCII.GetString(firstElement.GetOctetString());
                        break;
                    case 4:
                        cname = new PrincipalName(firstElement);
                        break;
                    case 5:
                        ticket = new Ticket(firstElement.FirstElement);
                        break;
                    case 6:
                        enc_part = new EncryptedData(firstElement);
                        break;
                    default:
                        break;
                }
            }
        }

        // won't really every need to *create* a AS reply, so no encode

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public PA_DATA padata { get; set; }

        public string crealm { get; set; }

        public PrincipalName cname { get; set; }

        public Ticket ticket { get; set; }

        public EncryptedData enc_part { get; set; }
    }
}
