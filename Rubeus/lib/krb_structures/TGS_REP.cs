using System.Text;

using Rubeus.Asn1;

namespace Rubeus
{
    public class TGS_REP
    {
        //TGS-REP         ::= [APPLICATION 13] KDC-REP

        //KDC-REP         ::= SEQUENCE {
        //        pvno            [0] INTEGER (5),
        //        msg-type        [1] INTEGER (13 -- TGS),
        //        padata          [2] SEQUENCE OF PA-DATA OPTIONAL
        //                                -- NOTE: not empty --,
        //        crealm          [3] Realm,
        //        cname           [4] PrincipalName,
        //        ticket          [5] Ticket,
        //        enc-part        [6] EncryptedData
        //                                -- EncTGSRepPart
        //}

        public TGS_REP(byte[] data)
        {
            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt asn_TGS_REP = AsnElt.Decode(data, false);

            this.Decode(asn_TGS_REP);
        }

        public TGS_REP(AsnElt asn_TGS_REP)
        {
            this.Decode(asn_TGS_REP);
        }

        private void Decode(AsnElt asn_TGS_REP)
        {
            // TGS - REP::= [APPLICATION 13] KDC - REP
            if (asn_TGS_REP.TagValue != 13)
            {
                throw new System.Exception("TGS-REP tag value should be 11");
            }

            if ((asn_TGS_REP.Count != 1) || (asn_TGS_REP.FirstElement.TagValue != 16))
            {
                throw new System.Exception("First TGS-REP sub should be a sequence");
            }

            // extract the KDC-REP out
            foreach (AsnElt s in asn_TGS_REP.FirstElement.EnumerateElements()) {
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
                        padata = new PA_DATA(firstElement);
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

        // won't really every need to *create* a TGS reply, so no encode

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public PA_DATA padata { get; set; }

        public string crealm { get; set; }

        public PrincipalName cname { get; set; }

        public Ticket ticket { get; set; }

        public EncryptedData enc_part { get; set; }
    }
}
