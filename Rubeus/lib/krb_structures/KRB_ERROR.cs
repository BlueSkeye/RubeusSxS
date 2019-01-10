using System;
using System.Collections.Generic;
using System.Text;

using Rubeus.Asn1;

namespace Rubeus
{
    public class KRB_ERROR
    {
        //KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
        //        pvno            [0] INTEGER (5),
        //        msg-type        [1] INTEGER (30),
        //        ctime           [2] KerberosTime OPTIONAL,
        //        cusec           [3] Microseconds OPTIONAL,
        //        stime           [4] KerberosTime,
        //        susec           [5] Microseconds,
        //        error-code      [6] Int32,
        //        crealm          [7] Realm OPTIONAL,
        //        cname           [8] PrincipalName OPTIONAL,
        //        realm           [9] Realm -- service realm --,
        //        sname           [10] PrincipalName -- service name --,
        //        e-text          [11] KerberosString OPTIONAL,
        //        e-data          [12] OCTET STRING OPTIONAL
        //}

        public KRB_ERROR(byte[] errorBytes)
        {
        }

        public KRB_ERROR(AsnElt body)
        {
            foreach (AsnElt s in body.EnumerateElements()) {
                AsnElt firstElement = s.FirstElement;
                switch (s.TagValue) {
                    case 0:
                        pvno = Convert.ToUInt32(firstElement.GetInteger());
                        break;
                    case 1:
                        msg_type = Convert.ToUInt32(firstElement.GetInteger());
                        break;
                    case 2:
                        ctime = firstElement.GetTime();
                        break;
                    case 3:
                        cusec = Convert.ToUInt32(firstElement.GetInteger());
                        break;
                    case 4:
                        stime = firstElement.GetTime();
                        break;
                    case 5:
                        susec = Convert.ToUInt32(firstElement.GetInteger());
                        break;
                    case 6:
                        ErrorCode = Convert.ToUInt32(firstElement.GetInteger());
                        break;
                    case 7:
                        crealm = Encoding.ASCII.GetString(firstElement.GetOctetString());
                        break;
                    case 8:
                        cname = new PrincipalName(firstElement);
                        break;
                    case 9:
                        realm = Encoding.ASCII.GetString(firstElement.GetOctetString());
                        break;
                    case 10:
                        sname = new PrincipalName(firstElement);
                        break;
                    default:
                        break;
                }
            }
        }

        // don't ever really need to create a KRB_ERROR structure manually, so no Encode()
        public long pvno { get; set; }

        public long msg_type { get; set; }

        public DateTime ctime { get; set; }

        public long cusec { get; set; }

        public DateTime stime { get; set; }

        public long susec { get; set; }

        internal long ErrorCode { get; private set; }

        public string crealm { get; set; }

        public PrincipalName cname { get; set; }

        public string realm { get; set; }

        public PrincipalName sname { get; set; }

        // skipping these two for now
        // e_text
        // e_data

        public List<Ticket> tickets { get; set; }

        internal EncKrbCredPart enc_part { get; private set; }
    }
}