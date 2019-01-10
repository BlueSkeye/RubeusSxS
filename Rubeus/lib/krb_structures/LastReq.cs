using System;

using Rubeus.Asn1;

namespace Rubeus
{
    public class LastReq
    {
        //LastReq::=     SEQUENCE OF SEQUENCE {
        //        lr-type[0] Int32,
        //        lr-value[1] KerberosTime
        //}

        public LastReq(AsnElt body)
        {
            foreach (AsnElt s in body.FirstElement.EnumerateElements()) {
                AsnElt firstElement = s.FirstElement;
                switch (s.TagValue) {
                    case 0:
                        lr_type = Convert.ToInt32(firstElement.GetInteger());
                        break;
                    case 1:
                        lr_value = firstElement.GetTime();
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // TODO: implement
            return null;
        }

        public Int32 lr_type { get; set; }

        public DateTime lr_value { get; set; }
    }
}