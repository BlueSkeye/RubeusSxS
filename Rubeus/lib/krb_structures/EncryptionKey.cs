using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace Rubeus
{
    public class EncryptionKey
    {
        //EncryptionKey::= SEQUENCE {
        //    keytype[0] Int32 -- actually encryption type --,
        //    keyvalue[1] OCTET STRING
        //}

        public EncryptionKey()
        {
            keytype = 0;
            keyvalue = null;
        }

        public EncryptionKey(AsnElt body)
        {
            foreach (AsnElt s in body.FirstElement.EnumerateElements()) {
                AsnElt firstElement = s.FirstElement;
                switch (s.TagValue) {
                    case 0:
                        keytype = Convert.ToInt32(firstElement.GetInteger());
                        break;
                    case 1:
                        keyvalue = firstElement.GetOctetString();
                        break;
                    case 2:
                        keyvalue = firstElement.GetOctetString();
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // keytype[0] Int32 -- actually encryption type --
            AsnElt keyTypeElt = AsnElt.MakeInteger(keytype);
            AsnElt keyTypeSeq = AsnElt.MakeSequence(new AsnElt[] { keyTypeElt });
            keyTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, keyTypeSeq);

            // keyvalue[1] OCTET STRING
            AsnElt blob = AsnElt.MakeBlob(keyvalue);
            AsnElt blobSeq = AsnElt.MakeSequence(new[] { blob });
            blobSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, blobSeq);

            // build the final sequences (s)
            AsnElt seq = AsnElt.MakeSequence(new[] { keyTypeSeq, blobSeq });
            return AsnElt.MakeSequence(new[] { seq });
        }

        public Int32 keytype { get; set; }

        public byte[] keyvalue { get; set; }
    }
}