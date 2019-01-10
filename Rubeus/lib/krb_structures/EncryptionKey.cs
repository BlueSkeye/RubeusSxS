using System;

using Rubeus.Asn1;

namespace Rubeus
{
    public class EncryptionKey : IAsnEncodable
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
                        keytype = (Rubeus.Interop.KERB_ETYPE)Convert.ToInt32(firstElement.GetInteger());
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
            // build the final sequences (s)
            return AsnElt.MakeSequence(
                AsnElt.MakeSequence(
                    // keytype[0] Int32 -- actually encryption type --
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                        AsnElt.MakeSequence(
                            AsnElt.MakeInteger((long)keytype))),
                    // keyvalue[1] OCTET STRING
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                        AsnElt.MakeSequence(
                            AsnElt.MakeBlob(keyvalue)))));
        }

        internal Rubeus.Interop.KERB_ETYPE keytype { get; set; }

        public byte[] keyvalue { get; set; }
    }
}