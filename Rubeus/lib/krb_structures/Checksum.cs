using System;

using Rubeus.Asn1;

namespace Rubeus
{
    public class Checksum : IAsnEncodable
    {
        //Checksum ::= SEQUENCE {
        // cksumtype       [0] Int32,
        // checksum        [1] OCTET STRING
        //}

        public Checksum(byte[] data)
        {
            // KERB_CHECKSUM_HMAC_MD5 = -138
            cksumtype = -138;
            checksum = data;
        }

        public Checksum(AsnElt body)
        {
            foreach (AsnElt s in body.EnumerateElements()) {
                AsnElt firstElement = s.FirstElement;
                switch (s.TagValue) {
                    case 0:
                        cksumtype = Convert.ToInt32(firstElement.GetInteger());
                        break;
                    case 2:
                        checksum = firstElement.GetOctetString();
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            return AsnElt.MakeSequence(
                AsnElt.MakeSequence(
                    // cksumtype [0] Int32
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                        AsnElt.MakeSequence(
                            AsnElt.MakeInteger(cksumtype))),
                    // checksum [1] OCTET STRING
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                        AsnElt.MakeSequence(
                            AsnElt.MakeBlob(checksum)))
                    ));
        }

        public Int32 cksumtype { get; set; }

        public byte[] checksum { get; set; }
    }
}