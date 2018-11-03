using System;
using Asn1;

namespace Rubeus
{
    public class Checksum
    {
        //Checksum        ::= SEQUENCE {
        //        cksumtype       [0] Int32,
        //        checksum        [1] OCTET STRING
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
            // cksumtype       [0] Int32
            AsnElt cksumtypeAsn = AsnElt.MakeInteger(cksumtype);
            AsnElt cksumtypeSeq = AsnElt.MakeSequence(new AsnElt[] { cksumtypeAsn });
            cksumtypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, cksumtypeSeq);

            // checksum        [1] OCTET STRING
            AsnElt checksumAsn = AsnElt.MakeBlob(checksum);
            AsnElt checksumSeq = AsnElt.MakeSequence(new AsnElt[] { checksumAsn });
            checksumSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, checksumSeq);

            AsnElt totalSeq = AsnElt.MakeSequence(new AsnElt[] { cksumtypeSeq, checksumSeq });
            AsnElt totalSeq2 = AsnElt.MakeSequence(new AsnElt[] { totalSeq });
            return totalSeq2;
        }

        public Int32 cksumtype { get; set; }

        public byte[] checksum { get; set; }
    }
}