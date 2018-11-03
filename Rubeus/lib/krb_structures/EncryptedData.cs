using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace Rubeus
{
    public class EncryptedData
    {
        //EncryptedData::= SEQUENCE {
        //    etype[0] Int32 -- EncryptionType --,
        //    kvno[1] UInt32 OPTIONAL,
        //    cipher[2] OCTET STRING -- ciphertext
        //}

        public EncryptedData()
        {
        }

        public EncryptedData(Int32 encType, byte[] data)
        {
            etype = encType;
            cipher = data;
        }

        public EncryptedData(AsnElt body)
        {
            foreach (AsnElt s in body.EnumerateElements()) {
                AsnElt firstElement = s.FirstElement;
                switch (s.TagValue) {
                    case 0:
                        etype = Convert.ToInt32(firstElement.GetInteger());
                        break;
                    case 1:
                        kvno = Convert.ToUInt32(firstElement.GetInteger());
                        break;
                    case 2:
                        cipher = firstElement.GetOctetString();
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // etype   [0] Int32 -- EncryptionType --,
            AsnElt etypeAsn = AsnElt.MakeInteger(etype);
            AsnElt etypeSeq = AsnElt.MakeSequence(new AsnElt[] { etypeAsn });
            etypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, etypeSeq);

            // cipher  [2] OCTET STRING -- ciphertext
            AsnElt cipherAsn = AsnElt.MakeBlob(cipher);
            AsnElt cipherSeq = AsnElt.MakeSequence(new AsnElt[] { cipherAsn });
            cipherSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, cipherSeq);

            if (kvno != 0) {
                // kvno    [1] UInt32 OPTIONAL
                AsnElt kvnoAsn = AsnElt.MakeInteger(kvno);
                AsnElt kvnoSeq = AsnElt.MakeSequence(new AsnElt[] { kvnoAsn });
                kvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, kvnoSeq);

                return AsnElt.MakeSequence(new AsnElt[] { etypeSeq, kvnoSeq, cipherSeq });
            }
            else {
                return AsnElt.MakeSequence(new AsnElt[] { etypeSeq, cipherSeq });
            }
        }

        public Int32 etype { get; set; }

        public UInt32 kvno { get; set; }

        public byte[] cipher { get; set; }
    }
}