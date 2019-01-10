using System;

using Rubeus.Asn1;

namespace Rubeus
{
    public class EncryptedData : IAsnEncodable
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
            // etype [0] Int32 -- EncryptionType --,
            AsnElt etypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                AsnElt.MakeSequence(AsnElt.MakeInteger(etype)));

            // cipher [2] OCTET STRING -- ciphertext
            AsnElt cipherSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2,
                AsnElt.MakeSequence(AsnElt.MakeBlob(cipher)));

            if (0 != kvno) {
                // kvno [1] UInt32 OPTIONAL
                AsnElt kvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                    AsnElt.MakeSequence(AsnElt.MakeInteger(kvno)));

                return AsnElt.MakeSequence(etypeSeq, kvnoSeq, cipherSeq);
            }
            else {
                return AsnElt.MakeSequence(etypeSeq, cipherSeq);
            }
        }

        public Int32 etype { get; set; }

        public UInt32 kvno { get; set; }

        public byte[] cipher { get; set; }
    }
}