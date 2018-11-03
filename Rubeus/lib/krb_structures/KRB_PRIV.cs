using System;
using Asn1;
using System.Collections.Generic;

namespace Rubeus
{
    public class KRB_PRIV
    {
        //KRB-PRIV        ::= [APPLICATION 21] SEQUENCE {
        //        pvno            [0] INTEGER (5),
        //        msg-type        [1] INTEGER (21),
        //                        -- NOTE: there is no [2] tag
        //        enc-part        [3] EncryptedData -- EncKrbPrivPart
        //}

        public KRB_PRIV(Interop.KERB_ETYPE encryptionType, byte[] encKey)
        {
            // defaults for creation
            pvno = 5;
            MessageType = 21;
            EncryptionType = encryptionType;
            EncryptionKey = encKey;
            enc_part = new EncKrbPrivPart();
        }

        internal byte[] EncryptionKey { get; private set; }

        internal EncKrbPrivPart enc_part { get; set; }

        internal Interop.KERB_ETYPE EncryptionType { get; private set; }

        internal long MessageType { get; private set; }

        internal long pvno { get; private set; }

        public AsnElt Encode()
        {
            // pvno            [0] INTEGER (5)
            AsnElt pvnoAsn = AsnElt.MakeInteger(pvno);
            AsnElt pvnoSeq = AsnElt.MakeSequence(new AsnElt[] { pvnoAsn });
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, pvnoSeq);

            // msg-type        [1] INTEGER (21)
            AsnElt msg_typeAsn = AsnElt.MakeInteger(MessageType);
            AsnElt msg_typeSeq = AsnElt.MakeSequence(new AsnElt[] { msg_typeAsn });
            msg_typeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, msg_typeSeq);

            // enc-part        [3] EncryptedData -- EncKrbPrivPart
            AsnElt enc_partAsn = enc_part.Encode();

            // etype
            AsnElt etypeAsn = AsnElt.MakeInteger((int)EncryptionType);
            AsnElt etypeSeq = AsnElt.MakeSequence(new AsnElt[] { etypeAsn });
            etypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, etypeSeq);

            // now encrypt the enc_part (EncKrbPrivPart)
            //  KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART = 13;
            byte[] encBytes = Crypto.KerberosEncrypt(EncryptionType, Interop.KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART, EncryptionKey, enc_partAsn.Encode());
            AsnElt blob = AsnElt.MakeBlob(encBytes);
            AsnElt blobSeq = AsnElt.MakeSequence(new AsnElt[] { blob });
            blobSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

            AsnElt encPrivSeq = AsnElt.MakeSequence(new AsnElt[] { etypeSeq, blobSeq });
            AsnElt encPrivSeq2 = AsnElt.MakeSequence(new AsnElt[] { encPrivSeq });
            encPrivSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, encPrivSeq2);

            // all the components
            AsnElt total = AsnElt.MakeSequence(new AsnElt[] { pvnoSeq, msg_typeSeq, encPrivSeq2 });

            // tag the final total ([APPLICATION 21])
            AsnElt final = AsnElt.MakeSequence(new AsnElt[] { total });
            return AsnElt.MakeImplicit(AsnElt.APPLICATION, 21, final);
        }
    }
}