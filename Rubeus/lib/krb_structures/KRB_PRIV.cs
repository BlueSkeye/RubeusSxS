
using Rubeus.Asn1;

namespace Rubeus
{
    public class KRB_PRIV : IAsnEncodable
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
            // tag the final total ([APPLICATION 21])
            return AsnElt.MakeImplicit(AsnElt.APPLICATION, 21,
                AsnElt.MakeSequence(
                    AsnElt.MakeSequence(
                        // pvno [0] INTEGER (5)
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                            AsnElt.MakeSequence(AsnElt.MakeInteger(pvno))),
                        // msg-type [1] INTEGER (21)
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                            AsnElt.MakeSequence(AsnElt.MakeInteger(MessageType))),
                        // now encrypt the enc_part (EncKrbPrivPart)
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 3,
                            AsnElt.MakeSequence(
                                AsnElt.MakeSequence(
                                    // etype
                                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                                        AsnElt.MakeSequence(
                                            AsnElt.MakeInteger((int)EncryptionType))),
                                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 2,
                                        AsnElt.MakeSequence(
                                            //  KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART = 13;
                                            AsnElt.MakeBlob(
                                                Crypto.KerberosEncrypt(EncryptionType, Interop.KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART,
                                                    // enc-part [3] EncryptedData -- EncKrbPrivPart
                                                    EncryptionKey, enc_part.Encode().Encode()))))))))));
        }
    }
}