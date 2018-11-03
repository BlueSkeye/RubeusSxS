using System;
using Asn1;

namespace Rubeus
{
    public class PA_DATA
    {
        //PA-DATA         ::= SEQUENCE {
        //        -- NOTE: first tag is [1], not [0]
        //        padata-type     [1] Int32,
        //        padata-value    [2] OCTET STRING -- might be encoded AP-REQ
        //}

        public PA_DATA()
        {
            // defaults for creation
            type = Interop.PADATA_TYPE.PA_PAC_REQUEST;
            value = new KERB_PA_PAC_REQUEST();
        }

        public PA_DATA(bool claims, bool branch, bool fullDC, bool rbcd)
        {
            // defaults for creation
            type = Interop.PADATA_TYPE.PA_PAC_OPTIONS;
            value = new PA_PAC_OPTIONS(claims, branch, fullDC, rbcd);
        }

        public PA_DATA(string keyString, Interop.KERB_ETYPE etype)
        {
            // include pac, supply enc timestamp
            type = Interop.PADATA_TYPE.ENC_TIMESTAMP;
            PA_ENC_TS_ENC temp = new PA_ENC_TS_ENC();
            byte[] rawBytes = temp.Encode().Encode();
            byte[] key = Helpers.StringToByteArray(keyString);

            // KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP == 1
            // From https://github.com/gentilkiwi/kekeo/blob/master/modules/asn1/kull_m_kerberos_asn1.h#L55
            byte[] encBytes = Crypto.KerberosEncrypt(etype, Interop.KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, key, rawBytes);
            value = new EncryptedData((int)etype, encBytes);
        }

        public PA_DATA(byte[] key, string name, string realm)
        {
            // used for constrained delegation
            type = Interop.PADATA_TYPE.S4U2SELF;
            value = new PA_FOR_USER(key, name, realm);
        }

        public PA_DATA(string crealm, string cname, Ticket providedTicket, byte[] clientKey, Interop.KERB_ETYPE etype)
        {
            // include an AP-REQ, so PA-DATA for a TGS-REQ
            type = Interop.PADATA_TYPE.AP_REQ;
            // build the AP-REQ
            value = new AP_REQ(crealm, cname, providedTicket, clientKey, etype);
        }

        public PA_DATA(AsnElt body)
        {
            //if (body.Sub.Length != 2)
            //{
            //    throw new System.Exception("PA-DATA should contain two elements");
            //}

            //Console.WriteLine("tag: {0}", body.Sub[0].Sub[1].TagString);
            type = (Interop.PADATA_TYPE)body.FirstElement.FirstElement.GetInteger();
            byte[] valueBytes = body.SecondElement.FirstElement.GetOctetString();
            
            switch (type) {
                case Interop.PADATA_TYPE.PA_PAC_REQUEST:
                    value = new KERB_PA_PAC_REQUEST(AsnElt.Decode(body.SecondElement.FirstElement.CopyValue()));
                    break;
                case Interop.PADATA_TYPE.ENC_TIMESTAMP:
                    // TODO: parse PA-ENC-TIMESTAMP
                    break;
                case Interop.PADATA_TYPE.AP_REQ:
                    // TODO: parse AP_REQ
                    break;
                default:
                    break;
            }
        }

        public AsnElt Encode()
        {
            // padata-type     [1] Int32
            AsnElt typeElt = AsnElt.MakeInteger((long)type);
            AsnElt nameTypeSeq = AsnElt.MakeSequence(new AsnElt[] { typeElt });
            nameTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, nameTypeSeq);

            AsnElt paDataElt;
            AsnElt blob;
            AsnElt blobSeq;
            switch (type) {
                case Interop.PADATA_TYPE.PA_PAC_REQUEST:
                    // used for AS-REQs
                    // padata-value    [2] OCTET STRING -- might be encoded AP-REQ
                    paDataElt = ((KERB_PA_PAC_REQUEST)value).Encode();
                    paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, paDataElt);
                    break;
                case Interop.PADATA_TYPE.ENC_TIMESTAMP:
                    // used for AS-REQs
                    blob = AsnElt.MakeBlob(((EncryptedData)value).Encode().Encode());
                    blobSeq = AsnElt.MakeSequence(new AsnElt[] { blob });
                    paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);
                    break;
                case Interop.PADATA_TYPE.AP_REQ:
                    // used for TGS-REQs
                    //paDataElt = ((AP_REQ)value).Encode(); //needed?
                    blob = AsnElt.MakeBlob(((AP_REQ)value).Encode().Encode());
                    blobSeq = AsnElt.MakeSequence(new AsnElt[] { blob });
                    paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);
                    break;
                case Interop.PADATA_TYPE.S4U2SELF:
                    // used for constrained delegation
                    paDataElt = ((PA_FOR_USER)value).Encode();
                    blob = AsnElt.MakeBlob(((PA_FOR_USER)value).Encode().Encode());
                    blobSeq = AsnElt.MakeSequence(new AsnElt[] { blob });
                    paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);
                    break;
                case Interop.PADATA_TYPE.PA_PAC_OPTIONS:
                    paDataElt = ((PA_PAC_OPTIONS)value).Encode();
                    blob = AsnElt.MakeBlob(((PA_PAC_OPTIONS)value).Encode().Encode());
                    blobSeq = AsnElt.MakeSequence(new AsnElt[] { blob });
                    paDataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);
                    break;
                default:
                    return null;
            }
            return AsnElt.MakeSequence(new AsnElt[] { nameTypeSeq, paDataElt });
        }

        public Interop.PADATA_TYPE type { get; set; }

        public Object value { get; set; }
    }
}