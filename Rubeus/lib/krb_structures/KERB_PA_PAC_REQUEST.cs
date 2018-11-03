using Asn1;
using System;
using System.Text;

namespace Rubeus
{
     //KERB-PA-PAC-REQUEST ::= SEQUENCE { 
     //    include-pac[0] BOOLEAN --If TRUE, and no pac present, include PAC.
     //                           --If FALSE, and PAC present, remove PAC
     //}

    public class KERB_PA_PAC_REQUEST
    {
        public KERB_PA_PAC_REQUEST()
        {
            // default -> include PAC
            include_pac = true;
        }

        public KERB_PA_PAC_REQUEST(AsnElt value)
        {
            include_pac = value.FirstElement.FirstElement.GetBoolean();
        }

        public AsnElt Encode()
        {
            AsnElt ret = AsnElt.MakeBlob(new byte[] { 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01,
                (include_pac) ? (byte)0x01 : (byte)0x00 });
            return AsnElt.MakeSequence(new AsnElt[] { ret });
        }
        
        public bool include_pac { get; set; }
    }
}