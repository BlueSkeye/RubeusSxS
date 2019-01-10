using System;

using Rubeus.Asn1;

namespace Rubeus
{
    //PA-ENC-TS-ENC   ::= SEQUENCE {
    //        patimestamp[0]               KerberosTime, -- client's time
    //        pausec[1]                    INTEGER OPTIONAL
    //}

    public class PA_ENC_TS_ENC : IAsnEncodable
    {
        public PA_ENC_TS_ENC()
        {
            patimestamp = DateTime.UtcNow;
        }

        public PA_ENC_TS_ENC(DateTime time)
        {
            patimestamp = time;
        }

        //public PA_ENC_TS_ENC(AsnElt value)
        //{
        //}

        public AsnElt Encode()
        {
            return AsnElt.MakeSequence(
                AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                    AsnElt.MakeSequence(AsnElt.MakeString(AsnElt.GeneralizedTime, patimestamp.ToString(Constants.UTCTimeFormat)))));
        }

        public DateTime patimestamp { get; set; }

        public int pausec { get; set; }

        //public bool include_pac { get; set; }
    }
}