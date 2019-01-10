using System.Collections.Generic;

using Rubeus.Asn1;

namespace Rubeus
{
    //EncKrbCredPart  ::= [APPLICATION 29] SEQUENCE {
    //        ticket-info     [0] SEQUENCE OF KrbCredInfo,
    //        nonce           [1] UInt32 OPTIONAL,
    //        timestamp       [2] KerberosTime OPTIONAL,
    //        usec            [3] Microseconds OPTIONAL,
    //        s-address       [4] HostAddress OPTIONAL,
    //        r-address       [5] HostAddress OPTIONAL
    //}

    internal class EncKrbCredPart : IAsnEncodable
    {
        public EncKrbCredPart()
        {
            // TODO: defaults for creation
            ticket_info = new List<KrbCredInfo>();
        }

        public EncKrbCredPart(AsnElt body)
            : this()
        {
            AsnElt body2 = AsnElt.Decode(body.SecondElement.FirstElement.GetOctetString(), false);

            // assume only one KrbCredInfo for now
            ticket_info.Add(
                new KrbCredInfo(body2.FirstElement.FirstElement.FirstElement.FirstElement));
        }

        public AsnElt Encode()
        {
            // ticket-info     [0] SEQUENCE OF KrbCredInfo
            // assume just one ticket-info for now
            // TODO: handle multiple ticket-infos
            return AsnElt.MakeImplicit(AsnElt.APPLICATION, 29,
                AsnElt.MakeSequence(
                    AsnElt.MakeSequence(
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                            AsnElt.MakeSequence(
                                AsnElt.MakeSequence(ticket_info[0].Encode()))))));
        }

        public List<KrbCredInfo> ticket_info { get; set; }

        // other fields are optional/not used in our use cases
    }
}