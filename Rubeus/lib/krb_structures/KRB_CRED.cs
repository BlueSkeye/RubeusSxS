using System;
using System.Collections.Generic;

using Rubeus.Asn1;

namespace Rubeus
{
    public class KRB_CRED : IAsnEncodable
    {
        //KRB-CRED::= [APPLICATION 22] SEQUENCE {
        //    pvno[0] INTEGER(5),
        //    msg-type[1] INTEGER(22),
        //    tickets[2] SEQUENCE OF Ticket,
        //    enc-part[3] EncryptedData -- EncKrbCredPart
        //}

        public KRB_CRED()
        {
            // defaults for creation
            pvno = 5;
            MessageType = 22;
            Tickets = new List<Ticket>();
            EncryptedPart = new EncKrbCredPart();
        }

        internal KRB_CRED(byte[] bytes)
        {
            this.Decode(AsnElt.Decode(bytes, false).FirstElement);
        }

        public KRB_CRED(AsnElt body)
        {
            this.Decode(body);
        }

        internal EncKrbCredPart EncryptedPart { get; private set; }

        internal long MessageType { get; private set; }

        internal long pvno { get; private set; }

        internal List<Ticket> Tickets { get; private set; }

        public void Decode(AsnElt body)
        {
            Tickets = new List<Ticket>();
            foreach (AsnElt s in body.EnumerateElements()) {
                AsnElt firstElement = s.FirstElement;
                switch (s.TagValue) {
                    case 0:
                        pvno = Convert.ToInt32(firstElement.GetInteger());
                        break;
                    case 1:
                        MessageType = Convert.ToInt32(firstElement.GetInteger());
                        break;
                    case 2:
                        foreach (AsnElt ae in firstElement.FirstElement.EnumerateElements()) {
                            Tickets.Add(new Ticket(ae));
                        }
                        break;
                    case 3:
                        EncryptedPart = new EncKrbCredPart(firstElement);
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // tag the final total ([APPLICATION 22])
            return AsnElt.MakeImplicit(AsnElt.APPLICATION, 22,
                AsnElt.MakeSequence(
                    AsnElt.MakeSequence(
                        // pvno [0] INTEGER (5)
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                            AsnElt.MakeSequence(AsnElt.MakeInteger(pvno))),
                        // msg-type [1] INTEGER (22)
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                            AsnElt.MakeSequence(AsnElt.MakeInteger(MessageType))),
                        // tickets [2] SEQUENCE OF Ticket
                        //  TODO: encode/handle multiple tickets!
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 2,
                            AsnElt.MakeSequence(AsnElt.MakeSequence(Tickets[0].Encode()))),
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 3,
                            AsnElt.MakeSequence(
                                AsnElt.MakeSequence(
                                    // etype == 0 -> no encryption
                                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                                        AsnElt.MakeSequence(AsnElt.MakeInteger(0))),
                                    // enc-part [3] EncryptedData -- EncKrbCredPart
                                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 2,
                                        AsnElt.MakeSequence(AsnElt.MakeBlob(EncryptedPart.Encode().Encode())))))))));
        }
    }
}