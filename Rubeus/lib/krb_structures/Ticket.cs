using System;
using System.Text;

using Rubeus.Asn1;

namespace Rubeus
{
    public class Ticket : IAsnEncodable
    {
        //Ticket::= [APPLICATION 1] SEQUENCE {
        //        tkt-vno[0] INTEGER(5),
        //        realm[1] Realm,
        //        sname[2] PrincipalName,
        //        enc-part[3] EncryptedData -- EncTicketPart
        //}

        public Ticket(AsnElt body)
        {
            foreach (AsnElt s in body.EnumerateElements()) {
                AsnElt firstItem = s.FirstElement;
                switch (s.TagValue) {
                    case 0:
                        tkt_vno = Convert.ToInt32(firstItem.GetInteger());
                        break;
                    case 1:
                        realm = Encoding.ASCII.GetString(firstItem.GetOctetString());
                        break;
                    case 2:
                        sname = new PrincipalName(firstItem);
                        break;
                    case 3:
                        enc_part = new EncryptedData(firstItem);
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            return AsnElt.MakeImplicit(AsnElt.APPLICATION, 1,
                AsnElt.MakeSequence(
                    AsnElt.MakeSequence(
                        // tkt-vno [0] INTEGER (5)
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                            AsnElt.MakeSequence(
                                AsnElt.MakeInteger(tkt_vno))),
                        // realm [1] Realm
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                            AsnElt.MakeSequence(
                                AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString,
                                    AsnElt.MakeString(AsnElt.IA5String, realm)))),
                        // sname [2] PrincipalName
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 2,
                            sname.Encode()),
                        // enc-part [3] EncryptedData -- EncTicketPart
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 3,
                            AsnElt.MakeSequence(
                                enc_part.Encode()))
                        )));
        }

        public int tkt_vno { get; set; }

        public string realm { get; set; }

        public PrincipalName sname { get; set; }

        public EncryptedData enc_part { get; set; }
    }
}