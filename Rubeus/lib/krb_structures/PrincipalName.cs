using System.Collections.Generic;
using System.Text;

using Rubeus.Asn1;

namespace Rubeus
{
    //PrincipalName::= SEQUENCE {
    //        name-type[0] Int32,
    //        name-string[1] SEQUENCE OF KerberosString
    //}

    public class PrincipalName : IAsnEncodable
    {
        public PrincipalName()
        {
            // KRB_NT_PRINCIPAL = 1
            //      means just the name of the principal
            // KRB_NT_SRV_INST = 2
            //      service and other unique instance (krbtgt)
            // KRB_NT_ENTERPRISE_PRINCIPAL = 10
            //      user@domain.com

            name_type = 1;
            
            name_string = new List<string>();
        }

        public PrincipalName(string principal)
        {
            // create with principal
            name_type = 1;

            name_string = new List<string>();
            name_string.Add(principal);
        }

        public PrincipalName(AsnElt body)
        {
            // KRB_NT_PRINCIPAL = 1
            //      means just the name of the principal
            // KRB_NT_SRV_INST = 2
            //      service and other unique instance (krbtgt)

            name_type = body.FirstElement.FirstElement.GetInteger();
            name_string = new List<string>();
            foreach(AsnElt item in body.SecondElement.FirstElement.EnumerateElements()) {
                name_string.Add(Encoding.ASCII.GetString(item.GetOctetString()));
            }
        }

        public AsnElt Encode()
        {
            AsnElt[] strings = new AsnElt[name_string.Count];

            for (int i = 0; i < name_string.Count; ++i) {
                strings[i] = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString,
                    AsnElt.MakeString(AsnElt.IA5String, name_string[i]));
            }

            return AsnElt.MakeSequence(
                AsnElt.MakeSequence(
                    // name-type[0] Int32
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                        AsnElt.MakeSequence(
                            AsnElt.MakeInteger(name_type))),
                    // name-string[1] SEQUENCE OF KerberosString
                    //  add in the name string sequence (one or more)
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                        AsnElt.MakeSequence(
                            AsnElt.MakeSequence(strings)))));
        }

        public long name_type { get; set; }

        public List<string> name_string { get; set; }
    }
}