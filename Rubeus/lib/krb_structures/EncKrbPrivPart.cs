using System;
using System.Text;

using Rubeus.Asn1;

namespace Rubeus
{
    //EncKrbPrivPart  ::= [APPLICATION 28] SEQUENCE {
    //        user-data       [0] OCTET STRING,
    //        timestamp       [1] KerberosTime OPTIONAL,
    //        usec            [2] Microseconds OPTIONAL,
    //        seq-number      [3] UInt32 OPTIONAL,
    //        s-address       [4] HostAddress -- sender's addr --,
    //        r-address       [5] HostAddress OPTIONAL -- recip's addr
    //}

    // NOTE: we only use:
    //  user-data       [0] OCTET STRING
    //  seq-number      [3] UInt32 OPTIONAL
    //  s-address       [4] HostAddress

    // only used by the changepw command

    public class EncKrbPrivPart : IAsnEncodable
    {
        public EncKrbPrivPart()
        {
            new_password = "";
            // mimikatz nonce ;
            seq_number = 1818848256;
            host_name = "";
        }

        public EncKrbPrivPart(string newPassword, string hostName)
        {
            new_password = newPassword;
            // mimikatz nonce ;
            seq_number = 1818848256;
            host_name = hostName;
        }

        public AsnElt Encode()
        {
            return AsnElt.MakeImplicit(AsnElt.APPLICATION, 28,
                AsnElt.MakeSequence(
                    // user-data [0] OCTET STRING
                    AsnElt.MakeSequence(
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                            AsnElt.MakeSequence(
                                AsnElt.MakeBlob(Encoding.ASCII.GetBytes(new_password)))),
                        // seq-number [3] UInt32 OPTIONAL
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 3,
                            AsnElt.MakeSequence(AsnElt.MakeInteger(seq_number))),
                        //  s-address [4] HostAddress
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 4,
                            AsnElt.MakeSequence(
                                AsnElt.MakeSequence(
                                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                                        AsnElt.MakeSequence(AsnElt.MakeInteger(20))),
                                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                                        AsnElt.MakeSequence(
                                            AsnElt.MakeBlob(Encoding.ASCII.GetBytes(host_name))))))))));
        }

        public string new_password { get; set; }

        public UInt32 seq_number { get; set; }

        public string host_name { get; set; }
    }
}