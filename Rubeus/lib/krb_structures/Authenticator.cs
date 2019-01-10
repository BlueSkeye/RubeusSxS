using System;
using System.Collections.Generic;

using Rubeus.Asn1;

namespace Rubeus
{
    public class Authenticator : IAsnEncodable
    {
        //Authenticator   ::= [APPLICATION 2] SEQUENCE  {
        //        authenticator-vno       [0] INTEGER (5),
        //        crealm                  [1] Realm,
        //        cname                   [2] PrincipalName,
        //        cksum                   [3] Checksum OPTIONAL,
        //        cusec                   [4] Microseconds,
        //        ctime                   [5] KerberosTime,
        //        subkey                  [6] EncryptionKey OPTIONAL,
        //        seq-number              [7] UInt32 OPTIONAL,
        //        authorization-data      [8] AuthorizationData OPTIONAL
        //}

        // NOTE: we're only using:
        //  authenticator-vno   [0]
        //  crealm              [1]
        //  cname               [2]
        //  cusec               [4]
        //  ctime               [5]

        public Authenticator()
        {
            authenticator_vno = 5;
            crealm = "";
            cname = new PrincipalName();
            cusec = 0;
            ctime = DateTime.UtcNow;
            subkey = null;
            seq_number = 0;
        }

        public AsnElt Encode()
        {
            List<AsnElt> allNodes = new List<AsnElt>();

            // authenticator-vno [0] INTEGER (5)
            allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                AsnElt.MakeSequence(
                    AsnElt.MakeInteger(authenticator_vno))));
            // crealm [1] Realm
            allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                AsnElt.MakeSequence(
                    AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString,
                        AsnElt.MakeString(AsnElt.IA5String, crealm)))));
            // cname [2] PrincipalName
            allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 2,
                cname.Encode()));
            // TODO: correct format (UInt32)?
            // cusec [4] Microseconds
            allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 4,
                AsnElt.MakeSequence(
                    AsnElt.MakeInteger(cusec))));
            // ctime [5] KerberosTime
            allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 5,
                AsnElt.MakeSequence(
                    AsnElt.MakeString(AsnElt.GeneralizedTime, ctime.ToString(Constants.UTCTimeFormat)))));
            if (null != subkey) {
                // subkey [6] EncryptionKey OPTIONAL
                allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 6,
                    subkey.Encode()));
            }

            if (0 != seq_number) {
                // seq-number [7] UInt32 OPTIONAL
                allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 7,
                    AsnElt.MakeSequence(
                        AsnElt.MakeInteger(seq_number))));
            }
            // tag the final total
            return AsnElt.MakeImplicit(AsnElt.APPLICATION, 2,
                AsnElt.MakeSequence(
                    AsnElt.MakeSequence(allNodes.ToArray())));
        }

        public long authenticator_vno { get; set; }

        public string crealm { get; set; }

        public PrincipalName cname { get; set; }

        public long cusec { get; set; }

        public DateTime ctime { get; set; }

        public EncryptionKey subkey { get; set; }

        public UInt32 seq_number { get; set; }
    }
}