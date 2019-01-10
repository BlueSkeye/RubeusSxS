using System;
using System.Text;
using System.Collections.Generic;

using Rubeus.Asn1;

namespace Rubeus
{
    public class KrbCredInfo : IAsnEncodable
    {
        //KrbCredInfo     ::= SEQUENCE {
        //        key             [0] EncryptionKey,
        //        prealm          [1] Realm OPTIONAL,
        //        pname           [2] PrincipalName OPTIONAL,
        //        flags           [3] TicketFlags OPTIONAL,
        //        authtime        [4] KerberosTime OPTIONAL,
        //        starttime       [5] KerberosTime OPTIONAL,
        //        endtime         [6] KerberosTime OPTIONAL,
        //        renew-till      [7] KerberosTime OPTIONAL,
        //        srealm          [8] Realm OPTIONAL,
        //        sname           [9] PrincipalName OPTIONAL,
        //        caddr           [10] HostAddresses OPTIONAL
        //}

        public KrbCredInfo()
        {
            key = new EncryptionKey();
            prealm = string.Empty;
            pname = new PrincipalName();
            flags = 0;
            srealm = string.Empty;
            sname = new PrincipalName();
        }

        public KrbCredInfo(AsnElt body)
        {
            foreach (AsnElt s in body.EnumerateElements()) {
                AsnElt firstElement = s.FirstElement;
                switch (s.TagValue) {
                    case 0:
                        key = new EncryptionKey(s);
                        break;
                    case 1:
                        prealm = Encoding.ASCII.GetString(firstElement.GetOctetString());
                        break;
                    case 2:
                        pname = new PrincipalName(firstElement);
                        break;
                    case 3:
                        UInt32 temp = Convert.ToUInt32(firstElement.GetInteger());
                        byte[] tempBytes = BitConverter.GetBytes(temp);
                        flags = (Interop.TicketFlags)BitConverter.ToInt32(tempBytes, 0);
                        break;
                    case 4:
                        authtime = firstElement.GetTime();
                        break;
                    case 5:
                        starttime = firstElement.GetTime();
                        break;
                    case 6:
                        endtime = firstElement.GetTime();
                        break;
                    case 7:
                        renew_till = firstElement.GetTime();
                        break;
                    case 8:
                        srealm = Encoding.ASCII.GetString(firstElement.GetOctetString());
                        break;
                    case 9:
                        sname = new PrincipalName(firstElement);
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            List<AsnElt> asnElements = new List<AsnElt>();

            // key [0] EncryptionKey
            asnElements.Add(
                AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                    key.Encode()));

            // prealm [1] Realm OPTIONAL
            if (!String.IsNullOrEmpty(prealm)) {
                asnElements.Add(
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                        AsnElt.MakeSequence(
                            AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString,
                                AsnElt.MakeString(AsnElt.IA5String, prealm)))));
            }

            // pname           [2] PrincipalName OPTIONAL
            if ((pname.name_string != null) && (pname.name_string.Count != 0) && (!String.IsNullOrEmpty(pname.name_string[0]))) {
                asnElements.Add(
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, pname.Encode()));
            }

            // pname           [2] PrincipalName OPTIONAL
            byte[] flagBytes = BitConverter.GetBytes((UInt32)flags);
            if (BitConverter.IsLittleEndian) {
                Array.Reverse(flagBytes);
            }
            asnElements.Add(
                AsnElt.MakeImplicit(AsnElt.CONTEXT, 3,
                    AsnElt.MakeSequence(
                        AsnElt.MakeBitString(flagBytes))));

            // authtime [4] KerberosTime OPTIONAL
            if ((authtime != null) && (authtime != DateTime.MinValue)) {
                asnElements.Add(
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 4,
                        AsnElt.MakeSequence(
                            AsnElt.MakeString(AsnElt.GeneralizedTime, authtime.ToString(Constants.UTCTimeFormat)))));
            }

            // starttime [5] KerberosTime OPTIONAL
            if ((starttime != null) && (starttime != DateTime.MinValue)) {
                asnElements.Add(
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 5,
                        AsnElt.MakeSequence(
                            AsnElt.MakeString(AsnElt.GeneralizedTime, starttime.ToString(Constants.UTCTimeFormat)))));
            }

            // endtime         [6] KerberosTime OPTIONAL
            if ((endtime != null) && (endtime != DateTime.MinValue)) {
                asnElements.Add(
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 6,
                        AsnElt.MakeSequence(
                            AsnElt.MakeString(AsnElt.GeneralizedTime, endtime.ToString(Constants.UTCTimeFormat)))));
            }

            // renew-till [7] KerberosTime OPTIONAL
            if ((renew_till != null) && (renew_till != DateTime.MinValue)) {
                asnElements.Add(
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 7,
                        AsnElt.MakeSequence(
                            AsnElt.MakeString(AsnElt.GeneralizedTime, renew_till.ToString(Constants.UTCTimeFormat)))));
            }

            // srealm [8] Realm OPTIONAL
            if (!String.IsNullOrEmpty(srealm)) {
                asnElements.Add(
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 8,
                        AsnElt.MakeSequence(
                            AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString,
                                AsnElt.MakeString(AsnElt.IA5String, srealm)))));
            }

            // sname [9] PrincipalName OPTIONAL
            if ((sname.name_string != null) && (sname.name_string.Count != 0) && (!String.IsNullOrEmpty(sname.name_string[0]))) {
                asnElements.Add(
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 9, sname.Encode()));
            }
            // caddr [10] HostAddresses OPTIONAL

            return AsnElt.MakeSequence(asnElements.ToArray());
        }

        public EncryptionKey key { get; set; }

        public string prealm { get; set; }

        public PrincipalName pname { get; set; }

        public Interop.TicketFlags flags { get; set; }

        public DateTime authtime { get; set; }

        public DateTime starttime { get; set; }

        public DateTime endtime { get; set; }

        public DateTime renew_till { get; set; }

        public string srealm { get; set; }

        public PrincipalName sname { get; set; }

        // caddr (optional) - skipping for now
    }
}