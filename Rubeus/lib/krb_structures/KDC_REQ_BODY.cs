using System;
using System.Text;
using System.Collections.Generic;

using Rubeus.Asn1;

namespace Rubeus
{
    public class KDCReqBody : IAsnEncodable
    {
        //KDC-REQ-BODY::= SEQUENCE {
        //    kdc-options[0] KDCOptions,
        //    cname[1] PrincipalName OPTIONAL
        //                                -- Used only in AS-REQ --,
        //    realm[2] Realm
        //                                -- Server's realm
        //                                -- Also client's in AS-REQ --,
        //    sname[3] PrincipalName OPTIONAL,
        //    from[4] KerberosTime OPTIONAL,
        //    till[5] KerberosTime,
        //    rtime[6] KerberosTime OPTIONAL,
        //    nonce[7] UInt32,
        //            etype[8] SEQUENCE OF Int32 -- EncryptionType
        //                                        -- in preference order --,
        //            addresses[9] HostAddresses OPTIONAL,
        //    enc-authorization-data[10] EncryptedData OPTIONAL
        //                                        -- AuthorizationData --,
        //            additional-tickets[11] SEQUENCE OF Ticket OPTIONAL
        //                                            -- NOTE: not empty
        //}

        public KDCReqBody()
        {
            // defaults for creation
            kdcOptions = Interop.KdcOptions.FORWARDABLE | Interop.KdcOptions.RENEWABLE | Interop.KdcOptions.RENEWABLEOK;
            cname = new PrincipalName();
            sname = new PrincipalName();
            // date time from kekeo ;) HAI 2037!
            till = DateTime.ParseExact("20370913024805Z", Constants.UTCTimeFormat, System.Globalization.CultureInfo.InvariantCulture);
            // kekeo/mimikatz nonce ;)
            //nonce = 12381973;
            nonce = 1818848256;
            additional_tickets = new List<Ticket>();
            etypes = new List<Interop.KERB_ETYPE>();
        }

        public KDCReqBody(AsnElt body)
        {
            foreach (AsnElt s in body.EnumerateElements()) {
                AsnElt firstElement = s.FirstElement;
                switch (s.TagValue) {
                    case 0:
                        UInt32 temp = Convert.ToUInt32(firstElement.GetInteger());
                        byte[] tempBytes = BitConverter.GetBytes(temp);
                        kdcOptions = (Interop.KdcOptions)BitConverter.ToInt32(tempBytes, 0);
                        break;
                    case 1:
                        // optional
                        cname = new PrincipalName(firstElement);
                        break;
                    case 2:
                        realm = Encoding.ASCII.GetString(firstElement.GetOctetString());
                        break;
                    case 3:
                        // optional
                        sname = new PrincipalName(firstElement);
                        break;
                    case 4:
                        // optional
                        from = firstElement.GetTime();
                        break;
                    case 5:
                        till = firstElement.GetTime();
                        break;
                    case 6:
                        // optional
                        rtime = firstElement.GetTime();
                        break;
                    case 7:
                        nonce = Convert.ToUInt32(firstElement.GetInteger());
                        break;
                    case 8:
                        //etypes = new Enums.KERB_ETYPE[s.Sub[0].Sub.Length];
                        etypes = new List<Interop.KERB_ETYPE>();
                        foreach(AsnElt item in firstElement.EnumerateElements()) {
                            //etypes[i] = (Enums.KERB_ETYPE)Convert.ToUInt32(item.GetInteger());
                            etypes.Add((Interop.KERB_ETYPE)Convert.ToUInt32(item.GetInteger()));
                        }
                        break;
                    case 9:
                        // addresses (optional)
                        break;
                    case 10:
                        // enc authorization-data (optional)
                        break;
                    case 11:
                        // additional-tickets (optional)
                        break;
                    default:
                        break;
                }
            }
        }

        public AsnElt Encode()
        {
            // TODO: error-checking!
            List<AsnElt> allNodes = new List<AsnElt>();

            // kdc-options [0] KDCOptions
            byte[] kdcOptionsBytes = BitConverter.GetBytes((UInt32)kdcOptions);
            if (BitConverter.IsLittleEndian) {
                Array.Reverse(kdcOptionsBytes);
            }
            allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                AsnElt.MakeSequence(
                    AsnElt.MakeBitString(kdcOptionsBytes))));
            // cname [1] PrincipalName
            if (null != cname) {
                allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                    cname.Encode()));
            }
            // realm [2] Realm
            // --Server's realm
            // -- Also client's in AS-REQ --
            allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 2,
                AsnElt.MakeSequence(
                    AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString,
                        AsnElt.MakeString(AsnElt.IA5String, realm)))));
            // sname [3] PrincipalName OPTIONAL
            allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 3,
                sname.Encode()));
            // from  [4] KerberosTime OPTIONAL
            // till  [5] KerberosTime
            allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 5,
                AsnElt.MakeSequence(
                    AsnElt.MakeString(AsnElt.GeneralizedTime, till.ToString(Constants.UTCTimeFormat)))));
            // rtime [6] KerberosTime
            // nonce [7] UInt32
            allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 7,
                AsnElt.MakeSequence(
                    AsnElt.MakeInteger(nonce))));
            // etype [8] SEQUENCE OF Int32 -- EncryptionType -- in preference order --
            List <AsnElt> etypeList = new List<AsnElt>();
            foreach (Interop.KERB_ETYPE etype in etypes) {
                etypeList.Add(AsnElt.MakeInteger((UInt32)etype));
            }
            allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 8,
                AsnElt.MakeSequence(
                    AsnElt.MakeSequence(etypeList.ToArray()))));
            // addresses [9] HostAddresses OPTIONAL
            // enc-authorization-data [10] EncryptedData OPTIONAL
            // additional-tickets [11] SEQUENCE OF Ticket OPTIONAL
            if (0 < additional_tickets.Count) {
                allNodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 11,
                    AsnElt.MakeSequence(
                        AsnElt.MakeSequence(
                            additional_tickets[0].Encode()))));
            }
            return AsnElt.MakeSequence(allNodes.ToArray());
        }

        public Interop.KdcOptions kdcOptions { get; set; }

        public PrincipalName cname { get; set; }

        public string realm { get; set; }

        public PrincipalName sname { get; set; }

        public DateTime from { get; set; }

        public DateTime till { get; set; }

        public DateTime rtime { get; set; }

        public UInt32 nonce { get; set; }

        public List<Interop.KERB_ETYPE> etypes { get; set; }

        public List<Ticket> additional_tickets { get; set; }
    }
}