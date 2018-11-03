using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace Rubeus
{
    public class KDCReqBody
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

            // kdc-options             [0] KDCOptions
            byte[] kdcOptionsBytes = BitConverter.GetBytes((UInt32)kdcOptions);
            if (BitConverter.IsLittleEndian) {
                Array.Reverse(kdcOptionsBytes);
            }
            AsnElt kdcOptionsAsn = AsnElt.MakeBitString(kdcOptionsBytes);
            AsnElt kdcOptionsSeq = AsnElt.MakeSequence(new[] { kdcOptionsAsn });
            kdcOptionsSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, kdcOptionsSeq);
            allNodes.Add(kdcOptionsSeq);

            // cname                   [1] PrincipalName
            if (cname != null) {
                AsnElt cnameElt = cname.Encode();
                cnameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, cnameElt);
                allNodes.Add(cnameElt);
            }

            // realm                   [2] Realm
            //                          --Server's realm
            //                          -- Also client's in AS-REQ --
            AsnElt realmAsn = AsnElt.MakeString(AsnElt.IA5String, realm);
            realmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, realmAsn);
            AsnElt realmSeq = AsnElt.MakeSequence(new[] { realmAsn });
            realmSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, realmSeq);
            allNodes.Add(realmSeq);

            // sname                   [3] PrincipalName OPTIONAL
            AsnElt snameElt = sname.Encode();
            snameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, snameElt);
            allNodes.Add(snameElt);

            // from                    [4] KerberosTime OPTIONAL

            // till                    [5] KerberosTime
            AsnElt tillAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, till.ToString(Constants.UTCTimeFormat));
            AsnElt tillSeq = AsnElt.MakeSequence(new[] { tillAsn });
            tillSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 5, tillSeq);
            allNodes.Add(tillSeq);

            // rtime                   [6] KerberosTime

            // nonce                   [7] UInt32
            AsnElt nonceAsn = AsnElt.MakeInteger(nonce);
            AsnElt nonceSeq = AsnElt.MakeSequence(new[] { nonceAsn });
            nonceSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 7, nonceSeq);
            allNodes.Add(nonceSeq);

            // etype                   [8] SEQUENCE OF Int32 -- EncryptionType -- in preference order --
            List <AsnElt> etypeList = new List<AsnElt>();
            foreach (Interop.KERB_ETYPE etype in etypes) {
                AsnElt etypeAsn = AsnElt.MakeInteger((UInt32)etype);
                //AsnElt etypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { etypeAsn });
                etypeList.Add(etypeAsn);
            }
            AsnElt etypeSeq = AsnElt.MakeSequence(etypeList.ToArray());
            AsnElt etypeSeqTotal1 = AsnElt.MakeSequence(etypeList.ToArray());
            AsnElt etypeSeqTotal2 = AsnElt.MakeSequence(etypeSeqTotal1);
            etypeSeqTotal2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 8, etypeSeqTotal2);
            allNodes.Add(etypeSeqTotal2);

            // addresses               [9] HostAddresses OPTIONAL

            // enc-authorization-data  [10] EncryptedData OPTIONAL

            // additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
            if(additional_tickets.Count > 0) {
                AsnElt ticketAsn = additional_tickets[0].Encode();
                AsnElt ticketSeq = AsnElt.MakeSequence(new AsnElt[] { ticketAsn });
                AsnElt ticketSeq2 = AsnElt.MakeSequence(new AsnElt[] { ticketSeq });
                ticketSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 11, ticketSeq2);
                allNodes.Add(ticketSeq2);
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