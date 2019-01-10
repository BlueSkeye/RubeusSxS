using System;
using System.Collections.Generic;

using Rubeus.Asn1;

namespace Rubeus
{
    //TGS-REQ         ::= [APPLICATION 12] KDC-REQ

    //KDC-REQ         ::= SEQUENCE {
    //    -- NOTE: first tag is [1], not [0]
    //    pvno            [1] INTEGER (5) ,
    //    msg-type        [2] INTEGER (12 -- TGS),
    //    padata          [3] SEQUENCE OF PA-DATA OPTIONAL
    //                        -- NOTE: not empty --,
    //                          in this case, it's an AP-REQ
    //    req-body        [4] KDC-REQ-BODY
    //}
    public class TGS_REQ : IAsnEncodable
    {
        public static byte[] NewTGSReq(string userName, string domain, string sname, Ticket providedTicket,
            byte[] clientKey, Interop.KERB_ETYPE etype, bool renew, string s4uUser = "")
        {
            TGS_REQ req = new TGS_REQ();

            // create the PA-DATA that contains the AP-REQ w/ appropriate authenticator/etc.
            PA_DATA padata = new PA_DATA(domain, userName, providedTicket, clientKey, etype);
            req.padata.Add(padata);

            // set the username
            req.req_body.cname.name_string.Add(userName);

            // the realm (domain) the user exists in
            req.req_body.realm = domain;

            // add in our encryption types
            req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
            req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
            req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);

            if (!String.IsNullOrEmpty(s4uUser)) {
                // constrained delegation yo'
                PA_DATA s4upadata = new PA_DATA(clientKey, String.Format("{0}@{1}", s4uUser, domain), domain);
                req.padata.Add(s4upadata);

                req.req_body.sname.name_type = 1;
                req.req_body.sname.name_string.Add(userName);

                req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.ENCTKTINSKEY;

                //req.req_body.etypes.Add(Interop.KERB_ETYPE.aes128_cts_hmac_sha1);
                //req.req_body.etypes.Add(Interop.KERB_ETYPE.aes256_cts_hmac_sha1);
                //req.req_body.etypes.Add(Interop.KERB_ETYPE.rc4_hmac);
            }
            else {
                //// add in our encryption type
                //req.req_body.etypes.Add(etype);
                string[] parts = sname.Split('/');
                PrincipalName principalName;
                switch (parts.Length) {
                    case 1:
                        principalName = req.req_body.sname;
                        // KRB_NT_SRV_INST = 2
                        //      service and other unique instance (e.g. krbtgt)
                        principalName.name_type = 2;
                        principalName.name_string.Add(sname);
                        principalName.name_string.Add(domain);
                        break;
                    case 2:
                        principalName = req.req_body.sname;
                        // KRB_NT_SRV_INST = 2
                        //      SPN (sname/server.domain.com)
                        principalName.name_type = 2;
                        principalName.name_string.Add(parts[0]);
                        principalName.name_string.Add(parts[1]);
                        break;
                    default:
                        Console.WriteLine("[X] Error: invalid TGS_REQ sname '{0}'", sname);
                        break;
                }
                if (renew) {
                    req.req_body.kdcOptions = req.req_body.kdcOptions | Interop.KdcOptions.RENEW;
                }
            }
            return req.Encode().Encode();
        }

        public static byte[] NewTGSReq(byte[] kirbi)
        {
            // take a supplied .kirbi TGT cred and build a TGS_REQ
            return null;
        }


        public TGS_REQ()
        {
            // default, for creation
            pvno = 5;
            // msg-type [2] INTEGER (12 -- TGS)
            msg_type = 12;
            padata = new List<PA_DATA>();
            req_body = new KDCReqBody();
        }

        public AsnElt Encode()
        {
            List<AsnElt> padatas = new List<AsnElt>();
            foreach (PA_DATA pa in padata) {
                padatas.Add(pa.Encode());
            }
            // TGS-REQ         ::= [APPLICATION 12] KDC-REQ
            //  put it all together and tag it with 10
            return AsnElt.MakeImplicit(AsnElt.APPLICATION, 12,
                AsnElt.MakeSequence(
                    AsnElt.MakeSequence(
                       // pvno [1] INTEGER (5)
                       AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                            AsnElt.MakeSequence(
                                AsnElt.MakeInteger(pvno))),
                        // msg-type [2] INTEGER (12 -- TGS -- )
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 2,
                            AsnElt.MakeSequence(AsnElt.MakeInteger(msg_type))),
                        // padata [3] SEQUENCE OF PA-DATA OPTIONAL
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 3,
                            AsnElt.MakeSequence(AsnElt.MakeSequence(padatas.ToArray()))),
                        // req-body [4] KDC-REQ-BODY
                        AsnElt.MakeImplicit(AsnElt.CONTEXT, 4,
                            AsnElt.MakeSequence(req_body.Encode()))
                )));
        }

        public long pvno { get; set; }

        public long msg_type { get; set; }

        public List<PA_DATA> padata { get; set; }

        public KDCReqBody req_body { get; set; }
    }
}