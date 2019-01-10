using System;
using System.Collections.Generic;
using System.Text;

using Rubeus.Asn1;

namespace Rubeus
{
    //PA-FOR-USER-ENC ::= SEQUENCE {
	   // userName[0] PrincipalName,
	   // userRealm[1] Realm,
	   // cksum[2] Checksum,
	   // auth-package[3] KerberosString
    //}

    public class PA_FOR_USER : IAsnEncodable
    {
        public PA_FOR_USER(byte[] key, string name, string realm)
        {
            userName = new PrincipalName(name);
            userName.name_type = 10;
            userRealm = realm.ToUpper();

            // now build the checksum

            auth_package = "Kerberos";

            byte[] nameTypeBytes = new byte[4];
            nameTypeBytes[0] = 0xa;

            byte[] nameBytes = Encoding.UTF8.GetBytes(name);
            byte[] realmBytes = Encoding.UTF8.GetBytes(userRealm);
            byte[] authPackageBytes = Encoding.UTF8.GetBytes(auth_package);

            byte[] finalBytes = new byte[nameTypeBytes.Length + nameBytes.Length + realmBytes.Length + authPackageBytes.Length];

            Array.Copy(nameTypeBytes, 0, finalBytes, 0, nameTypeBytes.Length);
            Array.Copy(nameBytes, 0, finalBytes, nameTypeBytes.Length, nameBytes.Length);
            Array.Copy(realmBytes, 0, finalBytes, nameTypeBytes.Length + nameBytes.Length, realmBytes.Length);
            Array.Copy(authPackageBytes, 0, finalBytes, nameTypeBytes.Length + nameBytes.Length + realmBytes.Length, authPackageBytes.Length);

            byte[] outBytes = Crypto.KerberosChecksum(key, finalBytes);

            Checksum checksum = new Checksum(outBytes);

            cksum = checksum;
        }

        public AsnElt Encode()
        {
            List<AsnElt> allNodes = new List<AsnElt>();

            // userName[0] PrincipalName
            allNodes.Add(
                AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, userName.Encode()));

            // userRealm[1] Realm
            allNodes.Add(
                AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                    AsnElt.MakeSequence(
                        AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString,
                            AsnElt.MakeString(AsnElt.IA5String, userRealm)))));

            // cksum[2] Checksum
            allNodes.Add(
                AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, cksum.Encode()));

            // auth-package[3] KerberosString
            allNodes.Add(
                AsnElt.MakeImplicit(AsnElt.CONTEXT, 3,
                    AsnElt.MakeSequence(
                        AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString,
                            AsnElt.MakeString(AsnElt.IA5String, auth_package)))));


            // package it all up
            AsnElt seq = AsnElt.MakeSequence(allNodes.ToArray());

            // tag the final total
            //AsnElt final = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] { seq });
            //final = AsnElt.MakeImplicit(AsnElt.APPLICATION, 2, final);

            return seq;
        }

        public PrincipalName userName { get; set; }

        public string userRealm { get; set; }

        public Checksum cksum { get; set; }

        public string auth_package { get; set; }
    }
}