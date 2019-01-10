using System;
using System.IO;

namespace Rubeus.Asn1
{
    public class AsnException : IOException
    {
	    public AsnException(string message)
		    : base(message)
	    {
            return;
	    }

	    public AsnException(string message, Exception nested)
		    : base(message, nested)
	    {
            return;
	    }
    }
}
