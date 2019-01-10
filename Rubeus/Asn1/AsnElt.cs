using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Rubeus.Asn1
{
    /* An AsnElt instance represents a decoded ASN.1 DER object. It is immutable. */
    public class AsnElt
    {
        /* Internal rules
	     * Instances are immutable. They reference an internal buffer that they never modify. 
         * The buffer is never shown to the outside; when decoding and creating, copies are
         * performed where necessary.
	     * If the instance was created by decoding, then:
	     *   objBuf   points to the array containing the complete object
	     *   objOff   start offset for the object header
	     *   objLen   complete object length
	     *   valOff   offset for the first value byte
	     *   valLen   value length (excluding the null-tag, if applicable)
	     *   hasEncodedHeader  is true
	     *
	     * If the instance was created from an explicit value or from sub-elements, then:
	     *   objBuf   contains the value, or is null
	     *   objOff   is 0
	     *   objLen   is -1, or contains the computed object length
	     *   valOff   is 0
	     *   valLen   is -1, or contains the computed value length
	     *   hasEncodedHeader  is false
	     *
	     * If objBuf is null, then the object is necessarily constructed (Sub is not null).
         * If objBuf is not null, then the encoded value is known (the object may be constructed
         * or primitive), and valOff/valLen identify the actual value within objBuf.
	     *
	     * Tag class and value, and sub-elements, are referenced from specific properties. */

        private AsnElt(int tagClass, int tagValue)
        {
            this.TagClass = tagClass;
            this.TagValue = tagValue;
            return;
        }

        public int Count
        {
            get { return (null == _sub) ? 0 : _sub.Length; }
        }

        /* The encoded object length (complete with header). */
        public int EncodedLength
        {
            get
            {
                if (0 > _objectLength) {
                    int vlen = ValueLength;
                    _objectLength = TagLength(TagValue) + LengthLength(vlen) + vlen;
                }
                return _objectLength;
            }
        }

        public AsnElt FirstElement
        {
            get { return (0 < _sub.Length) ? _sub[0] : null; }
        }

        /* The "constructed" flag: true for an elements with sub-elements, false for a primitive
         * element. */
        private bool IsConstructed
        {
            get { return (null != _sub); }
        }

        public AsnElt SecondElement
        {
            get { return (1 < _sub.Length) ? _sub[1] : null; }
        }

        /* The tag class for this element. */
        public int TagClass { get; private set; }

        /* Get a string representation of the tag class and value. */
        public string TagString
        {
            get { return TagToString(TagClass, TagValue); }
        }

        /// <summary>The tag value for this element.</summary>
        internal int TagValue { get; private set; }

        /* The value length. When the object is BER-encoded with an indefinite length, the value
         * length includes all the sub-objects but NOT the formal null-tag marker. */
        public int ValueLength
        {
            get {
                if (_valueLength < 0) {
                    if (IsConstructed) {
                        int vlen = 0;
                        foreach (AsnElt a in EnumerateElements()) { vlen += a.EncodedLength; }
                        _valueLength = vlen;
                    }
                    else { _valueLength = _objectBuffer.Length; }
                }
                return _valueLength;
            }
        }

        //public AsnElt[] Sub
        //{
        //    get { return _sub; }
        //    private set { _sub = value; }
        //}

        /* Check that this element is constructed. An exception is thrown if this is not the case.*/
        private void AssertConstructed()
        {
            if (!IsConstructed) {
                throw new AsnException("not constructed");
            }
        }

        /* Check that this element is primitive. An exception is thrown if this is not the case. */
        private void AssertPrimitive()
        {
            if (IsConstructed) {
                throw new AsnException("not primitive");
            }
        }

        /* Check that this element is constructed and contains exactly 'n' sub-elements. */
        public void CheckNumSub(int n)
        {
            AssertConstructed();
            int realLength = _sub.Length;
            if (realLength != n) {
                throw new AsnException("wrong number of sub-elements: " + realLength + " (expected: " + n + ")");
            }
        }

        /* Check that this element is constructed and contains no more than 'n' sub-elements. */
        public void CheckNumSubMax(int n)
        {
            AssertConstructed();
            int realLength = _sub.Length;
            if (realLength > n) {
                throw new AsnException("too many sub-elements: " + realLength + " (maximum: " + n + ")");
            }
        }

        /* Check that this element is constructed and contains at least 'n' sub-elements. */
        public void CheckNumSubMin(int n)
        {
            AssertConstructed();
            int realLength = _sub.Length;
            if (realLength < n) {
                throw new AsnException("not enough sub-elements: " + realLength + " (minimum: " + n + ")");
            }
        }

        /* Check that the tag is UNIVERSAL with the provided value. */
        public void CheckTag(int tv)
        {
            CheckTag(UNIVERSAL, tv);
        }

        /* Check that the tag has the specified class and value.*/
        public void CheckTag(int tc, int tv)
        {
            if (TagClass != tc || TagValue != tv) {
                throw new AsnException("unexpected tag: " + TagString);
            }
        }

        public IEnumerable<AsnElt> EnumerateElements()
        {
            foreach(AsnElt item in _sub) { yield return item; }
            yield break;
        }

        /* Get a sub-element. This method throws appropriate exceptions if this element is not
         * constructed, or the requested index is out of range. */
        public AsnElt GetSub(int index)
        {
            AssertConstructed();
            if ((0 > index) || (_sub.Length <= index)) {
                throw new AsnException("no such sub-object: n=" + index);
            }
            return _sub[index];
        }

        /* Get the encoded length for a tag. */
        private static int TagLength(int tv)
        {
            if (tv <= 0x1F) { return 1; }
            int result = 1;
            while (tv > 0) {
                result++;
                tv >>= 7;
            }
            return result;
        }

        private static string TagToString(int tc, int tv)
        {
            switch (tc) {
                case UNIVERSAL:
                    break;
                case APPLICATION:
                    return "APPLICATION:" + tv;
                case CONTEXT:
                    return "CONTEXT:" + tv;
                case PRIVATE:
                    return "PRIVATE:" + tv;
                default:
                    return string.Format("INVALID:{0}/{1}", tc, tv);
            }

            switch (tv) {
                case BOOLEAN: return "BOOLEAN";
                case INTEGER: return "INTEGER";
                case BIT_STRING: return "BIT_STRING";
                case OCTET_STRING: return "OCTET_STRING";
                case NULL: return "NULL";
                case OBJECT_IDENTIFIER: return "OBJECT_IDENTIFIER";
                case Object_Descriptor: return "Object_Descriptor";
                case EXTERNAL: return "EXTERNAL";
                case REAL: return "REAL";
                case ENUMERATED: return "ENUMERATED";
                case EMBEDDED_PDV: return "EMBEDDED_PDV";
                case UTF8String: return "UTF8String";
                case RELATIVE_OID: return "RELATIVE_OID";
                case SEQUENCE: return "SEQUENCE";
                case SET: return "SET";
                case NumericString: return "NumericString";
                case PrintableString: return "PrintableString";
                case TeletexString: return "TeletexString";
                case VideotexString: return "VideotexString";
                case IA5String: return "IA5String";
                case UTCTime: return "UTCTime";
                case GeneralizedTime: return "GeneralizedTime";
                case GraphicString: return "GraphicString";
                case VisibleString: return "VisibleString";
                case GeneralString: return "GeneralString";
                case UniversalString: return "UniversalString";
                case CHARACTER_STRING: return "CHARACTER_STRING";
                case BMPString: return "BMPString";
                default:
                    return String.Format("UNIVERSAL:" + tv);
            }
        }

        /* Get the encoded length for a length. */
        private static int LengthLength(int len)
        {
            if (len < 0x80) { return 1; }
            int result = 1;
            while (len > 0) {
                result++;
                len >>= 8;
            }
            return result;
        }

        /* Decode an ASN.1 object. The provided buffer is internally copied. Trailing garbage is
         * not tolerated. */
        public static AsnElt Decode(byte[] buf)
        {
            return Decode(buf, 0, buf.Length, true);
        }

        /* Decode an ASN.1 object. The provided buffer is internally copied. Trailing garbage is
         * not tolerated. */
        public static AsnElt Decode(byte[] buf, int off, int len)
        {
            return Decode(buf, off, len, true);
        }

        /* Decode an ASN.1 object. The provided buffer is internally copied. If 'exactLength' is
         * true, then trailing garbage is not tolerated (it triggers an exception). */
        public static AsnElt Decode(byte[] buf, bool exactLength)
        {
            return Decode(buf, 0, buf.Length, exactLength);
        }

        /* Decode an ASN.1 object. The provided buffer is internally copied. If 'exactLength' is
         * true, then trailing garbage is not tolerated (it triggers an exception). */
        public static AsnElt Decode(byte[] buf, int off, int len, bool exactLength)
        {
            int tc, tv, valOff, valLen;
            bool cons;
            int objLen = Decode(buf, off, len, out tc, out tv, out cons, out valOff, out valLen);
            if (exactLength && objLen != len) {
                throw new AsnException("trailing garbage");
            }
            byte[] nbuf = new byte[objLen];
            Array.Copy(buf, off, nbuf, 0, objLen);
            return DecodeNoCopy(nbuf, 0, objLen);
        }

        /* Internal recursive decoder. The provided array is NOT copied. Trailing garbage is
         * ignored (caller should use the 'objLen' field to learn the total object length). */
        static AsnElt DecodeNoCopy(byte[] buf, int off, int len)
        {
            int tc, tv, valOff, valLen, objLen;
            bool constructed;
            objLen = Decode(buf, off, len, out tc, out tv, out constructed, out valOff, out valLen);
            AsnElt result = new AsnElt(tc, tv) {
                _objectBuffer = buf,
                _objectOffset = off,
                _objectLength = objLen,
                _valueOffset = valOff,
                _valueLength = valLen,
                _hasEncodedHeader = true
            };
            if (constructed) {
                List<AsnElt> subs = new List<AsnElt>();
                off = valOff;
                int lim = valOff + valLen;
                while (off < lim) {
                    AsnElt b = DecodeNoCopy(buf, off, lim - off);
                    off += b._objectLength;
                    subs.Add(b);
                }
                result._sub = subs.ToArray();
            }
            else {
                result._sub = null;
            }
            return result;
        }

        /* Decode the tag and length, and get the value offset and length. Returned value if the
         * total object length. Note: when an object has indefinite length, the terminated "null
         * tag" will NOT be considered part of the "value length". */
        static int Decode(byte[] buf, int off, int maxLen, out int tc, out int tv, out bool cons,
            out int valOff, out int valLen)
        {
            int lim = off + maxLen;
            int orig = off;

            /* Decode tag. */
            CheckOff(off, lim);
            tv = buf[off++];
            cons = (tv & 0x20) != 0;
            tc = tv >> 6;
            tv &= 0x1F;
            if (tv == 0x1F) {
                tv = 0;
                while(true) {
                    CheckOff(off, lim);
                    int c = buf[off++];
                    if (tv > 0xFFFFFF) { throw new AsnException("tag value overflow"); }
                    tv = (tv << 7) | (c & 0x7F);
                    if ((c & 0x80) == 0) { break; }
                }
            }

            /* Decode length. */
            CheckOff(off, lim);
            int vlen = buf[off++];
            if (vlen == 0x80) {
                /* Indefinite length. This is not strict DER, bu we allow it nonetheless; we must
                 * check that the value was tagged as constructed, though. */
                vlen = -1;
                if (!cons) { throw new AsnException("indefinite length" + " but not constructed"); }
            }
            else if (vlen > 0x80) {
                int lenlen = vlen - 0x80;
                CheckOff(off + lenlen - 1, lim);
                vlen = 0;
                while (lenlen-- > 0) {
                    if (vlen > 0x7FFFFF) { throw new AsnException("length overflow"); }
                    vlen = (vlen << 8) + buf[off++];
                }
            }

            /* Length was decoded, so the value starts here. */
            valOff = off;

            /* If length is indefinite then we must explore sub-objects to get the value length. */
            if (vlen < 0) {
                while(true) {
                    int tc2, tv2, valOff2, valLen2;
                    bool cons2;
                    int slen = Decode(buf, off, lim - off, out tc2, out tv2, out cons2, out valOff2, out valLen2);
                    if (tc2 == 0 && tv2 == 0) {
                        if (cons2 || valLen2 != 0) { throw new AsnException("invalid null tag"); }
                        valLen = off - valOff;
                        off += slen;
                        break;
                    }
                    off += slen;
                }
            }
            else {
                if (vlen > (lim - off)) { throw new AsnException("value overflow"); }
                off += vlen;
                valLen = off - valOff;
            }
            return off - orig;
        }

        private static void CheckOff(int offset, int limitExcluded)
        {
            if (offset >= limitExcluded) {
                throw new AsnException("offset overflow");
            }
        }

        /* Get a specific byte from the value. This provided offset is relative to the value start
         * (first value byte has offset 0). */
        public int ValueByte(int off)
        {
            if (off < 0) {
                throw new AsnException("invalid value offset: " + off);
            }
            if (_objectBuffer == null) {
                int k = 0;
                foreach (AsnElt a in this.EnumerateElements()) {
                    int slen = a.EncodedLength;
                    if ((k + slen) > off) {
                        return a.ValueByte(off - k);
                    }
                }
            }
            else {
                if (off < _valueLength) {
                    return _objectBuffer[_valueOffset + off];
                }
            }
            throw new AsnException(String.Format("invalid value offset {0} (length = {1})",
                off, ValueLength));
        }

        /* Encode this object into a newly allocated array. */
        public byte[] Encode()
        {
            byte[] r = new byte[EncodedLength];
            Encode(r, 0);
            return r;
        }

        /* Encode this object into the provided array. Encoded object length is returned. */
        public int Encode(byte[] dst, int off)
        {
            return Encode(0, Int32.MaxValue, dst, off);
        }

        /* Encode this object into the provided array. Only bytes at offset between 'start'
         * (inclusive) and 'end' (exclusive) are actually written. The number of written bytes
         * is returned. Offsets are relative to the object start (first tag byte). */
        private int Encode(int start, int end, byte[] dst, int dstOff)
        {
            /* If the encoded value is already known, then we just dump it. */
            if (_hasEncodedHeader) {
                int from = _objectOffset + Math.Max(0, start);
                int to = _objectOffset + Math.Min(_objectLength, end);
                int len = to - from;
                if (len > 0) {
                    Array.Copy(_objectBuffer, from, dst, dstOff, len);
                    return len;
                }
                return 0;
            }
            int off = 0;
            /* Encode tag. */
            int fb = (TagClass << 6) + (IsConstructed ? 0x20 : 0x00);
            if (TagValue < 0x1F) {
                fb |= (TagValue & 0x1F);
                if (start <= off && off < end) {
                    dst[dstOff++] = (byte)fb;
                }
                off++;
            }
            else {
                fb |= 0x1F;
                if (start <= off && off < end) {
                    dst[dstOff++] = (byte)fb;
                }
                off++;
                int k = 0;
                for (int v = TagValue; v > 0; v >>= 7, k += 7) ;
                while (k > 0) {
                    k -= 7;
                    int v = (TagValue >> k) & 0x7F;
                    if (k != 0) {
                        v |= 0x80;
                    }
                    if (start <= off && off < end) {
                        dst[dstOff++] = (byte)v;
                    }
                    off++;
                }
            }

            /* Encode length. */
            int vlen = ValueLength;
            if (vlen < 0x80) {
                if (start <= off && off < end) {
                    dst[dstOff++] = (byte)vlen;
                }
                off++;
            }
            else {
                int k = 0;
                for (int v = vlen; v > 0; v >>= 8, k += 8) ;
                if (start <= off && off < end) {
                    dst[dstOff++] = (byte)(0x80 + (k >> 3));
                }
                off++;
                while (k > 0) {
                    k -= 8;
                    if (start <= off && off < end) {
                        dst[dstOff++] = (byte)(vlen >> k);
                    }
                    off++;
                }
            }

            /* Encode value. We must adjust the start/end window to make it relative to the value. */
            EncodeValue(start - off, end - off, dst, dstOff);
            off += vlen;

            /* Compute copied length. */
            return Math.Max(0, Math.Min(off, end) - Math.Max(0, start));
        }

        /* Encode the value into the provided buffer. Only value bytes at offsets between 'start'
         * (inclusive) and 'end' (exclusive) are written. Actual number of written bytes is
         * returned. Offsets are relative to the start of the value. */
        private int EncodeValue(int start, int end, byte[] dst, int dstOff)
        {
            int orig = dstOff;
            if (_objectBuffer == null) {
                int k = 0;
                foreach (AsnElt a in this.EnumerateElements()) {
                    int slen = a.EncodedLength;
                    dstOff += a.Encode(start - k, end - k, dst, dstOff);
                    k += slen;
                }
            }
            else {
                int from = Math.Max(0, start);
                int to = Math.Min(_valueLength, end);
                int len = to - from;
                if (len > 0) {
                    Array.Copy(_objectBuffer, _valueOffset + from, dst, dstOff, len);
                    dstOff += len;
                }
            }
            return dstOff - orig;
        }

        /* Copy a value chunk. The provided offset ('off') and length ('len') define the chunk to
         * copy; the offset is relative to the value start (first value byte has offset 0). If the
         * requested window exceeds the value boundaries, an exception is thrown. */
        public void CopyValueChunk(int off, int len, byte[] dst, int dstOff)
        {
            int vlen = ValueLength;
            if (off < 0 || len < 0 || len > (vlen - off)) {
                throw new AsnException(String.Format(
                    "invalid value window {0}:{1}"
                    + " (value length = {2})", off, len, vlen));
            }
            EncodeValue(off, off + len, dst, dstOff);
        }

        /* Copy the value into the specified array. The value length is returned. */
        public int CopyValue(byte[] dst, int off)
        {
            return EncodeValue(0, Int32.MaxValue, dst, off);
        }

        /* Get a copy of the value as a freshly allocated array. */
        public byte[] CopyValue()
        {
            byte[] r = new byte[ValueLength];
            EncodeValue(0, r.Length, r, 0);
            return r;
        }

        /* Get the value. This may return a shared buffer, that MUST NOT be modified. */
        private byte[] GetValue(out int off, out int len)
        {
            if (_objectBuffer == null) {
                /* We can modify objBuf because CopyValue() called ValueLength, thus valLen has
                 * been filled. */
                _objectBuffer = CopyValue();
                off = 0;
                len = _objectBuffer.Length;
            }
            else {
                off = _valueOffset;
                len = _valueLength;
            }
            return _objectBuffer;
        }

        /* Interpret the value as a BOOLEAN. */
        public bool GetBoolean()
        {
            AssertPrimitive();
            int vlen = ValueLength;
            if (vlen != 1) {
                throw new AsnException(String.Format("invalid BOOLEAN (length = {0})", vlen));
            }
            return ValueByte(0) != 0;
        }

        /* Interpret the value as an INTEGER. An exception is thrown if the value does not fit in
         * a 'long'. */
        public long GetInteger()
        {
            AssertPrimitive();
            int vlen = ValueLength;
            if (vlen == 0) {
                throw new AsnException("invalid INTEGER (length = 0)");
            }
            int v = ValueByte(0);
            long x;
            if ((v & 0x80) != 0) {
                x = -1;
                for (int k = 0; k < vlen; k++) {
                    if (x < ((-1L) << 55)) {
                        throw new AsnException("integer overflow (negative)");
                    }
                    x = (x << 8) + (long)ValueByte(k);
                }
            }
            else {
                x = 0;
                for (int k = 0; k < vlen; k++) {
                    if (x >= (1L << 55)) {
                        throw new AsnException("integer overflow (positive)");
                    }
                    x = (x << 8) + (long)ValueByte(k);
                }
            }
            return x;
        }

        /* Interpret the value as an INTEGER. An exception is thrown if the value is outside of
         * the provided range. */
        public long GetInteger(long min, long max)
        {
            long v = GetInteger();
            if (v < min || v > max) {
                throw new AsnException("integer out of allowed range");
            }
            return v;
        }

        /* Interpret the value as an INTEGER. Return its hexadecimal representation (uppercase),
         * preceded by a '0x' or '-0x' header, depending on the integer sign. The number of
         * hexadecimal digits is even. Leading zeroes are returned (but one may remain, to ensure
         * an even number of digits). If the integer has value 0, then 0x00 is returned. */
        public string GetIntegerHex()
        {
            AssertPrimitive();
            int vlen = ValueLength;
            if (vlen == 0) {
                throw new AsnException("invalid INTEGER (length = 0)");
            }
            StringBuilder sb = new StringBuilder();
            byte[] tmp = CopyValue();
            if (tmp[0] >= 0x80) {
                sb.Append('-');
                int cc = 1;
                for (int i = tmp.Length - 1; i >= 0; i--) {
                    int v = ((~tmp[i]) & 0xFF) + cc;
                    tmp[i] = (byte)v;
                    cc = v >> 8;
                }
            }
            int k = 0;
            while (k < tmp.Length && tmp[k] == 0) {
                k++;
            }
            if (k == tmp.Length) {
                return "0x00";
            }
            sb.Append("0x");
            while (k < tmp.Length) {
                sb.AppendFormat("{0:X2}", tmp[k++]);
            }
            return sb.ToString();
        }

        /* Interpret the value as an OCTET STRING. The value bytes are returned. This method
         * supports constructed values and performs the reassembly. */
        public byte[] GetOctetString()
        {
            int len = GetOctetString(null, 0);
            byte[] r = new byte[len];
            GetOctetString(r, 0);
            return r;
        }

        /* Interpret the value as an OCTET STRING. The value bytes are written in dst[], starting
         * at offset 'off', and the total value length is returned. If 'dst' is null, then no byte
         * is written anywhere, but the total length is still returned. This method supports
         * constructed values and performs the reassembly. */
        public int GetOctetString(byte[] dst, int off)
        {
            if (IsConstructed) {
                int orig = off;
                foreach (AsnElt ae in this.EnumerateElements()) {
                    ae.CheckTag(AsnElt.OCTET_STRING);
                    off += ae.GetOctetString(dst, off);
                }
                return off - orig;
            }
            if (dst != null) {
                return CopyValue(dst, off);
            }
            return ValueLength;
        }

        /* Interpret the value as a BIT STRING. The bits are returned, with the "ignored bits"
         * cleared. */
        public byte[] GetBitString()
        {
            int bitLength;
            return GetBitString(out bitLength);
        }

        /* Interpret the value as a BIT STRING. The bits are returned, with the "ignored bits"
         * cleared. The actual bit length is written in 'bitLength'. */
        public byte[] GetBitString(out int bitLength)
        {
            AssertPrimitive();
            int vlen = ValueLength;
            if (vlen == 0) {
                throw new AsnException("invalid BIT STRING (length = 0)");
            }
            int fb = ValueByte(0);
            if (fb > 7 || (vlen == 1 && fb != 0)) {
                throw new AsnException(String.Format("invalid BIT STRING (start = 0x{0:X2})", fb));
            }
            byte[] r = new byte[vlen - 1];
            CopyValueChunk(1, vlen - 1, r, 0);
            if (vlen > 1) {
                r[r.Length - 1] &= (byte)(0xFF << fb);
            }
            bitLength = (r.Length << 3) - fb;
            return r;
        }

        /* Interpret the value as a NULL. */
        public void CheckNull()
        {
            AssertPrimitive();
            if (ValueLength != 0) {
                throw new AsnException(String.Format("invalid NULL (length = {0})", ValueLength));
            }
        }

        /// <summary>Interpret the value as an OBJECT IDENTIFIER, and return it (in decimal-dotted
        /// string format).</summary>
        /// <returns></returns>
        internal string GetOID()
        {
            AssertPrimitive();
            if (_valueLength == 0) {
                throw new AsnException("zero-length OID");
            }
            int v = _objectBuffer[_valueOffset];
            if (v >= 120) {
                throw new AsnException("invalid OID: first byte = " + v);
            }
            StringBuilder sb = new StringBuilder();
            sb.Append(v / 40);
            sb.Append('.');
            sb.Append(v % 40);
            long acc = 0;
            bool uv = false;
            for (int i = 1; i < _valueLength; i++){
                v = _objectBuffer[_valueOffset + i];
                if ((acc >> 56) != 0){
                    throw new AsnException("invalid OID: integer overflow");
                }
                acc = (acc << 7) + (long)(v & 0x7F);
                if ((v & 0x80) == 0) {
                    sb.Append('.');
                    sb.Append(acc);
                    acc = 0;
                    uv = false;
                }
                else {
                    uv = true;
                }
            }
            if (uv) {
                throw new AsnException("invalid OID: truncated");
            }
            return sb.ToString();
        }

        /// <summary>Get the object value as a string. The string type is provided (universal tag
        /// value). Supported string types include NumericString, PrintableString, IA5String,
        /// TeletexString (interpreted as ISO-8859-1), UTF8String, BMPString and UniversalString;
        /// the "time types" (UTCTime and GeneralizedTime) are also supported, though, in their case,
        /// the internal contents are not checked (they are decoded as PrintableString).</summary>
        /// <param name="type"></param>
        /// <returns></returns>
        private string GetString(int type)
        {
            AssertPrimitive();
            switch (type) {
                case NumericString:
                case PrintableString:
                case IA5String:
                case TeletexString:
                case UTCTime:
                case GeneralizedTime:
                    return DecodeMono(_objectBuffer, _valueOffset, _valueLength, type);
                case UTF8String:
                    return DecodeUTF8(_objectBuffer, _valueOffset, _valueLength);
                case BMPString:
                    return DecodeUTF16(_objectBuffer, _valueOffset, _valueLength);
                case UniversalString:
                    return DecodeUTF32(_objectBuffer, _valueOffset, _valueLength);
                default:
                    throw new AsnException("unsupported string type: " + type);
            }
        }

        /// <summary></summary>
        /// <param name="buf"></param>
        /// <param name="off"></param>
        /// <param name="len"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        private static string DecodeMono(byte[] buf, int off, int len, int type)
        {
            char[] tc = new char[len];
            for (int i = 0; i < len; i++) {
                tc[i] = (char)buf[off + i];
            }
            VerifyChars(tc, type);
            return new string(tc);
        }

        /// <summary></summary>
        /// <param name="buf"></param>
        /// <param name="off"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        private static string DecodeUTF8(byte[] buf, int off, int len)
        {
            /* Skip BOM.*/
            if (len >= 3 && buf[off] == 0xEF
                && buf[off + 1] == 0xBB && buf[off + 2] == 0xBF)
            {
                off += 3;
                len -= 3;
            }
            char[] tc = null;
            for (int k = 0; k < 2; k++) {
                int tcOff = 0;
                for (int i = 0; i < len; i++) {
                    int c = buf[off + i];
                    int e;
                    if (c < 0x80) {
                        e = 0;
                    }
                    else if (c < 0xC0) {
                        throw BadByte(c, UTF8String);
                    }
                    else if (c < 0xE0) {
                        c &= 0x1F;
                        e = 1;
                    }
                    else if (c < 0xF0) {
                        c &= 0x0F;
                        e = 2;
                    }
                    else if (c < 0xF8) {
                        c &= 0x07;
                        e = 3;
                    }
                    else {
                        throw BadByte(c, UTF8String);
                    }
                    while (e-- > 0) {
                        if (++i >= len) {
                            throw new AsnException("invalid UTF-8 string");
                        }
                        int d = buf[off + i];
                        if (d < 0x80 || d > 0xBF) {
                            throw BadByte(d, UTF8String);
                        }
                        c = (c << 6) + (d & 0x3F);
                    }
                    if (c > 0x10FFFF) {
                        throw BadChar(c, UTF8String);
                    }
                    if (c > 0xFFFF) {
                        c -= 0x10000;
                        int hi = 0xD800 + (c >> 10);
                        int lo = 0xDC00 + (c & 0x3FF);
                        if (tc != null) {
                            tc[tcOff] = (char)hi;
                            tc[tcOff + 1] = (char)lo;
                        }
                        tcOff += 2;
                    }
                    else {
                        if (tc != null) {
                            tc[tcOff] = (char)c;
                        }
                        tcOff++;
                    }
                }
                if (tc == null) {
                    tc = new char[tcOff];
                }
            }
            VerifyChars(tc, UTF8String);
            return new string(tc);
        }

        /// <summary></summary>
        /// <param name="buf"></param>
        /// <param name="off"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        private static string DecodeUTF16(byte[] buf, int off, int len)
        {
            if ((len & 1) != 0) {
                throw new AsnException("invalid UTF-16 string: length = " + len);
            }
            len >>= 1;
            if (len == 0) {
                return "";
            }
            bool be = true;
            int hi = buf[off];
            int lo = buf[off + 1];
            if (hi == 0xFE && lo == 0xFF) {
                off += 2;
                len--;
            }
            else if (hi == 0xFF && lo == 0xFE) {
                off += 2;
                len--;
                be = false;
            }
            char[] tc = new char[len];
            for (int i = 0; i < len; i++) {
                int b0 = buf[off++];
                int b1 = buf[off++];
                if (be) {
                    tc[i] = (char)((b0 << 8) + b1);
                }
                else {
                    tc[i] = (char)((b1 << 8) + b0);
                }
            }
            VerifyChars(tc, BMPString);
            return new string(tc);
        }

        /// <summary></summary>
        /// <param name="buf"></param>
        /// <param name="off"></param>
        /// <param name="len"></param>
        /// <returns></returns>
        private static string DecodeUTF32(byte[] buf, int off, int len)
        {
            if ((len & 3) != 0) {
                throw new AsnException("invalid UTF-32 string: length = " + len);
            }
            len >>= 2;
            if (len == 0) {
                return "";
            }
            bool be = true;
            if (buf[off] == 0x00
                && buf[off + 1] == 0x00
                && buf[off + 2] == 0xFE
                && buf[off + 3] == 0xFF)
            {
                off += 4;
                len--;
            }
            else if (buf[off] == 0xFF
              && buf[off + 1] == 0xFE
              && buf[off + 2] == 0x00
              && buf[off + 3] == 0x00)
            {
                off += 4;
                len--;
                be = false;
            }

            char[] tc = null;
            for (int k = 0; k < 2; k++) {
                int tcOff = 0;
                for (int i = 0; i < len; i++) {
                    uint b0 = buf[off + 0];
                    uint b1 = buf[off + 1];
                    uint b2 = buf[off + 2];
                    uint b3 = buf[off + 3];
                    uint c;
                    if (be) {
                        c = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
                    }
                    else {
                        c = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
                    }
                    if (c > 0x10FFFF) {
                        throw BadChar((int)c, UniversalString);
                    }
                    if (c > 0xFFFF) {
                        c -= 0x10000;
                        int hi = 0xD800 + (int)(c >> 10);
                        int lo = 0xDC00 + (int)(c & 0x3FF);
                        if (tc != null) {
                            tc[tcOff] = (char)hi;
                            tc[tcOff + 1] = (char)lo;
                        }
                        tcOff += 2;
                    }
                    else {
                        if (tc != null) {
                            tc[tcOff] = (char)c;
                        }
                        tcOff++;
                    }
                }
                if (tc == null) {
                    tc = new char[tcOff];
                }
            }
            VerifyChars(tc, UniversalString);
            return new string(tc);
        }

        /// <summary></summary>
        /// <param name="tc"></param>
        /// <param name="type"></param>
        private static void VerifyChars(char[] tc, int type)
        {
            switch (type) {
                case NumericString:
                    foreach (char c in tc) {
                        if (!IsNum(c)) {
                            throw BadChar(c, type);
                        }
                    }
                    return;
                case PrintableString:
                case UTCTime:
                case GeneralizedTime:
                    foreach (char c in tc) {
                        if (!IsPrintable(c)) {
                            throw BadChar(c, type);
                        }
                    }
                    return;
                case IA5String:
                    foreach (char c in tc) {
                        if (!IsIA5(c)) {
                            throw BadChar(c, type);
                        }
                    }
                    return;
                case TeletexString:
                    foreach (char c in tc) {
                        if (!IsLatin1(c)) {
                            throw BadChar(c, type);
                        }
                    }
                    return;
            }

            /* For Unicode string types (UTF-8, BMP...). */
            for (int i = 0; i < tc.Length; i++) {
                int c = tc[i];
                if (c >= 0xFDD0 && c <= 0xFDEF) {
                    throw BadChar(c, type);
                }
                if (c == 0xFFFE || c == 0xFFFF) {
                    throw BadChar(c, type);
                }
                if (c < 0xD800 || c > 0xDFFF) {
                    continue;
                }
                if (c > 0xDBFF) {
                    throw BadChar(c, type);
                }
                int hi = c & 0x3FF;
                if (++i >= tc.Length) {
                    throw BadChar(c, type);
                }
                c = tc[i];
                if (c < 0xDC00 || c > 0xDFFF) {
                    throw BadChar(c, type);
                }
                int lo = c & 0x3FF;
                c = 0x10000 + lo + (hi << 10);
                if ((c & 0xFFFE) == 0xFFFE) {
                    throw BadChar(c, type);
                }
            }
        }

        /// <summary></summary>
        /// <param name="c"></param>
        /// <returns></returns>
        private static bool IsNum(int c)
        {
            return c == ' ' || (c >= '0' && c <= '9');
        }

        /// <summary></summary>
        /// <param name="c"></param>
        /// <returns></returns>
        private static bool IsPrintable(int c)
        {
            if (c >= 'A' && c <= 'Z') {
                return true;
            }
            if (c >= 'a' && c <= 'z') {
                return true;
            }
            if (c >= '0' && c <= '9') {
                return true;
            }
            switch (c) {
                case ' ':
                case '(':
                case ')':
                case '+':
                case ',':
                case '-':
                case '.':
                case '/':
                case ':':
                case '=':
                case '?':
                case '\'':
                    return true;
                default:
                    return false;
            }
        }

        /// <summary></summary>
        /// <param name="c"></param>
        /// <returns></returns>
        private static bool IsIA5(int c)
        {
            return (sbyte.MaxValue >= c);
        }

        /// <summary></summary>
        /// <param name="c"></param>
        /// <returns></returns>
        private static bool IsLatin1(int c)
        {
            return (byte.MaxValue >= c);
        }

        /// <summary></summary>
        /// <param name="c"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        private static AsnException BadByte(int c, int type)
        {
            return new AsnException(String.Format(
                "unexpected byte 0x{0:X2} in string of type {1}", c, type));
        }

        /// <summary></summary>
        /// <param name="c"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        private static AsnException BadChar(int c, int type)
        {
            return new AsnException(string.Format(
                "unexpected character U+{0:X4} in string of type {1}", c, type));
        }

        /// <summary>Decode the value as a date/time. Returned object is in UTC. Type of date is
        /// inferred from the tag value.</summary>
        /// <returns></returns>
        internal DateTime GetTime()
        {
            int type = TagValue;
            if (TagClass != UNIVERSAL) {
                throw new AsnException(string.Format("cannot infer date type: {0}:{1}",
                    TagClass, type));
            }
            bool isGen = false;
            switch (type) {
                case UTCTime:
                    break;
                case GeneralizedTime:
                    isGen = true;
                    break;
                default:
                    throw new AsnException("unsupported date type: " + type);
            }
            string s = GetString(type);
            string orig = s;

            /* UTCTime has format:
             *    YYMMDDhhmm[ss](Z|(+|-)hhmm)
             *
             * GeneralizedTime has format:
             *    YYYYMMDDhhmmss[.uu*][Z|(+|-)hhmm]
             *
             * Differences between the two types:
             * -- UTCTime encodes year over two digits; GeneralizedTime
             * uses four digits. UTCTime years map to 1950..2049 (00 is 2000).
             * -- Seconds are optional with UTCTime, mandatory with
             * GeneralizedTime.
             * -- GeneralizedTime can have fractional seconds (optional).
             * -- Time zone is optional for GeneralizedTime. However,
             * a missing time zone means "local time" which depends on
             * the locality, so this is discouraged.
             *
             * Some other notes:
             * -- If there is a fractional second, then it must include
             * at least one digit. This implementation processes the
             * first three digits, and ignores the rest (if present).
             * -- Time zone offset ranges from -23:59 to +23:59.
             * -- The calendar computations are delegated to .NET's
             * DateTime (and DateTimeOffset) so this implements a
             * Gregorian calendar, even for dates before 1589. Year 0 is not supported. */

            /* Check characters. */
            foreach (char c in s) {
                if (c >= '0' && c <= '9') {
                    continue;
                }
                if (c == '.' || c == '+' || c == '-' || c == 'Z') {
                    continue;
                }
                throw BadTime(type, orig);
            }

            bool good = true;

            /* Parse the time zone. */
            int tzHours = 0;
            int tzMinutes = 0;
            bool negZ = false;
            bool noTZ = false;
            if (s.EndsWith("Z")) {
                s = s.Substring(0, s.Length - 1);
            }
            else {
                int j = s.IndexOf('+');
                if (j < 0) {
                    j = s.IndexOf('-');
                    negZ = true;
                }
                if (j < 0) {
                    noTZ = true;
                }
                else {
                    string t = s.Substring(j + 1);
                    s = s.Substring(0, j);
                    if (t.Length != 4) {
                        throw BadTime(type, orig);
                    }
                    tzHours = Dec2(t, 0, ref good);
                    tzMinutes = Dec2(t, 2, ref good);
                    if (tzHours < 0 || tzHours > 23 || tzMinutes < 0 || tzMinutes > 59) {
                        throw BadTime(type, orig);
                    }
                }
            }

            /* Lack of time zone is allowed only for GeneralizedTime. */
            if (noTZ && !isGen) {
                throw BadTime(type, orig);
            }

            /* Parse the date elements. */
            if (s.Length < 4) {
                throw BadTime(type, orig);
            }
            int year = Dec2(s, 0, ref good);
            if (isGen) {
                year = year * 100 + Dec2(s, 2, ref good);
                s = s.Substring(4);
            }
            else {
                if (year < 50) {
                    year += 100;
                }
                year += 1900;
                s = s.Substring(2);
            }
            int month = Dec2(s, 0, ref good);
            int day = Dec2(s, 2, ref good);
            int hour = Dec2(s, 4, ref good);
            int minute = Dec2(s, 6, ref good);
            int second = 0;
            int millisecond = 0;
            if (isGen) {
                second = Dec2(s, 8, ref good);
                if (s.Length >= 12 && s[10] == '.') {
                    s = s.Substring(11);
                    foreach (char c in s) {
                        if (c < '0' || c > '9') {
                            good = false;
                            break;
                        }
                    }
                    s += "0000";
                    millisecond = 10 * Dec2(s, 0, ref good) + Dec2(s, 2, ref good) / 10;
                }
                else if (s.Length != 10) {
                    good = false;
                }
            }
            else {
                switch (s.Length) {
                    case 8:
                        break;
                    case 10:
                        second = Dec2(s, 8, ref good);
                        break;
                    default:
                        throw BadTime(type, orig);
                }
            }

            /* Parsing is finished; if any error occurred, then the 'good' flag has been cleared. */
            if (!good) {
                throw BadTime(type, orig);
            }

            /* Leap seconds are not supported by .NET, so we claim they do not occur. */
            if (second == 60) {
                second = 59;
            }

            /* .NET implementation performs all the checks (including checks on month length
             * depending on year, as per the proleptic Gregorian calendar). */
            try {
                if (noTZ) {
                    DateTime dt = new DateTime(year, month, day, hour, minute, second, millisecond,
                        DateTimeKind.Local);
                    return dt.ToUniversalTime();
                }
                TimeSpan tzOff = new TimeSpan(tzHours, tzMinutes, 0);
                if (negZ) {
                    tzOff = tzOff.Negate();
                }
                DateTimeOffset dto = new DateTimeOffset(year, month, day, hour, minute, second,
                    millisecond, tzOff);
                return dto.UtcDateTime;
            }
            catch (Exception e) {
                throw BadTime(type, orig, e);
            }
        }

        /// <summary></summary>
        /// <param name="s"></param>
        /// <param name="off"></param>
        /// <param name="good"></param>
        /// <returns></returns>
        private static int Dec2(string s, int off, ref bool good)
        {
            if (off < 0 || off >= (s.Length - 1)) {
                good = false;
                return -1;
            }
            char c1 = s[off];
            char c2 = s[off + 1];
            if (c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9') {
                good = false;
                return -1;
            }
            return 10 * (c1 - '0') + (c2 - '0');
        }

        /// <summary></summary>
        /// <param name="type"></param>
        /// <param name="s"></param>
        /// <param name="e"></param>
        /// <returns></returns>
        private static AsnException BadTime(int type, string s, Exception e = null)
        {
            string msg = string.Format("invalid {0} string: '{1}'",
                (type == UTCTime) ? "UTCTime" : "GeneralizedTime",
                s);
            if (null == e) {
                return new AsnException(msg);
            }
            else {
                return new AsnException(msg, e);
            }
        }

        /* =============================================================== */

        /* Like MakePrimitive(), but the provided array is NOT copied. This is for other factory
         * methods that already allocate a new array. */
        private static AsnElt MakeUniversalPrimitiveInner(int tagValue, byte[] val)
        {
            return MakePrimitiveInner(UNIVERSAL, tagValue, val, 0, val.Length);
        }

        private static AsnElt MakePrimitiveInner(int tagClass, int tagValue, byte[] val, int off, int len)
        {
            if (tagClass < 0 || tagClass > 3) {
                throw new AsnException("invalid tag class: " + tagClass);
            }
            if (tagValue < 0) {
                throw new AsnException("invalid tag value: " + tagValue);
            }
            AsnElt a = new AsnElt(tagClass, tagValue);
            a._objectBuffer = new byte[len];
            Array.Copy(val, off, a._objectBuffer, 0, len);
            a._objectOffset = 0;
            a._objectLength = -1;
            a._valueOffset = 0;
            a._valueLength = len;
            a._hasEncodedHeader = false;
            a._sub = null;
            return a;
        }

        /// <summary>Create a new INTEGER value for the provided integer.</summary>
        /// <param name="x"></param>
        /// <returns></returns>
        internal static AsnElt MakeInteger(long x)
        {
            byte[] v;
            int k = 1;
            if (0 <= x) {
                for (ulong w = (ulong)x; 0x80 <= w; w >>= sizeof(byte)) {
                    k++;
                }
            }
            else {
                for (long w = x; (-(long)0x80) >= w; w >>= sizeof(byte)) {
                    k++;
                }
            }
            v = new byte[k];
            for (long w = x; k > 0; w >>= sizeof(byte)) {
                v[--k] = (byte)w;
            }
            return MakeUniversalPrimitiveInner(INTEGER, v);
        }

        /// <summary>Create a BIT STRING from the provided value. The number of "unused bits" is
        /// set to 0.</summary>
        /// <param name="buf"></param>
        /// <returns></returns>
        internal static AsnElt MakeBitString(byte[] buf)
        {
            int len = buf.Length;
            int off = 0;
            byte[] tmp = new byte[len + 1];
            Array.Copy(buf, off, tmp, 1, len);
            return MakeUniversalPrimitiveInner(BIT_STRING, tmp);
        }

        /// <summary>Create an OCTET STRING from the provided value.</summary>
        /// <param name="buf"></param>
        /// <returns></returns>
        public static AsnElt MakeBlob(byte[] buf)
        {
            int len = buf.Length;
            byte[] nval = new byte[len];
            Array.Copy(buf, 0, nval, 0, len);
            return MakePrimitiveInner(UNIVERSAL, OCTET_STRING, nval, 0, len);
        }

        /// <summary>Create a new constructed elements, by providing the relevant sub-elements.</summary>
        /// <param name="tagClass"></param>
        /// <param name="tagValue"></param>
        /// <param name="subs"></param>
        /// <returns></returns>
        private static AsnElt Make(int tagClass, int tagValue, params AsnElt[] subs)
        {
            if ((0 > tagClass) || (3 < tagClass)) {
                throw new AsnException("invalid tag class: " + tagClass);
            }
            if (0 > tagValue) {
                throw new AsnException("invalid tag value: " + tagValue);
            }
            AsnElt result = new AsnElt(tagClass, tagValue) {
                _objectBuffer = null,
                _objectOffset = 0,
                _objectLength = -1,
                _valueOffset = 0,
                _valueLength = -1,
                _hasEncodedHeader = false,
            };
            if (null == subs) {
                result._sub = new AsnElt[0];
            }
            else {
                result._sub = new AsnElt[subs.Length];
                Array.Copy(subs, 0, result._sub, 0, subs.Length);
            }
            return result;
        }

        /// <summary>Wrap an element into an explicit CONTEXT tag.</summary>
        /// <param name="tagValue"></param>
        /// <param name="x"></param>
        /// <returns></returns>
        public static AsnElt MakeExplicit(int tagValue, AsnElt x)
        {
            return Make(CONTEXT, tagValue, x);
        }

        /// <summary>Apply an implicit tag to a value. The source AsnElt object is unmodified;
        /// a new object is returned.</summary>
        /// <param name="tagClass"></param>
        /// <param name="tagValue"></param>
        /// <param name="x"></param>
        /// <returns></returns>
        internal static AsnElt MakeImplicit(int tagClass, int tagValue, AsnElt x)
        {
            if (x.IsConstructed) {
                return Make(tagClass, tagValue, x._sub);
            }
            AsnElt result = new AsnElt(tagClass, tagValue) {
                _objectOffset = 0,
                _objectLength = -1,
                _hasEncodedHeader = false,
                _sub = null
            };
            result._objectBuffer = x.GetValue(out result._valueOffset, out result._valueLength);
            return result;
        }

        /// <summary></summary>
        /// <param name="subs"></param>
        /// <returns></returns>
        internal static AsnElt MakeSequence(params AsnElt[] subs)
        {
            return Make(UNIVERSAL, SEQUENCE, subs);
        }

        /// <summary>Create a string of the provided type and contents. The string type is a
        /// universal tag value for one of the string or time types.</summary>
        /// <param name="type"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public static AsnElt MakeString(int type, string value)
        {
            VerifyChars(value.ToCharArray(), type);
            byte[] buf;
            switch (type) {
                case NumericString:
                case PrintableString:
                case UTCTime:
                case GeneralizedTime:
                case IA5String:
                case TeletexString:
                    buf = EncodeMono(value);
                    break;
                case UTF8String:
                    buf = EncodeUTF8(value);
                    break;
                case BMPString:
                    buf = EncodeUTF16(value);
                    break;
                case UniversalString:
                    buf = EncodeUTF32(value);
                    break;
                default:
                    throw new AsnException("unsupported string type: " + type);
            }
            return MakeUniversalPrimitiveInner(type, buf);
        }

        /// <summary></summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private static byte[] EncodeMono(string value)
        {
            byte[] result = new byte[value.Length];
            int k = 0;
            foreach (char c in value) {
                result[k++] = (byte)c;
            }
            return result;
        }

        /// <summary>Get the code point at offset 'off' in the string. Either one or two 'char'
        /// slots are used; 'off' is updated accordingly.</summary>
        /// <param name="str"></param>
        /// <param name="off"></param>
        /// <returns></returns>
        private static int CodePoint(string str, ref int off)
        {
            int result = str[off++];
            if (result >= 0xD800 && result < 0xDC00 && off < str.Length) {
                int d = str[off];
                if (d >= 0xDC00 && d < 0xE000) {
                    result = ((result & 0x3FF) << 10) + (d & 0x3FF) + 0x10000;
                    off++;
                }
            }
            return result;
        }

        /// <summary></summary>
        /// <param name="str"></param>
        /// <returns></returns>
        private static byte[] EncodeUTF8(string str)
        {
            int k = 0;
            int n = str.Length;
            MemoryStream ms = new MemoryStream();
            while (k < n) {
                int cp = CodePoint(str, ref k);
                if (cp < 0x80) {
                    ms.WriteByte((byte)cp);
                }
                else if (cp < 0x800) {
                    ms.WriteByte((byte)(0xC0 + (cp >> 6)));
                    ms.WriteByte((byte)(0x80 + (cp & 63)));
                }
                else if (cp < 0x10000) {
                    ms.WriteByte((byte)(0xE0 + (cp >> 12)));
                    ms.WriteByte((byte)(0x80 + ((cp >> 6) & 63)));
                    ms.WriteByte((byte)(0x80 + (cp & 63)));
                }
                else {
                    ms.WriteByte((byte)(0xF0 + (cp >> 18)));
                    ms.WriteByte((byte)(0x80 + ((cp >> 12) & 63)));
                    ms.WriteByte((byte)(0x80 + ((cp >> 6) & 63)));
                    ms.WriteByte((byte)(0x80 + (cp & 63)));
                }
            }
            return ms.ToArray();
        }

        /// <summary></summary>
        /// <param name="str"></param>
        /// <returns></returns>
        private static byte[] EncodeUTF16(string str)
        {
            byte[] buf = new byte[str.Length << 1];
            int k = 0;
            foreach (char c in str) {
                buf[k++] = (byte)(c >> 8);
                buf[k++] = (byte)c;
            }
            return buf;
        }

        /// <summary></summary>
        /// <param name="str"></param>
        /// <returns></returns>
        private static byte[] EncodeUTF32(string str)
        {
            int k = 0;
            int n = str.Length;
            MemoryStream ms = new MemoryStream();
            while (k < n) {
                int cp = CodePoint(str, ref k);
                ms.WriteByte((byte)(cp >> 24));
                ms.WriteByte((byte)(cp >> 16));
                ms.WriteByte((byte)(cp >> 8));
                ms.WriteByte((byte)cp);
            }
            return ms.ToArray();
        }

        /// <summary>Create a time value of the specified type (UTCTime or GeneralizedTime).</summary>
        /// <param name="type"></param>
        /// <param name="dt"></param>
        /// <returns></returns>
        private static AsnElt MakeTime(int type, DateTime dt)
        {
            dt = dt.ToUniversalTime();
            string str;
            switch (type) {
                case UTCTime:
                    int year = dt.Year;
                    if (year < 1950 || year >= 2050) {
                        throw new AsnException(String.Format("cannot encode year {0} as UTCTime", year));
                    }
                    year = year % 100;
                    str = String.Format("{0:d2}{1:d2}{2:d2}{3:d2}{4:d2}{5:d2}Z",
                        year, dt.Month, dt.Day, dt.Hour, dt.Minute, dt.Second);
                    break;
                case GeneralizedTime:
                    str = String.Format("{0:d4}{1:d2}{2:d2}{3:d2}{4:d2}{5:d2}",
                        dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, dt.Second);
                    int millis = dt.Millisecond;
                    if (millis != 0) {
                        if (millis % 100 == 0) {
                            str = String.Format("{0}.{1:d1}", str, millis / 100);
                        }
                        else if (millis % 10 == 0) {
                            str = String.Format("{0}.{1:d2}", str, millis / 10);
                        }
                        else {
                            str = String.Format("{0}.{1:d3}", str, millis);
                        }
                    }
                    str = str + "Z";
                    break;
                default:
                    throw new AsnException("unsupported time type: " + type);
            }
            return MakeString(type, str);
        }

        private static readonly IComparer<byte[]> COMPARER_LEXICOGRAPHIC = new ComparerLexicographic();

        /* Universal tag values. */
        public const int BOOLEAN = 1;
        public const int INTEGER = 2;
        public const int BIT_STRING = 3;
        public const int OCTET_STRING = 4;
        public const int NULL = 5;
        public const int OBJECT_IDENTIFIER = 6;
        public const int Object_Descriptor = 7;
        public const int EXTERNAL = 8;
        public const int REAL = 9;
        public const int ENUMERATED = 10;
        public const int EMBEDDED_PDV = 11;
        public const int UTF8String = 12;
        public const int RELATIVE_OID = 13;
        public const int SEQUENCE = 16;
        public const int SET = 17;
        public const int NumericString = 18;
        public const int PrintableString = 19;
        public const int T61String = 20;
        public const int TeletexString = 20;
        public const int VideotexString = 21;
        public const int IA5String = 22;
        public const int UTCTime = 23;
        public const int GeneralizedTime = 24;
        public const int GraphicString = 25;
        public const int VisibleString = 26;
        public const int GeneralString = 27;
        public const int UniversalString = 28;
        public const int CHARACTER_STRING = 29;
        public const int BMPString = 30;

        /* Tag classes. */
        public const int UNIVERSAL = 0;
        public const int APPLICATION = 1;
        public const int CONTEXT = 2;
        public const int PRIVATE = 3;

        private bool _hasEncodedHeader;
        private byte[] _objectBuffer;
        private int _objectOffset;
        private int _objectLength;
        private int _valueLength;
        private int _valueOffset;

        /* The sub-elements. This is null if this element is primitive.
         * DO NOT MODIFY this array. */
        private AsnElt[] _sub;

        // public static readonly AsnElt NULL_V = AsnElt.MakePrimitive(NULL, new byte[0]);
        // public static readonly AsnElt BOOL_TRUE = AsnElt.MakePrimitive(BOOLEAN, new byte[] { 0xFF });
        // public static readonly AsnElt BOOL_FALSE = AsnElt.MakePrimitive(BOOLEAN, new byte[] { 0x00 });

        private class ComparerLexicographic : IComparer<byte[]>
        {
            public int Compare(byte[] x, byte[] y)
            {
                int xLen = x.Length;
                int yLen = y.Length;
                int cLen = Math.Min(xLen, yLen);
                for (int index = 0; index < cLen; index++) {
                    if (x[index] != y[index]) {
                        return (int)x[index] - (int)y[index];
                    }
                }
                return xLen - yLen;
            }
        }
    }
}
