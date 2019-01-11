using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Rubeus.Asn1
{
    /// <summary>An AsnElt instance is an immutable representation of a decoded ASN.1 DER object.</summary>
    public partial class AsnElt
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
            this._tagClass = tagClass;
            this.TagValue = tagValue;
            return;
        }

        // UNUSED : internal AsnElt this[int index] { get }

        public int Count
        {
            get { return (null == _sub) ? 0 : _sub.Length; }
        }

        /// <summary>The encoded object length (complete with header).</summary>
        internal int EncodedLength
        {
            get
            {
                if (0 > _objectLength) {
                    int valueLength = ValueLength;
                    _objectLength = GetTagLength(TagValue) + GetLengthEncodedLength(valueLength) + valueLength;
                }
                return _objectLength;
            }
        }

        internal AsnElt FirstElement
        {
            get { return (0 < _sub.Length) ? _sub[0] : null; }
        }

        /// <summary>The "constructed" flag: true for an elements with sub-elements, false for
        /// a primitive element.</summary>
        internal bool IsConstructed
        {
            get { return (null != _sub); }
        }

        internal AsnElt SecondElement
        {
            get { return (1 < _sub.Length) ? _sub[1] : null; }
        }

        /// <summary>The tag class for this element.</summary>
        internal int TagClass
        {
            get { return _tagClass; }
        }

        /// <summary>Get a string representation of the tag class and value.</summary>
        internal string TagString
        {
            get { return TagToString(_tagClass, TagValue); }
        }

        /// <summary>The tag value for this element.</summary>
        internal int TagValue { get; set; }

        /// <summary>The value length. When the object is BER-encoded with an indefinite length,
        /// the value length includes all the sub-objects but NOT the formal null-tag marker.</summary>
        public int ValueLength
        {
            get
            {
                if (0 > _valueLength) {
                    if (IsConstructed) {
                        int valueLength = 0;
                        foreach (AsnElt item in EnumerateElements()) {
                            valueLength += item.EncodedLength;
                        }
                        _valueLength = valueLength;
                    }
                    else {
                        _valueLength = _objectBuffer.Length;
                    }
                }
                return _valueLength;
            }
        }

        //public AsnElt[] Sub
        //{
        //    get { return _sub; }
        //    private set { _sub = value; }
        //}

        /// <summary>Check that this element is constructed. An exception is thrown if this is not the case.</summary>
        private void AssertConstructed()
        {
            if (!IsConstructed) {
                throw new AsnException("not constructed");
            }
        }

        public void AssertNullValue()
        {
            AssertPrimitive();
            if (0 != ValueLength) {
                throw new AsnException(String.Format("invalid NULL (length = {0})", ValueLength));
            }
        }

        private static void AssertOffsetValue(int offset, int limitExcluded)
        {
            if (offset >= limitExcluded) {
                throw new AsnException("offset overflow");
            }
        }

        /// <summary>Check that this element is primitive. An exception is thrown if this is not the case.</summary>
        private void AssertPrimitive()
        {
            if (IsConstructed) {
                throw new AsnException("not primitive");
            }
        }

        // UNUSED : internal void AssertItemsCountEquals(int expected)

        // UNUSED : internal void AssertItemsCountAtLeast(int expected)

        // UNUSED : internal void AssertItemsCountAtMost(int expected)

        /// <summary>Check that the tag has the specified class and value.</summary>
        /// <param name="tagClass"></param>
        /// <param name="tagValue"></param>
        private void AssertTagClassAndValue(int tagClass, int tagValue)
        {
            if ((_tagClass != tagClass) || (TagValue != tagValue)) {
                throw new AsnException("unexpected tag: " + TagString);
            }
        }

        /// <summary>Check that the tag is UNIVERSAL with the provided value.</summary>
        /// <param name="tagValue"></param>
        private void AssertUniveralTagValue(int tagValue)
        {
            AssertTagClassAndValue(UNIVERSAL, tagValue);
        }

        /// <summary>Get a copy of the value as a freshly allocated array.</summary>
        /// <returns></returns>
        internal byte[] CopyValue()
        {
            byte[] result = new byte[ValueLength];
            EncodeValue(0, result.Length, result, 0);
            return result;
        }

        /// <summary>Copy a value chunk. The provided offset ('off') and length ('len') define
        /// the chunk to copy; the offset is relative to the value start(first value byte has
        /// offset 0). If the requested window exceeds the value boundaries, an exception is
        /// thrown.</summary>
        /// <param name="fromOffset"></param>
        /// <param name="fromLength"></param>
        /// <param name="toBuffer"></param>
        /// <param name="toOffset"></param>
        public void CopyValueChunk(int fromOffset, int fromLength, byte[] toBuffer, int toOffset)
        {
            int valueLength = ValueLength;
            if ((0 > fromOffset) || (0 > fromLength) || (fromLength > (valueLength - fromOffset))) {
                throw new AsnException(String.Format(
                    "invalid value window {0}:{1} (value length = {2})", fromOffset, fromLength, valueLength));
            }
            EncodeValue(fromOffset, fromOffset + fromLength, toBuffer, toOffset);
        }

        /// <summary>Decode an ASN.1 object. The provided buffer is internally copied. Trailing
        /// garbage is not tolerated.</summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static AsnElt Decode(byte[] buffer)
        {
            return Decode(buffer, 0, buffer.Length, true);
        }

        /// <summary>Decode an ASN.1 object. The provided buffer is internally copied. Trailing
        /// garbage is not tolerated.</summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static AsnElt Decode(byte[] buffer, int offset, int length)
        {
            return Decode(buffer, offset, length, true);
        }

        /// <summary>Decode an ASN.1 object. The provided buffer is internally copied. If 'exactLength'
        /// is true, then trailing garbage is not tolerated(it triggers an exception).</summary>
        /// <param name="buffer"></param>
        /// <param name="exactLength"></param>
        /// <returns></returns>
        public static AsnElt Decode(byte[] buffer, bool exactLength)
        {
            return Decode(buffer, 0, buffer.Length, exactLength);
        }

        /// <summary>Decode an ASN.1 object. The provided buffer is internally copied. If 'exactLength'
        /// is true, then trailing garbage is not tolerated(it triggers an exception).</summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        /// <param name="exactLength"></param>
        /// <returns></returns>
        public static AsnElt Decode(byte[] buffer, int offset, int length, bool exactLength)
        {
            int tagClass, tagValue, valueOffset, valueLength;
            bool constructed;
            int objectLength = Decode(buffer, offset, length, out tagClass, out tagValue,
                out constructed, out valueOffset, out valueLength);
            if (exactLength && (objectLength != length)) {
                throw new AsnException("trailing garbage");
            }
            byte[] nbuf = new byte[objectLength];
            Array.Copy(buffer, offset, nbuf, 0, objectLength);
            return DecodeNoCopy(nbuf, 0, objectLength);
        }

        /// <summary>Decode the tag and length, and get the value offset and length. Returned
        /// value if the total object length.Note: when an object has indefinite length, the
        /// terminated "null tag" will NOT be considered part of the "value length".</summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="maxLength"></param>
        /// <param name="tagClass"></param>
        /// <param name="tagValue"></param>
        /// <param name="constructed"></param>
        /// <param name="valueOffset"></param>
        /// <param name="valueLength"></param>
        /// <returns></returns>
        private static int Decode(byte[] buffer, int offset, int maxLength, out int tagClass,
            out int tagValue, out bool constructed, out int valueOffset, out int valueLength)
        {
            int lim = offset + maxLength;
            int orig = offset;

            /* Decode tag. */
            AssertOffsetValue(offset, lim);
            tagValue = buffer[offset++];
            constructed = (tagValue & 0x20) != 0;
            tagClass = tagValue >> 6;
            tagValue &= 0x1F;
            if (0x1F == tagValue) {
                tagValue = 0;
                while (true) {
                    AssertOffsetValue(offset, lim);
                    int c = buffer[offset++];
                    if (tagValue > 0xFFFFFF) {
                        throw new AsnException("tag value overflow");
                    }
                    tagValue = (tagValue << 7) | (c & 0x7F);
                    if ((c & 0x80) == 0) { break; }
                }
            }

            /* Decode length. */
            AssertOffsetValue(offset, lim);
            int vlen = buffer[offset++];
            if (0x80 == vlen) {
                /* Indefinite length. This is not strict DER, bu we allow it nonetheless; we must
                 * check that the value was tagged as constructed, though. */
                vlen = -1;
                if (!constructed) {
                    throw new AsnException("indefinite length but not constructed");
                }
            }
            else if (0x80 < vlen) {
                int lenlen = vlen - 0x80;
                AssertOffsetValue(offset + lenlen - 1, lim);
                vlen = 0;
                while (lenlen-- > 0) {
                    if (vlen > 0x7FFFFF) {
                        throw new AsnException("length overflow");
                    }
                    vlen = (vlen << 8) + buffer[offset++];
                }
            }

            /* Length was decoded, so the value starts here. */
            valueOffset = offset;

            /* If length is indefinite then we must explore sub-objects to get the value length. */
            if (0 > vlen) {
                while (true) {
                    int tc2, tv2, valOff2, valLen2;
                    bool cons2;
                    int slen = Decode(buffer, offset, lim - offset, out tc2, out tv2, out cons2, out valOff2, out valLen2);
                    if (tc2 == 0 && tv2 == 0) {
                        if (cons2 || valLen2 != 0) { throw new AsnException("invalid null tag"); }
                        valueLength = offset - valueOffset;
                        offset += slen;
                        break;
                    }
                    offset += slen;
                }
            }
            else {
                if (vlen > (lim - offset)) {
                    throw new AsnException("value overflow");
                }
                offset += vlen;
                valueLength = offset - valueOffset;
            }
            return offset - orig;
        }

        /// <summary>Internal recursive decoder. The provided array is NOT copied. Trailing garbage
        /// is ignored(caller should use the 'objLen' field to learn the total object length).</summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        private static AsnElt DecodeNoCopy(byte[] buffer, int offset, int length)
        {
            int tagClass, tagValue, valueOffset, vauleLength;
            bool constructed;
            int objectLength = Decode(buffer, offset, length, out tagClass, out tagValue,
                out constructed, out valueOffset, out vauleLength);
            AsnElt result = new AsnElt(tagClass, tagValue) {
                _objectBuffer = buffer,
                _objectOffset = offset,
                _objectLength = objectLength,
                _valueOffset = valueOffset,
                _valueLength = vauleLength,
                _hasEncodedHeader = true
            };
            if (constructed) {
                List<AsnElt> subs = new List<AsnElt>();
                offset = valueOffset;
                int lim = valueOffset + vauleLength;
                while (offset < lim) {
                    AsnElt b = DecodeNoCopy(buffer, offset, lim - offset);
                    offset += b._objectLength;
                    subs.Add(b);
                }
                result._sub = subs.ToArray();
            }
            else {
                result._sub = null;
            }
            return result;
        }

        /// <summary>Encode this object into a newly allocated array.</summary>
        /// <returns></returns>
        internal byte[] Encode()
        {
            byte[] r = new byte[EncodedLength];
            Encode(r, 0);
            return r;
        }

        /// <summary>Encode this object into the provided array. Encoded object length is returned.</summary>
        /// <param name="dst"></param>
        /// <param name="off"></param>
        /// <returns></returns>
        private int Encode(byte[] dst, int off)
        {
            return Encode(0, Int32.MaxValue, dst, off);
        }

        /// <summary>Encode this object into the provided array. Only bytes at offset between
        /// 'start' (inclusive) and 'end' (exclusive) are actually written.The number of written
        /// bytes is returned.Offsets are relative to the object start (first tag byte).</summary>
        /// <param name="startInclusive"></param>
        /// <param name="endExclusive"></param>
        /// <param name="buffer"></param>
        /// <param name="bufferOffset"></param>
        /// <returns></returns>
        private int Encode(int startInclusive, int endExclusive, byte[] buffer, int bufferOffset)
        {
            if (0 > startInclusive) {
                throw new ArgumentOutOfRangeException("startInclusive");
            }
            if (startInclusive >= endExclusive) {
                throw new ArgumentOutOfRangeException("endExclusive");
            }
            // If the encoded value is already known, then we just dump it.
            if (_hasEncodedHeader) {
                int objectBufferStartOffset = _objectOffset + Math.Max(0, startInclusive);
                int objectBufferEndOffset = _objectOffset + Math.Min(_objectLength, endExclusive);
                int length = objectBufferEndOffset - objectBufferStartOffset;
                if (0 < length) {
                    Array.Copy(_objectBuffer, objectBufferStartOffset, buffer, bufferOffset, length);
                    return length;
                }
                return 0;
            }
            int encodedLength = 0;
            // Encode tag.
            int headerByte = (_tagClass << 6) + (IsConstructed ? 0x20 : 0x00);
            if (0x1F > TagValue) {
                headerByte |= (TagValue & 0x1F);
                if (startInclusive <= encodedLength && encodedLength < endExclusive) {
                    buffer[bufferOffset++] = (byte)headerByte;
                }
                encodedLength++;
            }
            else {
                headerByte |= 0x1F;
                if (startInclusive <= encodedLength && encodedLength < endExclusive) {
                    buffer[bufferOffset++] = (byte)headerByte;
                }
                encodedLength++;
                int k = 0;
                for (int v = TagValue; v > 0; v >>= 7, k += 7) { }
                while (k > 0) {
                    k -= 7;
                    int v = (TagValue >> k) & 0x7F;
                    if (k != 0) {
                        v |= 0x80;
                    }
                    if (startInclusive <= encodedLength && encodedLength < endExclusive) {
                        buffer[bufferOffset++] = (byte)v;
                    }
                    encodedLength++;
                }
            }

            /* Encode length. */
            int valueLength = ValueLength;
            if (0x80 > valueLength) {
                if (startInclusive <= encodedLength && encodedLength < endExclusive) {
                    buffer[bufferOffset++] = (byte)valueLength;
                }
                encodedLength++;
            }
            else {
                int k = 0;
                for (int v = valueLength; v > 0; v >>= 8, k += 8) { }
                if (startInclusive <= encodedLength && encodedLength < endExclusive) {
                    buffer[bufferOffset++] = (byte)(0x80 + (k >> 3));
                }
                encodedLength++;
                while (k > 0) {
                    k -= 8;
                    if (startInclusive <= encodedLength && encodedLength < endExclusive) {
                        buffer[bufferOffset++] = (byte)(valueLength >> k);
                    }
                    encodedLength++;
                }
            }

            /* Encode value. We must adjust the start/end window to make it relative to the value. */
            EncodeValue(startInclusive - encodedLength, endExclusive - encodedLength, buffer, bufferOffset);
            encodedLength += valueLength;

            // Compute copied length.
            return Math.Max(0, Math.Min(encodedLength, endExclusive) - Math.Max(0, startInclusive));
        }

        /// <summary>Encode the value into the provided buffer. Only value bytes at offsets
        /// between 'start' (inclusive) and 'end' (exclusive) are written.Actual number of
        /// written bytes is returned.Offsets are relative to the start of the value.</summary>
        /// <param name="startInclusive"></param>
        /// <param name="endExclusive"></param>
        /// <param name="buffer"></param>
        /// <param name="bufferOffset"></param>
        /// <returns></returns>
        private int EncodeValue(int startInclusive, int endExclusive, byte[] buffer, int bufferOffset)
        {
            if (0 > startInclusive) {
                throw new IndexOutOfRangeException("startInclusive");
            }
            if (startInclusive > endExclusive) {
                throw new IndexOutOfRangeException("endExclusive");
            }
            int initialBufferOffset = bufferOffset;
            if (null == _objectBuffer) {
                int k = 0;
                foreach (AsnElt item in this.EnumerateElements()) {
                    int slen = item.EncodedLength;
                    bufferOffset += item.Encode(startInclusive - k, endExclusive - k, buffer, bufferOffset);
                    k += slen;
                }
            }
            else {
                int from = Math.Max(0, startInclusive);
                int to = Math.Min(_valueLength, endExclusive);
                int len = to - from;
                if (0 < len) {
                    Array.Copy(_objectBuffer, _valueOffset + from, buffer, bufferOffset, len);
                    bufferOffset += len;
                }
            }
            return bufferOffset - initialBufferOffset;
        }

        /// <summary>An enumerator of the sub-elements of the object.</summary>
        /// <returns></returns>
        public IEnumerable<AsnElt> EnumerateElements()
        {
            foreach (AsnElt item in _sub) { yield return item; }
            yield break;
        }

        /// <summary>Interpret the value as a BIT STRING. The bits are returned, with the
        /// "ignored bits" cleared.The actual bit length is written in 'bitLength'.</summary>
        /// <param name="bitLength"></param>
        /// <returns></returns>
        public byte[] GetBitString(out int bitLength)
        {
            AssertPrimitive();
            int valueLength = ValueLength;
            if (0 == valueLength) {
                throw new AsnException("invalid BIT STRING (length = 0)");
            }
            int headerByte = ValueByte(0);
            if ((7 < headerByte) || ((1 == valueLength) && (0 != headerByte))) {
                throw new AsnException(String.Format("invalid BIT STRING (start = 0x{0:X2})", headerByte));
            }
            byte[] result = new byte[valueLength - 1];
            CopyValueChunk(1, valueLength - 1, result, 0);
            if (valueLength > 1) {
                result[result.Length - 1] &= (byte)(0xFF << headerByte);
            }
            bitLength = (result.Length << 3) - headerByte;
            return result;
        }

        /// <summary>Interpret the value as a BOOLEAN.</summary>
        /// <returns></returns>
        public bool GetBoolean()
        {
            AssertPrimitive();
            int valueLength = ValueLength;
            if (valueLength != 1) {
                throw new AsnException(String.Format("invalid BOOLEAN (length = {0})", valueLength));
            }
            return ValueByte(0) != 0;
        }

        /// <summary>Interpret the value as a BIT STRING. The bits are returned, with the
        /// "ignored bits" cleared.</summary>
        /// <returns></returns>
        public byte[] GetBitString()
        {
            int bitLength;
            return GetBitString(out bitLength);
        }

        /// <summary>Interpret the value as an INTEGER. An exception is thrown if the value
        /// is outside of the provided range or does not fit in a 'long'.</summary>
        /// <returns></returns>
        public long GetInteger(long min = long.MinValue, long max = long.MaxValue)
        {
            AssertPrimitive();
            int valueLength = ValueLength;
            if (0 == valueLength) {
                throw new AsnException("invalid INTEGER (length = 0)");
            }
            int mostSignificantValueByte = ValueByte(0);
            long result;
            if (0 != (mostSignificantValueByte & 0x80)) {
                // This is a negative number.
                result = -1;
                for (int k = 0; k < valueLength; k++) {
                    if (result < ((-1L) << 55)) {
                        throw new AsnException("integer overflow (negative)");
                    }
                    result = (result << 8) + (long)ValueByte(k);
                }
            }
            else {
                // This is a positive number.
                result = 0;
                for (int k = 0; k < valueLength; k++) {
                    if (result >= (1L << 55)) {
                        throw new AsnException("integer overflow (positive)");
                    }
                    result = (result << 8) + (long)ValueByte(k);
                }
            }
            if ((result < min) || (result > max)) {
                throw new AsnException("integer out of allowed range");
            }
            return result;
        }

        /// <summary>Interpret the value as an INTEGER. Return its hexadecimal representation
        /// (uppercase), preceded by a '0x' or '-0x' header, depending on the integer sign.
        /// The number of hexadecimal digits is even.Leading zeroes are returned(but one may
        /// remain, to ensure an even number of digits). If the integer has value 0, then 0x00
        /// is returned.</summary>
        /// <returns></returns>
        public string GetIntegerHex()
        {
            AssertPrimitive();
            int valueLength = ValueLength;
            if (0 == valueLength) {
                throw new AsnException("invalid INTEGER (length = 0)");
            }
            StringBuilder builder = new StringBuilder();
            byte[] tmp = CopyValue();
            if (0x80 <= tmp[0]) {
                builder.Append('-');
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
            builder.Append("0x");
            while (k < tmp.Length) {
                builder.AppendFormat("{0:X2}", tmp[k++]);
            }
            return builder.ToString();
        }

        /// <summary>Get the encoded length for a length.</summary>
        /// <param name="len"></param>
        /// <returns></returns>
        private static int GetLengthEncodedLength(int len)
        {
            if (0x80 > len) { return 1; }
            int result = 1;
            while (0 < len) {
                result++;
                len >>= 8;
            }
            return result;
        }

        /// <summary>Interpret the value as an OCTET STRING. The value bytes are returned.
        /// This method supports constructed values and performs the reassembly.</summary>
        /// <returns></returns>
        public byte[] GetOctetString()
        {
            int len = GetOctetString(null, 0);
            byte[] r = new byte[len];
            GetOctetString(r, 0);
            return r;
        }

        /// <summary>Interpret the value as an OCTET STRING. The value bytes are written in
        /// dst[], starting at offset 'off', and the total value length is returned.If 'dst'
        /// is null, then no byte is written anywhere, but the total length is still returned.
        /// This method supports constructed values and performs the reassembly.</summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <returns></returns>
        public int GetOctetString(byte[] buffer, int offset)
        {
            if (IsConstructed) {
                int initialOffset = offset;
                foreach (AsnElt item in this.EnumerateElements()) {
                    item.AssertUniveralTagValue(AsnElt.OCTET_STRING);
                    offset += item.GetOctetString(buffer, offset);
                }
                return offset - initialOffset;
            }
            if (null != buffer) {
                return EncodeValue(0, Int32.MaxValue, buffer, offset);
            }
            return ValueLength;
        }

        /// <summary>Get the encoded length for a tag.</summary>
        /// <param name="tagValue"></param>
        /// <returns></returns>
        private static int GetTagLength(int tagValue)
        {
            if (0x1F >= tagValue) { return 1; }
            int result = 1;
            while (0 < tagValue) {
                result++;
                tagValue >>= 7;
            }
            return result;
        }

        private static string TagToString(int tagClass, int tagValue)
        {
            switch (tagClass) {
                case APPLICATION:
                    return "APPLICATION:" + tagValue;
                case CONTEXT:
                    return "CONTEXT:" + tagValue;
                case PRIVATE:
                    return "PRIVATE:" + tagValue;
                case UNIVERSAL:
                    switch (tagValue) {
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
                            return String.Format("UNIVERSAL:" + tagValue);
                    }
                default:
                    return string.Format("INVALID:{0}/{1}", tagClass, tagValue);
            }
        }

        /// <summary>Get a specific byte from the value. This provided offset is relative to
        /// the value start (first value byte has offset 0).</summary>
        /// <param name="offset"></param>
        /// <returns></returns>
        public int ValueByte(int offset)
        {
            if (0 > offset) {
                throw new AsnException("invalid value offset: " + offset);
            }
            if (null == _objectBuffer) {
                int k = 0;
                foreach (AsnElt item in this.EnumerateElements()) {
                    int slen = item.EncodedLength;
                    if ((k + slen) > offset) {
                        return item.ValueByte(offset - k);
                    }
                }
            }
            else {
                if (offset < _valueLength) {
                    return _objectBuffer[_valueOffset + offset];
                }
            }
            throw new AsnException(String.Format("invalid value offset {0} (length = {1})",
                offset, ValueLength));
        }

        // ==============================================================================

        /* Interpret the value as an OBJECT IDENTIFIER, and return it (in decimal-dotted string
         * format). */
        public string GetOID()
        {
            AssertPrimitive();
            if (0 == _valueLength) {
                throw new AsnException("zero-length OID");
            }
            int v = _objectBuffer[_valueOffset];
            if (120 <= v) {
                throw new AsnException("invalid OID: first byte = " + v);
            }
            StringBuilder builder = new StringBuilder();
            builder.Append(v / 40);
            builder.Append('.');
            builder.Append(v % 40);
            long acc = 0;
            bool uv = false;
            for (int i = 1; i < _valueLength; i++) {
                v = _objectBuffer[_valueOffset + i];
                if ((acc >> 56) != 0) {
                    throw new AsnException("invalid OID: integer overflow");
                }
                acc = (acc << 7) + (long)(v & 0x7F);
                if ((v & 0x80) == 0) {
                    builder.Append('.');
                    builder.Append(acc);
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
            return builder.ToString();
        }

        /* Get the object value as a string. The string type is inferred from the tag. */
        public string GetString()
        {
            if (_tagClass != UNIVERSAL)
            {
                throw new AsnException(String.Format("cannot infer string type: {0}:{1}", _tagClass, TagValue));
            }
            return GetString(TagValue);
        }

        /* Get the object value as a string. The string type is provided (universal tag value).
         * Supported string types include NumericString, PrintableString, IA5String, TeletexString
         * (interpreted as ISO-8859-1), UTF8String, BMPString and UniversalString; the "time types"
         * (UTCTime and GeneralizedTime) are also supported, though, in their case, the internal
         * contents are not checked (they are decoded as PrintableString). */
        public string GetString(int type)
        {
            AssertPrimitive();
            switch (type)
            {
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

        static string DecodeMono(byte[] buf, int off, int len, int type)
        {
            char[] tc = new char[len];
            for (int i = 0; i < len; i++)
            {
                tc[i] = (char)buf[off + i];
            }
            VerifyChars(tc, type);
            return new string(tc);
        }

        static string DecodeUTF8(byte[] buf, int off, int len)
        {
            /* Skip BOM.*/
            if (len >= 3 && buf[off] == 0xEF
                && buf[off + 1] == 0xBB && buf[off + 2] == 0xBF)
            {
                off += 3;
                len -= 3;
            }
            char[] tc = null;
            for (int k = 0; k < 2; k++)
            {
                int tcOff = 0;
                for (int i = 0; i < len; i++)
                {
                    int c = buf[off + i];
                    int e;
                    if (c < 0x80)
                    {
                        e = 0;
                    }
                    else if (c < 0xC0)
                    {
                        throw BadByte(c, UTF8String);
                    }
                    else if (c < 0xE0)
                    {
                        c &= 0x1F;
                        e = 1;
                    }
                    else if (c < 0xF0)
                    {
                        c &= 0x0F;
                        e = 2;
                    }
                    else if (c < 0xF8)
                    {
                        c &= 0x07;
                        e = 3;
                    }
                    else
                    {
                        throw BadByte(c, UTF8String);
                    }
                    while (e-- > 0)
                    {
                        if (++i >= len)
                        {
                            throw new AsnException("invalid UTF-8 string");
                        }
                        int d = buf[off + i];
                        if (d < 0x80 || d > 0xBF)
                        {
                            throw BadByte(d, UTF8String);
                        }
                        c = (c << 6) + (d & 0x3F);
                    }
                    if (c > 0x10FFFF)
                    {
                        throw BadChar(c, UTF8String);
                    }
                    if (c > 0xFFFF)
                    {
                        c -= 0x10000;
                        int hi = 0xD800 + (c >> 10);
                        int lo = 0xDC00 + (c & 0x3FF);
                        if (tc != null)
                        {
                            tc[tcOff] = (char)hi;
                            tc[tcOff + 1] = (char)lo;
                        }
                        tcOff += 2;
                    }
                    else
                    {
                        if (tc != null)
                        {
                            tc[tcOff] = (char)c;
                        }
                        tcOff++;
                    }
                }
                if (tc == null)
                {
                    tc = new char[tcOff];
                }
            }
            VerifyChars(tc, UTF8String);
            return new string(tc);
        }

        static string DecodeUTF16(byte[] buf, int off, int len)
        {
            if ((len & 1) != 0)
            {
                throw new AsnException("invalid UTF-16 string: length = " + len);
            }
            len >>= 1;
            if (len == 0)
            {
                return "";
            }
            bool be = true;
            int hi = buf[off];
            int lo = buf[off + 1];
            if (hi == 0xFE && lo == 0xFF)
            {
                off += 2;
                len--;
            }
            else if (hi == 0xFF && lo == 0xFE)
            {
                off += 2;
                len--;
                be = false;
            }
            char[] tc = new char[len];
            for (int i = 0; i < len; i++)
            {
                int b0 = buf[off++];
                int b1 = buf[off++];
                if (be)
                {
                    tc[i] = (char)((b0 << 8) + b1);
                }
                else
                {
                    tc[i] = (char)((b1 << 8) + b0);
                }
            }
            VerifyChars(tc, BMPString);
            return new string(tc);
        }

        static string DecodeUTF32(byte[] buf, int off, int len)
        {
            if ((len & 3) != 0)
            {
                throw new AsnException("invalid UTF-32 string: length = " + len);
            }
            len >>= 2;
            if (len == 0)
            {
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
            for (int k = 0; k < 2; k++)
            {
                int tcOff = 0;
                for (int i = 0; i < len; i++)
                {
                    uint b0 = buf[off + 0];
                    uint b1 = buf[off + 1];
                    uint b2 = buf[off + 2];
                    uint b3 = buf[off + 3];
                    uint c;
                    if (be)
                    {
                        c = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
                    }
                    else
                    {
                        c = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
                    }
                    if (c > 0x10FFFF)
                    {
                        throw BadChar((int)c, UniversalString);
                    }
                    if (c > 0xFFFF)
                    {
                        c -= 0x10000;
                        int hi = 0xD800 + (int)(c >> 10);
                        int lo = 0xDC00 + (int)(c & 0x3FF);
                        if (tc != null)
                        {
                            tc[tcOff] = (char)hi;
                            tc[tcOff + 1] = (char)lo;
                        }
                        tcOff += 2;
                    }
                    else
                    {
                        if (tc != null)
                        {
                            tc[tcOff] = (char)c;
                        }
                        tcOff++;
                    }
                }
                if (tc == null)
                {
                    tc = new char[tcOff];
                }
            }
            VerifyChars(tc, UniversalString);
            return new string(tc);
        }

        static void VerifyChars(char[] tc, int type)
        {
            switch (type)
            {
                case NumericString:
                    foreach (char c in tc)
                    {
                        if (!IsNum(c))
                        {
                            throw BadChar(c, type);
                        }
                    }
                    return;
                case PrintableString:
                case UTCTime:
                case GeneralizedTime:
                    foreach (char c in tc)
                    {
                        if (!IsPrintable(c))
                        {
                            throw BadChar(c, type);
                        }
                    }
                    return;
                case IA5String:
                    foreach (char c in tc)
                    {
                        if (!IsIA5(c))
                        {
                            throw BadChar(c, type);
                        }
                    }
                    return;
                case TeletexString:
                    foreach (char c in tc)
                    {
                        if (!IsLatin1(c))
                        {
                            throw BadChar(c, type);
                        }
                    }
                    return;
            }

            /* For Unicode string types (UTF-8, BMP...). */
            for (int i = 0; i < tc.Length; i++)
            {
                int c = tc[i];
                if (c >= 0xFDD0 && c <= 0xFDEF)
                {
                    throw BadChar(c, type);
                }
                if (c == 0xFFFE || c == 0xFFFF)
                {
                    throw BadChar(c, type);
                }
                if (c < 0xD800 || c > 0xDFFF)
                {
                    continue;
                }
                if (c > 0xDBFF)
                {
                    throw BadChar(c, type);
                }
                int hi = c & 0x3FF;
                if (++i >= tc.Length)
                {
                    throw BadChar(c, type);
                }
                c = tc[i];
                if (c < 0xDC00 || c > 0xDFFF)
                {
                    throw BadChar(c, type);
                }
                int lo = c & 0x3FF;
                c = 0x10000 + lo + (hi << 10);
                if ((c & 0xFFFE) == 0xFFFE)
                {
                    throw BadChar(c, type);
                }
            }
        }

        static bool IsNum(int c)
        {
            return c == ' ' || (c >= '0' && c <= '9');
        }

        internal static bool IsPrintable(int c)
        {
            if (c >= 'A' && c <= 'Z')
            {
                return true;
            }
            if (c >= 'a' && c <= 'z')
            {
                return true;
            }
            if (c >= '0' && c <= '9')
            {
                return true;
            }
            switch (c)
            {
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

        static bool IsIA5(int c)
        {
            return c < 128;
        }

        static bool IsLatin1(int c)
        {
            return c < 256;
        }

        static AsnException BadByte(int c, int type)
        {
            return new AsnException(String.Format(
                "unexpected byte 0x{0:X2} in string of type {1}", c, type));
        }

        static AsnException BadChar(int c, int type)
        {
            return new AsnException(String.Format(
                "unexpected character U+{0:X4} in string of type {1}", c, type));
        }

        /* Decode the value as a date/time. Returned object is in UTC. Type of date is inferred7
         * from the tag value. */
        public DateTime GetTime()
        {
            if (_tagClass != UNIVERSAL)
            {
                throw new AsnException(String.Format("cannot infer date type: {0}:{1}", _tagClass, TagValue));
            }
            return GetTime(TagValue);
        }

        /* Decode the value as a date/time. Returned object is in UTC. The time string type is
         * provided as parameter (UTCTime or GeneralizedTime). */
        public DateTime GetTime(int type)
        {
            bool isGen = false;
            switch (type)
            {
                case UTCTime:
                    break;
                case GeneralizedTime:
                    isGen = true;
                    break;
                default:
                    throw new AsnException(
                        "unsupported date type: " + type);
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
             * uses four digits. UTCTime years map to 1950..2049 (00 is
             * 2000).
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
            foreach (char c in s)
            {
                if (c >= '0' && c <= '9')
                {
                    continue;
                }
                if (c == '.' || c == '+' || c == '-' || c == 'Z')
                {
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
            if (s.EndsWith("Z"))
            {
                s = s.Substring(0, s.Length - 1);
            }
            else
            {
                int j = s.IndexOf('+');
                if (j < 0)
                {
                    j = s.IndexOf('-');
                    negZ = true;
                }
                if (j < 0)
                {
                    noTZ = true;
                }
                else
                {
                    string t = s.Substring(j + 1);
                    s = s.Substring(0, j);
                    if (t.Length != 4)
                    {
                        throw BadTime(type, orig);
                    }
                    tzHours = Dec2(t, 0, ref good);
                    tzMinutes = Dec2(t, 2, ref good);
                    if (tzHours < 0 || tzHours > 23 || tzMinutes < 0 || tzMinutes > 59)
                    {
                        throw BadTime(type, orig);
                    }
                }
            }

            /* Lack of time zone is allowed only for GeneralizedTime. */
            if (noTZ && !isGen)
            {
                throw BadTime(type, orig);
            }

            /* Parse the date elements. */
            if (s.Length < 4)
            {
                throw BadTime(type, orig);
            }
            int year = Dec2(s, 0, ref good);
            if (isGen)
            {
                year = year * 100 + Dec2(s, 2, ref good);
                s = s.Substring(4);
            }
            else
            {
                if (year < 50)
                {
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
            if (isGen)
            {
                second = Dec2(s, 8, ref good);
                if (s.Length >= 12 && s[10] == '.')
                {
                    s = s.Substring(11);
                    foreach (char c in s)
                    {
                        if (c < '0' || c > '9')
                        {
                            good = false;
                            break;
                        }
                    }
                    s += "0000";
                    millisecond = 10 * Dec2(s, 0, ref good) + Dec2(s, 2, ref good) / 10;
                }
                else if (s.Length != 10)
                {
                    good = false;
                }
            }
            else
            {
                switch (s.Length)
                {
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
            if (!good)
            {
                throw BadTime(type, orig);
            }

            /* Leap seconds are not supported by .NET, so we claim they do not occur. 
             */
            if (second == 60)
            {
                second = 59;
            }

            /* .NET implementation performs all the checks (including checks on month length
             * depending on year, as per the proleptic Gregorian calendar). */
            try
            {
                if (noTZ)
                {
                    DateTime dt = new DateTime(year, month, day, hour, minute, second, millisecond,
                        DateTimeKind.Local);
                    return dt.ToUniversalTime();
                }
                TimeSpan tzOff = new TimeSpan(tzHours, tzMinutes, 0);
                if (negZ)
                {
                    tzOff = tzOff.Negate();
                }
                DateTimeOffset dto = new DateTimeOffset(year, month, day, hour, minute, second,
                    millisecond, tzOff);
                return dto.UtcDateTime;
            }
            catch (Exception e)
            {
                throw BadTime(type, orig, e);
            }
        }

        static int Dec2(string s, int off, ref bool good)
        {
            if (off < 0 || off >= (s.Length - 1))
            {
                good = false;
                return -1;
            }
            char c1 = s[off];
            char c2 = s[off + 1];
            if (c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9')
            {
                good = false;
                return -1;
            }
            return 10 * (c1 - '0') + (c2 - '0');
        }

        static AsnException BadTime(int type, string s)
        {
            return BadTime(type, s, null);
        }

        static AsnException BadTime(int type, string s, Exception e)
        {
            string tt = (type == UTCTime) ? "UTCTime" : "GeneralizedTime";
            string msg = String.Format("invalid {0} string: '{1}'", tt, s);
            if (e == null)
            {
                return new AsnException(msg);
            }
            else
            {
                return new AsnException(msg, e);
            }
        }

        /* =============================================================== */

        /* Create a new element for a primitive value. The provided buffer is internally copied. */
        public static AsnElt MakePrimitive(int tagValue, byte[] val)
        {
            return MakePrimitive(UNIVERSAL, tagValue, val, 0, val.Length);
        }

        /* Create a new element for a primitive value. The provided buffer is internally copied */
        public static AsnElt MakePrimitive(int tagValue, byte[] val, int off, int len)
        {
            return MakePrimitive(UNIVERSAL, tagValue, val, off, len);
        }

        /* Create a new element for a primitive value. The provided buffer is internally copied. */
        public static AsnElt MakePrimitive(int tagClass, int tagValue, byte[] val)
        {
            return MakePrimitive(tagClass, tagValue, val, 0, val.Length);
        }

        /* Create a new element for a primitive value. The provided buffer is internally copied. */
        public static AsnElt MakePrimitive(int tagClass, int tagValue,
            byte[] val, int off, int len)
        {
            byte[] nval = new byte[len];
            Array.Copy(val, off, nval, 0, len);
            return MakePrimitiveInner(tagClass, tagValue, nval, 0, len);
        }

        /* Like MakePrimitive(), but the provided array is NOT copied. This is for other factory
         * methods that already allocate a new array. */
        static AsnElt MakePrimitiveInner(int tagValue, byte[] val)
        {
            return MakePrimitiveInner(UNIVERSAL, tagValue, val, 0, val.Length);
        }

        static AsnElt MakePrimitiveInner(int tagValue, byte[] val, int off, int len)
        {
            return MakePrimitiveInner(UNIVERSAL, tagValue, val, off, len);
        }

        static AsnElt MakePrimitiveInner(int tagClass, int tagValue, byte[] val)
        {
            return MakePrimitiveInner(tagClass, tagValue, val, 0, val.Length);
        }

        private static AsnElt MakePrimitiveInner(int tagClass, int tagValue, byte[] val, int off, int len)
        {
            if (tagClass < 0 || tagClass > 3)
            {
                throw new AsnException("invalid tag class: " + tagClass);
            }
            if (tagValue < 0)
            {
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

        /* Create a new INTEGER value for the provided integer. */
        public static AsnElt MakeInteger(long x)
        {
            if (x >= 0)
            {
                return MakeInteger((ulong)x);
            }
            int k = 1;
            for (long w = x; w <= -(long)0x80; w >>= 8)
            {
                k++;
            }
            byte[] v = new byte[k];
            for (long w = x; k > 0; w >>= 8)
            {
                v[--k] = (byte)w;
            }
            return MakePrimitiveInner(INTEGER, v);
        }

        /* Create a new INTEGER value for the provided integer. */
        public static AsnElt MakeInteger(ulong x)
        {
            int k = 1;
            for (ulong w = x; w >= 0x80; w >>= 8)
            {
                k++;
            }
            byte[] v = new byte[k];
            for (ulong w = x; k > 0; w >>= 8)
            {
                v[--k] = (byte)w;
            }
            return MakePrimitiveInner(INTEGER, v);
        }

        /* Create a new INTEGER value for the provided integer. The x[] array uses
         * _unsigned_ big-endian encoding. */
        public static AsnElt MakeInteger(byte[] x)
        {
            int xLen = x.Length;
            int j = 0;
            while (j < xLen && x[j] == 0x00)
            {
                j++;
            }
            if (j == xLen)
            {
                return MakePrimitiveInner(INTEGER, new byte[] { 0x00 });
            }
            byte[] v;
            if (x[j] < 0x80)
            {
                v = new byte[xLen - j];
                Array.Copy(x, j, v, 0, v.Length);
            }
            else
            {
                v = new byte[1 + xLen - j];
                Array.Copy(x, j, v, 1, v.Length - 1);
            }
            return MakePrimitiveInner(INTEGER, v);
        }

        /* Create a new INTEGER value for the provided integer. The x[] array uses _signed_
         * big-endian encoding. */
        public static AsnElt MakeIntegerSigned(byte[] x)
        {
            int xLen = x.Length;
            if (xLen == 0)
            {
                throw new AsnException("Invalid signed integer (empty)");
            }
            int j = 0;
            if (x[0] >= 0x80)
            {
                while (j < (xLen - 1)
                    && x[j] == 0xFF
                    && x[j + 1] >= 0x80)
                {
                    j++;
                }
            }
            else
            {
                while (j < (xLen - 1)
                    && x[j] == 0x00
                    && x[j + 1] < 0x80)
                {
                    j++;
                }
            }
            byte[] v = new byte[xLen - j];
            Array.Copy(x, j, v, 0, v.Length);
            return MakePrimitiveInner(INTEGER, v);
        }

        /* Create a BIT STRING from the provided value. The number of "unused bits" is set to 0. */
        public static AsnElt MakeBitString(byte[] buf)
        {
            return MakeBitString(buf, 0, buf.Length);
        }

        public static AsnElt MakeBitString(byte[] buf, int off, int len)
        {
            byte[] tmp = new byte[len + 1];
            Array.Copy(buf, off, tmp, 1, len);
            return MakePrimitiveInner(BIT_STRING, tmp);
        }

        /* Create a BIT STRING from the provided value. The number of "unused bits" is specified. */
        public static AsnElt MakeBitString(int unusedBits, byte[] buf)
        {
            return MakeBitString(unusedBits, buf, 0, buf.Length);
        }

        public static AsnElt MakeBitString(int unusedBits, byte[] buf, int off, int len)
        {
            if (unusedBits < 0 || unusedBits > 7
                || (unusedBits != 0 && len == 0))
            {
                throw new AsnException("Invalid number of unused bits in BIT STRING: " + unusedBits);
            }
            byte[] tmp = new byte[len + 1];
            tmp[0] = (byte)unusedBits;
            Array.Copy(buf, off, tmp, 1, len);
            if (len > 0)
            {
                tmp[len - 1] &= (byte)(0xFF << unusedBits);
            }
            return MakePrimitiveInner(BIT_STRING, tmp);
        }

        /* Create an OCTET STRING from the provided value. */
        public static AsnElt MakeBlob(byte[] buf)
        {
            return MakeBlob(buf, 0, buf.Length);
        }

        public static AsnElt MakeBlob(byte[] buf, int off, int len)
        {
            return MakePrimitive(OCTET_STRING, buf, off, len);
        }

        /* Create a new constructed elements, by providing the relevant sub-elements. */
        public static AsnElt Make(int tagValue, params AsnElt[] subs)
        {
            return Make(UNIVERSAL, tagValue, subs);
        }

        /* Create a new constructed elements, by providing the relevant sub-elements. */
        public static AsnElt Make(int tagClass, int tagValue, params AsnElt[] subs)
        {
            if (tagClass < 0 || tagClass > 3)
            {
                throw new AsnException("invalid tag class: " + tagClass);
            }
            if (tagValue < 0)
            {
                throw new AsnException("invalid tag value: " + tagValue);
            }
            AsnElt result = new AsnElt(tagClass, tagValue)
            {
                _objectBuffer = null,
                _objectOffset = 0,
                _objectLength = -1,
                _valueOffset = 0,
                _valueLength = -1,
                _hasEncodedHeader = false,
            };
            if (null == subs)
            {
                result._sub = new AsnElt[0];
            }
            else
            {
                result._sub = new AsnElt[subs.Length];
                Array.Copy(subs, 0, result._sub, 0, subs.Length);
            }
            return result;
        }

        /* Create a SET OF: sub-elements are automatically sorted by lexicographic order of their
         * DER encodings. Identical elements are merged. */
        public static AsnElt MakeSetOf(params AsnElt[] subs)
        {
            AsnElt a = new AsnElt(UNIVERSAL, SET);
            a._objectBuffer = null;
            a._objectOffset = 0;
            a._objectLength = -1;
            a._valueOffset = 0;
            a._valueLength = -1;
            a._hasEncodedHeader = false;
            if (subs == null)
            {
                a._sub = new AsnElt[0];
            }
            else
            {
                SortedDictionary<byte[], AsnElt> d =
                    new SortedDictionary<byte[], AsnElt>(COMPARER_LEXICOGRAPHIC);
                foreach (AsnElt ax in subs)
                {
                    d[ax.Encode()] = ax;
                }
                AsnElt[] tmp = new AsnElt[d.Count];
                int j = 0;
                foreach (AsnElt ax in d.Values)
                {
                    tmp[j++] = ax;
                }
                a._sub = tmp;
            }
            return a;
        }

        /* Wrap an element into an explicit tag. */
        public static AsnElt MakeExplicit(int tagClass, int tagValue, AsnElt x)
        {
            return Make(tagClass, tagValue, x);
        }

        /* Wrap an element into an explicit CONTEXT tag. */
        public static AsnElt MakeExplicit(int tagValue, AsnElt x)
        {
            return Make(CONTEXT, tagValue, x);
        }

        /* Apply an implicit tag to a value. The source AsnElt object is unmodified; a new object
         * is returned. */
        public static AsnElt MakeImplicit(int tagClass, int tagValue, AsnElt x)
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
            /* Get the value. This may return a shared buffer, that MUST NOT be modified. */
            if (null == x._objectBuffer) {
                /* We can modify objBuf because CopyValue() called ValueLength, thus valLen has been filled. */
                x._objectBuffer = x.CopyValue();
                result._valueOffset = 0;
                result._valueLength = x._objectBuffer.Length;
            }
            else {
                result._valueOffset = x._valueOffset;
                result._valueLength = x._valueLength;
            }
            result._objectBuffer = x._objectBuffer;
            return result;
        }

        /* Create an OBJECT IDENTIFIER from its string representation. This function tolerates
         * extra leading zeros. */
        public static AsnElt MakeOID(string str)
        {
            List<long> r = new List<long>();
            int n = str.Length;
            long x = -1;
            for (int i = 0; i < n; i++) {
                int c = str[i];
                if (c == '.') {
                    if (x < 0) {
                        throw new AsnException("invalid OID (empty element)");
                    }
                    r.Add(x);
                    x = -1;
                    continue;
                }
                if (c < '0' || c > '9') {
                    throw new AsnException(String.Format("invalid character U+{0:X4} in OID", c));
                }
                if (x < 0) {
                    x = 0;
                }
                else if (x > ((Int64.MaxValue - 9) / 10)) {
                    throw new AsnException("OID element overflow");
                }
                x = x * (long)10 + (long)(c - '0');
            }
            if (x < 0) {
                throw new AsnException("invalid OID (empty element)");
            }
            r.Add(x);
            if (r.Count < 2) {
                throw new AsnException("invalid OID (not enough elements)");
            }
            if (r[0] > 2 || r[1] > 40) {
                throw new AsnException("invalid OID (first elements out of range)");
            }
            MemoryStream ms = new MemoryStream();
            ms.WriteByte((byte)(40 * (int)r[0] + (int)r[1]));
            for (int i = 2; i < r.Count; i++)
            {
                long v = r[i];
                if (v < 0x80)
                {
                    ms.WriteByte((byte)v);
                    continue;
                }
                int k = -7;
                for (long w = v; w != 0; w >>= 7, k += 7) ;
                ms.WriteByte((byte)(0x80 + (int)(v >> k)));
                for (k -= 7; k >= 0; k -= 7)
                {
                    int z = (int)(v >> k) & 0x7F;
                    if (k > 0)
                    {
                        z |= 0x80;
                    }
                    ms.WriteByte((byte)z);
                }
            }
            byte[] buf = ms.ToArray();
            return MakePrimitiveInner(OBJECT_IDENTIFIER, buf, 0, buf.Length);
        }

        internal static AsnElt MakeSequence(params AsnElt[] subs)
        {
            return Make(SEQUENCE, subs);
        }

        /* Create a string of the provided type and contents. The string type is a universal tag
         * value for one of the string or time types. */
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
            return MakePrimitiveInner(type, buf);
        }

        private static byte[] EncodeMono(string str)
        {
            byte[] result = new byte[str.Length];
            int k = 0;
            foreach (char c in str) {
                result[k++] = (byte)c;
            }
            return result;
        }

        /* Get the code point at offset 'off' in the string. Either one or two 'char' slots are
         * used; 'off' is updated accordingly. */
        private static int CodePoint(string str, ref int off)
        {
            int result = str[off++];
            if (result >= 0xD800 && result < 0xDC00 && off < str.Length) {
                int d = str[off];
                if ((0xDC00 <= d) && (0xE000 > d)) {
                    result = ((result & 0x3FF) << 10) + (d & 0x3FF) + 0x10000;
                    off++;
                }
            }
            return result;
        }

        private static byte[] EncodeUTF8(string str)
        {
            int k = 0;
            int n = str.Length;
            MemoryStream ms = new MemoryStream();
            while (k < n) {
                int cp = CodePoint(str, ref k);
                if (0x80 > cp) {
                    ms.WriteByte((byte)cp);
                }
                else if (0x800 > cp) {
                    ms.WriteByte((byte)(0xC0 + (cp >> 6)));
                    ms.WriteByte((byte)(0x80 + (cp & 63)));
                }
                else if (0x10000 > cp) {
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

        private static byte[] EncodeUTF16(string str)
        {
            byte[] result = new byte[str.Length << 1];
            int k = 0;
            foreach (char c in str) {
                result[k++] = (byte)(c >> 8);
                result[k++] = (byte)c;
            }
            return result;
        }

        private static byte[] EncodeUTF32(string str)
        {
            int k = 0;
            int n = str.Length;
            MemoryStream ms = new MemoryStream();
            while (k < n)
            {
                int cp = CodePoint(str, ref k);
                ms.WriteByte((byte)(cp >> 24));
                ms.WriteByte((byte)(cp >> 16));
                ms.WriteByte((byte)(cp >> 8));
                ms.WriteByte((byte)cp);
            }
            return ms.ToArray();
        }

        /* Create a time value of the specified type (UTCTime or GeneralizedTime). */
        public static AsnElt MakeTime(int type, DateTime dt)
        {
            dt = dt.ToUniversalTime();
            string str;
            switch (type)
            {
                case UTCTime:
                    int year = dt.Year;
                    if (year < 1950 || year >= 2050)
                    {
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
                    if (millis != 0)
                    {
                        if (millis % 100 == 0)
                        {
                            str = String.Format("{0}.{1:d1}", str, millis / 100);
                        }
                        else if (millis % 10 == 0)
                        {
                            str = String.Format("{0}.{1:d2}", str, millis / 10);
                        }
                        else
                        {
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

        /* Create a time value of the specified type (UTCTime or GeneralizedTime). */
        public static AsnElt MakeTime(int type, DateTimeOffset dto)
        {
            return MakeTime(type, dto.UtcDateTime);
        }

        /* Create a time value with an automatic type selection (UTCTime if year is in the
         * 1950..2049 range, GeneralizedTime otherwise). */
        public static AsnElt MakeTimeAuto(DateTime dt)
        {
            dt = dt.ToUniversalTime();
            return MakeTime(((1950 <= dt.Year) && (2049 >= dt.Year)) ? UTCTime : GeneralizedTime, dt);
        }

        /* Create a time value with an automatic type selection (UTCTime if year is in the
         * 1950..2049 range, GeneralizedTime otherwise). */
        public static AsnElt MakeTimeAuto(DateTimeOffset dto)
        {
            return MakeTimeAuto(dto.UtcDateTime);
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
        private int _valueOffset;
        private int _valueLength;

        /* The sub-elements. This is null if this element is primitive.
         * DO NOT MODIFY this array. */
        private AsnElt[] _sub;
        private int _tagClass;

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
                for (int i = 0; i < cLen; i++)
                {
                    if (x[i] != y[i])
                    {
                        return (int)x[i] - (int)y[i];
                    }
                }
                return xLen - yLen;
            }
        }
    }
}
