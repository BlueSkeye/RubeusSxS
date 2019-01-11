using System;

namespace Rubeus.Asn1
{
    public partial class AsnElt
    {
        ///// <summary>Get a sub-element. This method throws appropriate exceptions if this
        ///// element is not constructed, or the requested index is out of range.</summary>
        ///// <param name="index"></param>
        ///// <returns></returns>
        //internal AsnElt this[int index]
        //{
        //    get
        //    {
        //        if (0 > index) {
        //            throw new IndexOutOfRangeException("index");
        //        }
        //        AssertConstructed();
        //        if (_sub.Length <= index) {
        //            throw new AsnException("no such sub-object: n=" + index);
        //        }
        //        return _sub[index];
        //    }
        //}

        ///// <summary>Check that this element is constructed and contains exactly 'n' sub-elements.</summary>
        ///// <param name="expected"></param>
        //internal void AssertItemsCountEquals(int expected)
        //{
        //    AssertConstructed();
        //    int realLength = _sub.Length;
        //    if (realLength != expected) {
        //        throw new AsnException("wrong number of sub-elements: " + realLength + " (expected: " + expected + ")");
        //    }
        //}

        ///// <summary>Check that this element is constructed and contains at least 'n' sub-elements.</summary>
        ///// <param name="expected"></param>
        //internal void AssertItemsCountAtLeast(int expected)
        //{
        //    AssertConstructed();
        //    int realLength = _sub.Length;
        //    if (realLength < expected) {
        //        throw new AsnException("not enough sub-elements: " + realLength + " (minimum: " + expected + ")");
        //    }
        //}

        ///// <summary>Check that this element is constructed and contains no more than 'n' sub-elements.</summary>
        ///// <param name="expected"></param>
        //internal void AssertItemsCountAtMost(int expected)
        //{
        //    AssertConstructed();
        //    int realLength = _sub.Length;
        //    if (realLength > expected) {
        //        throw new AsnException("too many sub-elements: " + realLength + " (maximum: " + expected + ")");
        //    }
        //}

    }
}
