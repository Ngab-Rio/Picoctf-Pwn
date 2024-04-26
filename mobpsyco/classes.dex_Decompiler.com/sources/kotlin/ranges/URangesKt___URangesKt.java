package kotlin.ranges;

import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.UByte;
import kotlin.UInt;
import kotlin.ULong;
import kotlin.UShort;
import kotlin.UnsignedKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.random.Random;
import kotlin.random.URandomKt;

@Metadata(d1 = {"\u0000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\u0010\t\n\u0002\b\n\u001a\u001e\u0010\u0000\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0007ø\u0001\u0000¢\u0006\u0004\b\u0003\u0010\u0004\u001a\u001e\u0010\u0000\u001a\u00020\u0005*\u00020\u00052\u0006\u0010\u0002\u001a\u00020\u0005H\u0007ø\u0001\u0000¢\u0006\u0004\b\u0006\u0010\u0007\u001a\u001e\u0010\u0000\u001a\u00020\b*\u00020\b2\u0006\u0010\u0002\u001a\u00020\bH\u0007ø\u0001\u0000¢\u0006\u0004\b\t\u0010\n\u001a\u001e\u0010\u0000\u001a\u00020\u000b*\u00020\u000b2\u0006\u0010\u0002\u001a\u00020\u000bH\u0007ø\u0001\u0000¢\u0006\u0004\b\f\u0010\r\u001a\u001e\u0010\u000e\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u000f\u001a\u00020\u0001H\u0007ø\u0001\u0000¢\u0006\u0004\b\u0010\u0010\u0004\u001a\u001e\u0010\u000e\u001a\u00020\u0005*\u00020\u00052\u0006\u0010\u000f\u001a\u00020\u0005H\u0007ø\u0001\u0000¢\u0006\u0004\b\u0011\u0010\u0007\u001a\u001e\u0010\u000e\u001a\u00020\b*\u00020\b2\u0006\u0010\u000f\u001a\u00020\bH\u0007ø\u0001\u0000¢\u0006\u0004\b\u0012\u0010\n\u001a\u001e\u0010\u000e\u001a\u00020\u000b*\u00020\u000b2\u0006\u0010\u000f\u001a\u00020\u000bH\u0007ø\u0001\u0000¢\u0006\u0004\b\u0013\u0010\r\u001a&\u0010\u0014\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u000f\u001a\u00020\u0001H\u0007ø\u0001\u0000¢\u0006\u0004\b\u0015\u0010\u0016\u001a&\u0010\u0014\u001a\u00020\u0005*\u00020\u00052\u0006\u0010\u0002\u001a\u00020\u00052\u0006\u0010\u000f\u001a\u00020\u0005H\u0007ø\u0001\u0000¢\u0006\u0004\b\u0017\u0010\u0018\u001a$\u0010\u0014\u001a\u00020\u0005*\u00020\u00052\f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00050\u001aH\u0007ø\u0001\u0000¢\u0006\u0004\b\u001b\u0010\u001c\u001a&\u0010\u0014\u001a\u00020\b*\u00020\b2\u0006\u0010\u0002\u001a\u00020\b2\u0006\u0010\u000f\u001a\u00020\bH\u0007ø\u0001\u0000¢\u0006\u0004\b\u001d\u0010\u001e\u001a$\u0010\u0014\u001a\u00020\b*\u00020\b2\f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\b0\u001aH\u0007ø\u0001\u0000¢\u0006\u0004\b\u001f\u0010 \u001a&\u0010\u0014\u001a\u00020\u000b*\u00020\u000b2\u0006\u0010\u0002\u001a\u00020\u000b2\u0006\u0010\u000f\u001a\u00020\u000bH\u0007ø\u0001\u0000¢\u0006\u0004\b!\u0010\"\u001a\u001f\u0010#\u001a\u00020$*\u00020%2\u0006\u0010&\u001a\u00020\u0001H\u0002ø\u0001\u0000¢\u0006\u0004\b'\u0010(\u001a\u001f\u0010#\u001a\u00020$*\u00020%2\b\u0010)\u001a\u0004\u0018\u00010\u0005H\nø\u0001\u0000¢\u0006\u0002\b*\u001a\u001f\u0010#\u001a\u00020$*\u00020%2\u0006\u0010&\u001a\u00020\bH\u0002ø\u0001\u0000¢\u0006\u0004\b+\u0010,\u001a\u001f\u0010#\u001a\u00020$*\u00020%2\u0006\u0010&\u001a\u00020\u000bH\u0002ø\u0001\u0000¢\u0006\u0004\b-\u0010.\u001a\u001f\u0010#\u001a\u00020$*\u00020/2\u0006\u0010&\u001a\u00020\u0001H\u0002ø\u0001\u0000¢\u0006\u0004\b0\u00101\u001a\u001f\u0010#\u001a\u00020$*\u00020/2\u0006\u0010&\u001a\u00020\u0005H\u0002ø\u0001\u0000¢\u0006\u0004\b2\u00103\u001a\u001f\u0010#\u001a\u00020$*\u00020/2\b\u0010)\u001a\u0004\u0018\u00010\bH\nø\u0001\u0000¢\u0006\u0002\b4\u001a\u001f\u0010#\u001a\u00020$*\u00020/2\u0006\u0010&\u001a\u00020\u000bH\u0002ø\u0001\u0000¢\u0006\u0004\b5\u00106\u001a\u001f\u00107\u001a\u000208*\u00020\u00012\u0006\u00109\u001a\u00020\u0001H\u0004ø\u0001\u0000¢\u0006\u0004\b:\u0010;\u001a\u001f\u00107\u001a\u000208*\u00020\u00052\u0006\u00109\u001a\u00020\u0005H\u0004ø\u0001\u0000¢\u0006\u0004\b<\u0010=\u001a\u001f\u00107\u001a\u00020>*\u00020\b2\u0006\u00109\u001a\u00020\bH\u0004ø\u0001\u0000¢\u0006\u0004\b?\u0010@\u001a\u001f\u00107\u001a\u000208*\u00020\u000b2\u0006\u00109\u001a\u00020\u000bH\u0004ø\u0001\u0000¢\u0006\u0004\bA\u0010B\u001a\u0014\u0010C\u001a\u00020\u0005*\u000208H\u0007ø\u0001\u0000¢\u0006\u0002\u0010D\u001a\u0014\u0010C\u001a\u00020\b*\u00020>H\u0007ø\u0001\u0000¢\u0006\u0002\u0010E\u001a\u0011\u0010F\u001a\u0004\u0018\u00010\u0005*\u000208H\u0007ø\u0001\u0000\u001a\u0011\u0010F\u001a\u0004\u0018\u00010\b*\u00020>H\u0007ø\u0001\u0000\u001a\u0014\u0010G\u001a\u00020\u0005*\u000208H\u0007ø\u0001\u0000¢\u0006\u0002\u0010D\u001a\u0014\u0010G\u001a\u00020\b*\u00020>H\u0007ø\u0001\u0000¢\u0006\u0002\u0010E\u001a\u0011\u0010H\u001a\u0004\u0018\u00010\u0005*\u000208H\u0007ø\u0001\u0000\u001a\u0011\u0010H\u001a\u0004\u0018\u00010\b*\u00020>H\u0007ø\u0001\u0000\u001a\u0015\u0010I\u001a\u00020\u0005*\u00020%H\bø\u0001\u0000¢\u0006\u0002\u0010J\u001a\u001c\u0010I\u001a\u00020\u0005*\u00020%2\u0006\u0010I\u001a\u00020KH\u0007ø\u0001\u0000¢\u0006\u0002\u0010L\u001a\u0015\u0010I\u001a\u00020\b*\u00020/H\bø\u0001\u0000¢\u0006\u0002\u0010M\u001a\u001c\u0010I\u001a\u00020\b*\u00020/2\u0006\u0010I\u001a\u00020KH\u0007ø\u0001\u0000¢\u0006\u0002\u0010N\u001a\u0012\u0010O\u001a\u0004\u0018\u00010\u0005*\u00020%H\bø\u0001\u0000\u001a\u0019\u0010O\u001a\u0004\u0018\u00010\u0005*\u00020%2\u0006\u0010I\u001a\u00020KH\u0007ø\u0001\u0000\u001a\u0012\u0010O\u001a\u0004\u0018\u00010\b*\u00020/H\bø\u0001\u0000\u001a\u0019\u0010O\u001a\u0004\u0018\u00010\b*\u00020/2\u0006\u0010I\u001a\u00020KH\u0007ø\u0001\u0000\u001a\f\u0010P\u001a\u000208*\u000208H\u0007\u001a\f\u0010P\u001a\u00020>*\u00020>H\u0007\u001a\u0015\u0010Q\u001a\u000208*\u0002082\u0006\u0010Q\u001a\u00020RH\u0004\u001a\u0015\u0010Q\u001a\u00020>*\u00020>2\u0006\u0010Q\u001a\u00020SH\u0004\u001a\u001f\u0010T\u001a\u00020%*\u00020\u00012\u0006\u00109\u001a\u00020\u0001H\u0004ø\u0001\u0000¢\u0006\u0004\bU\u0010V\u001a\u001f\u0010T\u001a\u00020%*\u00020\u00052\u0006\u00109\u001a\u00020\u0005H\u0004ø\u0001\u0000¢\u0006\u0004\bW\u0010X\u001a\u001f\u0010T\u001a\u00020/*\u00020\b2\u0006\u00109\u001a\u00020\bH\u0004ø\u0001\u0000¢\u0006\u0004\bY\u0010Z\u001a\u001f\u0010T\u001a\u00020%*\u00020\u000b2\u0006\u00109\u001a\u00020\u000bH\u0004ø\u0001\u0000¢\u0006\u0004\b[\u0010\\\u0002\u0004\n\u0002\b\u0019¨\u0006]"}, d2 = {"coerceAtLeast", "Lkotlin/UByte;", "minimumValue", "coerceAtLeast-Kr8caGY", "(BB)B", "Lkotlin/UInt;", "coerceAtLeast-J1ME1BU", "(II)I", "Lkotlin/ULong;", "coerceAtLeast-eb3DHEI", "(JJ)J", "Lkotlin/UShort;", "coerceAtLeast-5PvTz6A", "(SS)S", "coerceAtMost", "maximumValue", "coerceAtMost-Kr8caGY", "coerceAtMost-J1ME1BU", "coerceAtMost-eb3DHEI", "coerceAtMost-5PvTz6A", "coerceIn", "coerceIn-b33U2AM", "(BBB)B", "coerceIn-WZ9TVnA", "(III)I", "range", "Lkotlin/ranges/ClosedRange;", "coerceIn-wuiCnnA", "(ILkotlin/ranges/ClosedRange;)I", "coerceIn-sambcqE", "(JJJ)J", "coerceIn-JPwROB0", "(JLkotlin/ranges/ClosedRange;)J", "coerceIn-VKSA0NQ", "(SSS)S", "contains", "", "Lkotlin/ranges/UIntRange;", "value", "contains-68kG9v0", "(Lkotlin/ranges/UIntRange;B)Z", "element", "contains-biwQdVI", "contains-fz5IDCE", "(Lkotlin/ranges/UIntRange;J)Z", "contains-ZsK3CEQ", "(Lkotlin/ranges/UIntRange;S)Z", "Lkotlin/ranges/ULongRange;", "contains-ULb-yJY", "(Lkotlin/ranges/ULongRange;B)Z", "contains-Gab390E", "(Lkotlin/ranges/ULongRange;I)Z", "contains-GYNo2lE", "contains-uhHAxoY", "(Lkotlin/ranges/ULongRange;S)Z", "downTo", "Lkotlin/ranges/UIntProgression;", "to", "downTo-Kr8caGY", "(BB)Lkotlin/ranges/UIntProgression;", "downTo-J1ME1BU", "(II)Lkotlin/ranges/UIntProgression;", "Lkotlin/ranges/ULongProgression;", "downTo-eb3DHEI", "(JJ)Lkotlin/ranges/ULongProgression;", "downTo-5PvTz6A", "(SS)Lkotlin/ranges/UIntProgression;", "first", "(Lkotlin/ranges/UIntProgression;)I", "(Lkotlin/ranges/ULongProgression;)J", "firstOrNull", "last", "lastOrNull", "random", "(Lkotlin/ranges/UIntRange;)I", "Lkotlin/random/Random;", "(Lkotlin/ranges/UIntRange;Lkotlin/random/Random;)I", "(Lkotlin/ranges/ULongRange;)J", "(Lkotlin/ranges/ULongRange;Lkotlin/random/Random;)J", "randomOrNull", "reversed", "step", "", "", "until", "until-Kr8caGY", "(BB)Lkotlin/ranges/UIntRange;", "until-J1ME1BU", "(II)Lkotlin/ranges/UIntRange;", "until-eb3DHEI", "(JJ)Lkotlin/ranges/ULongRange;", "until-5PvTz6A", "(SS)Lkotlin/ranges/UIntRange;", "kotlin-stdlib"}, k = 5, mv = {1, 7, 1}, xi = 49, xs = "kotlin/ranges/URangesKt")
/* compiled from: _URanges.kt */
class URangesKt___URangesKt {
    public static final int first(UIntProgression $this$first) {
        Intrinsics.checkNotNullParameter($this$first, "<this>");
        if (!$this$first.isEmpty()) {
            return $this$first.m1265getFirstpVg5ArA();
        }
        throw new NoSuchElementException("Progression " + $this$first + " is empty.");
    }

    public static final long first(ULongProgression $this$first) {
        Intrinsics.checkNotNullParameter($this$first, "<this>");
        if (!$this$first.isEmpty()) {
            return $this$first.m1272getFirstsVKNKU();
        }
        throw new NoSuchElementException("Progression " + $this$first + " is empty.");
    }

    public static final UInt firstOrNull(UIntProgression $this$firstOrNull) {
        Intrinsics.checkNotNullParameter($this$firstOrNull, "<this>");
        if ($this$firstOrNull.isEmpty()) {
            return null;
        }
        return UInt.m128boximpl($this$firstOrNull.m1265getFirstpVg5ArA());
    }

    public static final ULong firstOrNull(ULongProgression $this$firstOrNull) {
        Intrinsics.checkNotNullParameter($this$firstOrNull, "<this>");
        if ($this$firstOrNull.isEmpty()) {
            return null;
        }
        return ULong.m206boximpl($this$firstOrNull.m1272getFirstsVKNKU());
    }

    public static final int last(UIntProgression $this$last) {
        Intrinsics.checkNotNullParameter($this$last, "<this>");
        if (!$this$last.isEmpty()) {
            return $this$last.m1266getLastpVg5ArA();
        }
        throw new NoSuchElementException("Progression " + $this$last + " is empty.");
    }

    public static final long last(ULongProgression $this$last) {
        Intrinsics.checkNotNullParameter($this$last, "<this>");
        if (!$this$last.isEmpty()) {
            return $this$last.m1273getLastsVKNKU();
        }
        throw new NoSuchElementException("Progression " + $this$last + " is empty.");
    }

    public static final UInt lastOrNull(UIntProgression $this$lastOrNull) {
        Intrinsics.checkNotNullParameter($this$lastOrNull, "<this>");
        if ($this$lastOrNull.isEmpty()) {
            return null;
        }
        return UInt.m128boximpl($this$lastOrNull.m1266getLastpVg5ArA());
    }

    public static final ULong lastOrNull(ULongProgression $this$lastOrNull) {
        Intrinsics.checkNotNullParameter($this$lastOrNull, "<this>");
        if ($this$lastOrNull.isEmpty()) {
            return null;
        }
        return ULong.m206boximpl($this$lastOrNull.m1273getLastsVKNKU());
    }

    private static final int random(UIntRange $this$random) {
        Intrinsics.checkNotNullParameter($this$random, "<this>");
        return URangesKt.random($this$random, (Random) Random.Default);
    }

    private static final long random(ULongRange $this$random) {
        Intrinsics.checkNotNullParameter($this$random, "<this>");
        return URangesKt.random($this$random, (Random) Random.Default);
    }

    public static final int random(UIntRange $this$random, Random random) {
        Intrinsics.checkNotNullParameter($this$random, "<this>");
        Intrinsics.checkNotNullParameter(random, "random");
        try {
            return URandomKt.nextUInt(random, $this$random);
        } catch (IllegalArgumentException e) {
            throw new NoSuchElementException(e.getMessage());
        }
    }

    public static final long random(ULongRange $this$random, Random random) {
        Intrinsics.checkNotNullParameter($this$random, "<this>");
        Intrinsics.checkNotNullParameter(random, "random");
        try {
            return URandomKt.nextULong(random, $this$random);
        } catch (IllegalArgumentException e) {
            throw new NoSuchElementException(e.getMessage());
        }
    }

    private static final UInt randomOrNull(UIntRange $this$randomOrNull) {
        Intrinsics.checkNotNullParameter($this$randomOrNull, "<this>");
        return URangesKt.randomOrNull($this$randomOrNull, (Random) Random.Default);
    }

    private static final ULong randomOrNull(ULongRange $this$randomOrNull) {
        Intrinsics.checkNotNullParameter($this$randomOrNull, "<this>");
        return URangesKt.randomOrNull($this$randomOrNull, (Random) Random.Default);
    }

    public static final UInt randomOrNull(UIntRange $this$randomOrNull, Random random) {
        Intrinsics.checkNotNullParameter($this$randomOrNull, "<this>");
        Intrinsics.checkNotNullParameter(random, "random");
        if ($this$randomOrNull.isEmpty()) {
            return null;
        }
        return UInt.m128boximpl(URandomKt.nextUInt(random, $this$randomOrNull));
    }

    public static final ULong randomOrNull(ULongRange $this$randomOrNull, Random random) {
        Intrinsics.checkNotNullParameter($this$randomOrNull, "<this>");
        Intrinsics.checkNotNullParameter(random, "random");
        if ($this$randomOrNull.isEmpty()) {
            return null;
        }
        return ULong.m206boximpl(URandomKt.nextULong(random, $this$randomOrNull));
    }

    /* renamed from: contains-biwQdVI  reason: not valid java name */
    private static final boolean m1298containsbiwQdVI(UIntRange $this$contains_u2dbiwQdVI, UInt element) {
        Intrinsics.checkNotNullParameter($this$contains_u2dbiwQdVI, "$this$contains");
        return element != null && $this$contains_u2dbiwQdVI.m1269containsWZ4Q5Ns(element.m185unboximpl());
    }

    /* renamed from: contains-GYNo2lE  reason: not valid java name */
    private static final boolean m1294containsGYNo2lE(ULongRange $this$contains_u2dGYNo2lE, ULong element) {
        Intrinsics.checkNotNullParameter($this$contains_u2dGYNo2lE, "$this$contains");
        return element != null && $this$contains_u2dGYNo2lE.m1276containsVKZWuLQ(element.m263unboximpl());
    }

    /* renamed from: contains-68kG9v0  reason: not valid java name */
    public static final boolean m1293contains68kG9v0(UIntRange $this$contains_u2d68kG9v0, byte value) {
        Intrinsics.checkNotNullParameter($this$contains_u2d68kG9v0, "$this$contains");
        return $this$contains_u2d68kG9v0.m1269containsWZ4Q5Ns(UInt.m134constructorimpl(value & UByte.MAX_VALUE));
    }

    /* renamed from: contains-ULb-yJY  reason: not valid java name */
    public static final boolean m1296containsULbyJY(ULongRange $this$contains_u2dULb_u2dyJY, byte value) {
        Intrinsics.checkNotNullParameter($this$contains_u2dULb_u2dyJY, "$this$contains");
        return $this$contains_u2dULb_u2dyJY.m1276containsVKZWuLQ(ULong.m212constructorimpl(((long) value) & 255));
    }

    /* renamed from: contains-Gab390E  reason: not valid java name */
    public static final boolean m1295containsGab390E(ULongRange $this$contains_u2dGab390E, int value) {
        Intrinsics.checkNotNullParameter($this$contains_u2dGab390E, "$this$contains");
        return $this$contains_u2dGab390E.m1276containsVKZWuLQ(ULong.m212constructorimpl(((long) value) & 4294967295L));
    }

    /* renamed from: contains-fz5IDCE  reason: not valid java name */
    public static final boolean m1299containsfz5IDCE(UIntRange $this$contains_u2dfz5IDCE, long value) {
        Intrinsics.checkNotNullParameter($this$contains_u2dfz5IDCE, "$this$contains");
        return ULong.m212constructorimpl(value >>> 32) == 0 && $this$contains_u2dfz5IDCE.m1269containsWZ4Q5Ns(UInt.m134constructorimpl((int) value));
    }

    /* renamed from: contains-ZsK3CEQ  reason: not valid java name */
    public static final boolean m1297containsZsK3CEQ(UIntRange $this$contains_u2dZsK3CEQ, short value) {
        Intrinsics.checkNotNullParameter($this$contains_u2dZsK3CEQ, "$this$contains");
        return $this$contains_u2dZsK3CEQ.m1269containsWZ4Q5Ns(UInt.m134constructorimpl(65535 & value));
    }

    /* renamed from: contains-uhHAxoY  reason: not valid java name */
    public static final boolean m1300containsuhHAxoY(ULongRange $this$contains_u2duhHAxoY, short value) {
        Intrinsics.checkNotNullParameter($this$contains_u2duhHAxoY, "$this$contains");
        return $this$contains_u2duhHAxoY.m1276containsVKZWuLQ(ULong.m212constructorimpl(((long) value) & 65535));
    }

    /* renamed from: downTo-Kr8caGY  reason: not valid java name */
    public static final UIntProgression m1303downToKr8caGY(byte $this$downTo_u2dKr8caGY, byte to) {
        return UIntProgression.Companion.m1267fromClosedRangeNkh28Cs(UInt.m134constructorimpl($this$downTo_u2dKr8caGY & UByte.MAX_VALUE), UInt.m134constructorimpl(to & UByte.MAX_VALUE), -1);
    }

    /* renamed from: downTo-J1ME1BU  reason: not valid java name */
    public static final UIntProgression m1302downToJ1ME1BU(int $this$downTo_u2dJ1ME1BU, int to) {
        return UIntProgression.Companion.m1267fromClosedRangeNkh28Cs($this$downTo_u2dJ1ME1BU, to, -1);
    }

    /* renamed from: downTo-eb3DHEI  reason: not valid java name */
    public static final ULongProgression m1304downToeb3DHEI(long $this$downTo_u2deb3DHEI, long to) {
        return ULongProgression.Companion.m1274fromClosedRange7ftBX0g($this$downTo_u2deb3DHEI, to, -1);
    }

    /* renamed from: downTo-5PvTz6A  reason: not valid java name */
    public static final UIntProgression m1301downTo5PvTz6A(short $this$downTo_u2d5PvTz6A, short to) {
        return UIntProgression.Companion.m1267fromClosedRangeNkh28Cs(UInt.m134constructorimpl($this$downTo_u2d5PvTz6A & UShort.MAX_VALUE), UInt.m134constructorimpl(65535 & to), -1);
    }

    public static final UIntProgression reversed(UIntProgression $this$reversed) {
        Intrinsics.checkNotNullParameter($this$reversed, "<this>");
        return UIntProgression.Companion.m1267fromClosedRangeNkh28Cs($this$reversed.m1266getLastpVg5ArA(), $this$reversed.m1265getFirstpVg5ArA(), -$this$reversed.getStep());
    }

    public static final ULongProgression reversed(ULongProgression $this$reversed) {
        Intrinsics.checkNotNullParameter($this$reversed, "<this>");
        return ULongProgression.Companion.m1274fromClosedRange7ftBX0g($this$reversed.m1273getLastsVKNKU(), $this$reversed.m1272getFirstsVKNKU(), -$this$reversed.getStep());
    }

    public static final UIntProgression step(UIntProgression $this$step, int step) {
        Intrinsics.checkNotNullParameter($this$step, "<this>");
        RangesKt.checkStepIsPositive(step > 0, Integer.valueOf(step));
        return UIntProgression.Companion.m1267fromClosedRangeNkh28Cs($this$step.m1265getFirstpVg5ArA(), $this$step.m1266getLastpVg5ArA(), $this$step.getStep() > 0 ? step : -step);
    }

    public static final ULongProgression step(ULongProgression $this$step, long step) {
        Intrinsics.checkNotNullParameter($this$step, "<this>");
        RangesKt.checkStepIsPositive(step > 0, Long.valueOf(step));
        return ULongProgression.Companion.m1274fromClosedRange7ftBX0g($this$step.m1272getFirstsVKNKU(), $this$step.m1273getLastsVKNKU(), $this$step.getStep() > 0 ? step : -step);
    }

    /* renamed from: until-Kr8caGY  reason: not valid java name */
    public static final UIntRange m1307untilKr8caGY(byte $this$until_u2dKr8caGY, byte to) {
        if (Intrinsics.compare((int) to & UByte.MAX_VALUE, 0) <= 0) {
            return UIntRange.Companion.getEMPTY();
        }
        return new UIntRange(UInt.m134constructorimpl($this$until_u2dKr8caGY & UByte.MAX_VALUE), UInt.m134constructorimpl(UInt.m134constructorimpl(to & UByte.MAX_VALUE) - 1), (DefaultConstructorMarker) null);
    }

    /* renamed from: until-J1ME1BU  reason: not valid java name */
    public static final UIntRange m1306untilJ1ME1BU(int $this$until_u2dJ1ME1BU, int to) {
        if (UnsignedKt.uintCompare(to, 0) <= 0) {
            return UIntRange.Companion.getEMPTY();
        }
        return new UIntRange($this$until_u2dJ1ME1BU, UInt.m134constructorimpl(to - 1), (DefaultConstructorMarker) null);
    }

    /* renamed from: until-eb3DHEI  reason: not valid java name */
    public static final ULongRange m1308untileb3DHEI(long $this$until_u2deb3DHEI, long to) {
        if (UnsignedKt.ulongCompare(to, 0) <= 0) {
            return ULongRange.Companion.getEMPTY();
        }
        return new ULongRange($this$until_u2deb3DHEI, ULong.m212constructorimpl(to - ULong.m212constructorimpl(((long) 1) & 4294967295L)), (DefaultConstructorMarker) null);
    }

    /* renamed from: until-5PvTz6A  reason: not valid java name */
    public static final UIntRange m1305until5PvTz6A(short $this$until_u2d5PvTz6A, short to) {
        if (Intrinsics.compare((int) to & UShort.MAX_VALUE, 0) <= 0) {
            return UIntRange.Companion.getEMPTY();
        }
        return new UIntRange(UInt.m134constructorimpl($this$until_u2d5PvTz6A & UShort.MAX_VALUE), UInt.m134constructorimpl(UInt.m134constructorimpl(65535 & to) - 1), (DefaultConstructorMarker) null);
    }

    /* renamed from: coerceAtLeast-J1ME1BU  reason: not valid java name */
    public static final int m1280coerceAtLeastJ1ME1BU(int $this$coerceAtLeast_u2dJ1ME1BU, int minimumValue) {
        return UnsignedKt.uintCompare($this$coerceAtLeast_u2dJ1ME1BU, minimumValue) < 0 ? minimumValue : $this$coerceAtLeast_u2dJ1ME1BU;
    }

    /* renamed from: coerceAtLeast-eb3DHEI  reason: not valid java name */
    public static final long m1282coerceAtLeasteb3DHEI(long $this$coerceAtLeast_u2deb3DHEI, long minimumValue) {
        return UnsignedKt.ulongCompare($this$coerceAtLeast_u2deb3DHEI, minimumValue) < 0 ? minimumValue : $this$coerceAtLeast_u2deb3DHEI;
    }

    /* renamed from: coerceAtLeast-Kr8caGY  reason: not valid java name */
    public static final byte m1281coerceAtLeastKr8caGY(byte $this$coerceAtLeast_u2dKr8caGY, byte minimumValue) {
        return Intrinsics.compare((int) $this$coerceAtLeast_u2dKr8caGY & UByte.MAX_VALUE, (int) minimumValue & UByte.MAX_VALUE) < 0 ? minimumValue : $this$coerceAtLeast_u2dKr8caGY;
    }

    /* renamed from: coerceAtLeast-5PvTz6A  reason: not valid java name */
    public static final short m1279coerceAtLeast5PvTz6A(short $this$coerceAtLeast_u2d5PvTz6A, short minimumValue) {
        return Intrinsics.compare((int) $this$coerceAtLeast_u2d5PvTz6A & UShort.MAX_VALUE, (int) 65535 & minimumValue) < 0 ? minimumValue : $this$coerceAtLeast_u2d5PvTz6A;
    }

    /* renamed from: coerceAtMost-J1ME1BU  reason: not valid java name */
    public static final int m1284coerceAtMostJ1ME1BU(int $this$coerceAtMost_u2dJ1ME1BU, int maximumValue) {
        return UnsignedKt.uintCompare($this$coerceAtMost_u2dJ1ME1BU, maximumValue) > 0 ? maximumValue : $this$coerceAtMost_u2dJ1ME1BU;
    }

    /* renamed from: coerceAtMost-eb3DHEI  reason: not valid java name */
    public static final long m1286coerceAtMosteb3DHEI(long $this$coerceAtMost_u2deb3DHEI, long maximumValue) {
        return UnsignedKt.ulongCompare($this$coerceAtMost_u2deb3DHEI, maximumValue) > 0 ? maximumValue : $this$coerceAtMost_u2deb3DHEI;
    }

    /* renamed from: coerceAtMost-Kr8caGY  reason: not valid java name */
    public static final byte m1285coerceAtMostKr8caGY(byte $this$coerceAtMost_u2dKr8caGY, byte maximumValue) {
        return Intrinsics.compare((int) $this$coerceAtMost_u2dKr8caGY & UByte.MAX_VALUE, (int) maximumValue & UByte.MAX_VALUE) > 0 ? maximumValue : $this$coerceAtMost_u2dKr8caGY;
    }

    /* renamed from: coerceAtMost-5PvTz6A  reason: not valid java name */
    public static final short m1283coerceAtMost5PvTz6A(short $this$coerceAtMost_u2d5PvTz6A, short maximumValue) {
        return Intrinsics.compare((int) $this$coerceAtMost_u2d5PvTz6A & UShort.MAX_VALUE, (int) 65535 & maximumValue) > 0 ? maximumValue : $this$coerceAtMost_u2d5PvTz6A;
    }

    /* renamed from: coerceIn-WZ9TVnA  reason: not valid java name */
    public static final int m1289coerceInWZ9TVnA(int $this$coerceIn_u2dWZ9TVnA, int minimumValue, int maximumValue) {
        if (UnsignedKt.uintCompare(minimumValue, maximumValue) > 0) {
            throw new IllegalArgumentException("Cannot coerce value to an empty range: maximum " + UInt.m179toStringimpl(maximumValue) + " is less than minimum " + UInt.m179toStringimpl(minimumValue) + '.');
        } else if (UnsignedKt.uintCompare($this$coerceIn_u2dWZ9TVnA, minimumValue) < 0) {
            return minimumValue;
        } else {
            if (UnsignedKt.uintCompare($this$coerceIn_u2dWZ9TVnA, maximumValue) > 0) {
                return maximumValue;
            }
            return $this$coerceIn_u2dWZ9TVnA;
        }
    }

    /* renamed from: coerceIn-sambcqE  reason: not valid java name */
    public static final long m1291coerceInsambcqE(long $this$coerceIn_u2dsambcqE, long minimumValue, long maximumValue) {
        if (UnsignedKt.ulongCompare(minimumValue, maximumValue) > 0) {
            throw new IllegalArgumentException("Cannot coerce value to an empty range: maximum " + ULong.m257toStringimpl(maximumValue) + " is less than minimum " + ULong.m257toStringimpl(minimumValue) + '.');
        } else if (UnsignedKt.ulongCompare($this$coerceIn_u2dsambcqE, minimumValue) < 0) {
            return minimumValue;
        } else {
            if (UnsignedKt.ulongCompare($this$coerceIn_u2dsambcqE, maximumValue) > 0) {
                return maximumValue;
            }
            return $this$coerceIn_u2dsambcqE;
        }
    }

    /* renamed from: coerceIn-b33U2AM  reason: not valid java name */
    public static final byte m1290coerceInb33U2AM(byte $this$coerceIn_u2db33U2AM, byte minimumValue, byte maximumValue) {
        if (Intrinsics.compare((int) minimumValue & UByte.MAX_VALUE, (int) maximumValue & UByte.MAX_VALUE) > 0) {
            throw new IllegalArgumentException("Cannot coerce value to an empty range: maximum " + UByte.m101toStringimpl(maximumValue) + " is less than minimum " + UByte.m101toStringimpl(minimumValue) + '.');
        } else if (Intrinsics.compare((int) $this$coerceIn_u2db33U2AM & UByte.MAX_VALUE, (int) minimumValue & UByte.MAX_VALUE) < 0) {
            return minimumValue;
        } else {
            if (Intrinsics.compare((int) $this$coerceIn_u2db33U2AM & UByte.MAX_VALUE, (int) maximumValue & UByte.MAX_VALUE) > 0) {
                return maximumValue;
            }
            return $this$coerceIn_u2db33U2AM;
        }
    }

    /* renamed from: coerceIn-VKSA0NQ  reason: not valid java name */
    public static final short m1288coerceInVKSA0NQ(short $this$coerceIn_u2dVKSA0NQ, short minimumValue, short maximumValue) {
        if (Intrinsics.compare((int) minimumValue & UShort.MAX_VALUE, (int) maximumValue & UShort.MAX_VALUE) > 0) {
            throw new IllegalArgumentException("Cannot coerce value to an empty range: maximum " + UShort.m361toStringimpl(maximumValue) + " is less than minimum " + UShort.m361toStringimpl(minimumValue) + '.');
        } else if (Intrinsics.compare((int) $this$coerceIn_u2dVKSA0NQ & UShort.MAX_VALUE, (int) minimumValue & UShort.MAX_VALUE) < 0) {
            return minimumValue;
        } else {
            if (Intrinsics.compare((int) $this$coerceIn_u2dVKSA0NQ & UShort.MAX_VALUE, (int) 65535 & maximumValue) > 0) {
                return maximumValue;
            }
            return $this$coerceIn_u2dVKSA0NQ;
        }
    }

    /* renamed from: coerceIn-wuiCnnA  reason: not valid java name */
    public static final int m1292coerceInwuiCnnA(int $this$coerceIn_u2dwuiCnnA, ClosedRange<UInt> range) {
        Intrinsics.checkNotNullParameter(range, "range");
        if (range instanceof ClosedFloatingPointRange) {
            return ((UInt) RangesKt.coerceIn(UInt.m128boximpl($this$coerceIn_u2dwuiCnnA), (ClosedFloatingPointRange) range)).m185unboximpl();
        }
        if (range.isEmpty()) {
            throw new IllegalArgumentException("Cannot coerce value to an empty range: " + range + '.');
        } else if (UnsignedKt.uintCompare($this$coerceIn_u2dwuiCnnA, range.getStart().m185unboximpl()) < 0) {
            return range.getStart().m185unboximpl();
        } else {
            if (UnsignedKt.uintCompare($this$coerceIn_u2dwuiCnnA, range.getEndInclusive().m185unboximpl()) > 0) {
                return range.getEndInclusive().m185unboximpl();
            }
            return $this$coerceIn_u2dwuiCnnA;
        }
    }

    /* renamed from: coerceIn-JPwROB0  reason: not valid java name */
    public static final long m1287coerceInJPwROB0(long $this$coerceIn_u2dJPwROB0, ClosedRange<ULong> range) {
        Intrinsics.checkNotNullParameter(range, "range");
        if (range instanceof ClosedFloatingPointRange) {
            return ((ULong) RangesKt.coerceIn(ULong.m206boximpl($this$coerceIn_u2dJPwROB0), (ClosedFloatingPointRange) range)).m263unboximpl();
        }
        if (range.isEmpty()) {
            throw new IllegalArgumentException("Cannot coerce value to an empty range: " + range + '.');
        } else if (UnsignedKt.ulongCompare($this$coerceIn_u2dJPwROB0, range.getStart().m263unboximpl()) < 0) {
            return range.getStart().m263unboximpl();
        } else {
            if (UnsignedKt.ulongCompare($this$coerceIn_u2dJPwROB0, range.getEndInclusive().m263unboximpl()) > 0) {
                return range.getEndInclusive().m263unboximpl();
            }
            return $this$coerceIn_u2dJPwROB0;
        }
    }
}
