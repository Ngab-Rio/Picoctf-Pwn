package androidx.emoji2.text.flatbuffer;

import com.android.tools.r8.annotations.SynthesizedClassV2;
import java.util.function.Supplier;

@SynthesizedClassV2(kind = 21, versionHash = "b9fe669522e76a1913eadf452da56796d42e756f2af239d12ad6b753581fecaa")
/* compiled from: D8$$SyntheticClass */
public final /* synthetic */ class Utf8Old$$ExternalSyntheticThreadLocal1 extends ThreadLocal {
    public final /* synthetic */ Supplier initialValueSupplier;

    public /* synthetic */ Utf8Old$$ExternalSyntheticThreadLocal1(Supplier supplier) {
        this.initialValueSupplier = supplier;
    }

    /* access modifiers changed from: protected */
    public /* synthetic */ Object initialValue() {
        return this.initialValueSupplier.get();
    }
}
