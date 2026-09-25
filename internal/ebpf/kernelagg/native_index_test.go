package kernelagg

import (
	"math"
	"math/big"
	"testing"
)

func TestTheExportedBucketContainsTheDurationInSeconds(t *testing.T) {
	base := math.Pow(2, 1.0/8)
	for _, ns := range []uint64{
		100, 137, 999, 1000, 1001, 12_345, 250_000, 999_999, 1_000_000,
		40_000_000, 99_999_999, 100_000_000, 150_000_000, 999_999_999,
		1_000_000_000, 1_000_000_001, 7_500_000_000, 30_000_000_000, 3_600_000_000_000,
	} {
		seconds := float64(ns) / 1e9
		index := NativeIndex(BucketIndex(ns))
		upper := math.Pow(base, float64(index))
		lower := math.Pow(base, float64(index-1))
		if seconds > upper*(1+1e-9) || seconds <= lower*(1-1e-9) {
			t.Errorf("%dns = %gs was exported in bucket %d, (%g, %g].\n\nA native bucket i "+
				"holds (2^((i-1)/8), 2^(i/8)] seconds. Exporting the nanosecond index unchanged "+
				"put a 150ms RTT under a bound of 146 million seconds, so no quantile or rule "+
				"could read the distribution.", ns, seconds, index, lower, upper)
		}
	}
}

func TestScaledUnitsMatchTheExactConversion(t *testing.T) {
	for _, ns := range []uint64{1, 999, 1_000_000, 999_999_999, 1_000_000_000, 86_400_000_000_000} {
		want := float64(ns) * math.Exp2(30) / 1e9
		got := float64(ScaledUnits(ns))
		if math.Abs(got-want) > want*1e-6+1 {
			t.Errorf("ScaledUnits(%d) = %g, want %g", ns, got, want)
		}
	}
	if ScaledUnits(0) != 0 {
		t.Error("zero did not scale to zero")
	}
	for _, ns := range []uint64{1_000_000_000, 7_999_999_999, 86_400_000_000_000, 1 << 62} {
		exact := new(big.Int).Div(new(big.Int).Mul(new(big.Int).SetUint64(ns), big.NewInt(1<<30)), big.NewInt(1e9))
		if got := ScaledUnits(ns); got != exact.Uint64() {
			t.Errorf("ScaledUnits(%d) = %d, want exactly %s; the kernel computes the same integer "+
				"steps, so any rounding difference would put the two sides in different buckets", ns, got, exact)
		}
	}
}
