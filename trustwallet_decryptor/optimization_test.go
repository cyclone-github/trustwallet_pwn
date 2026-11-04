package main

import "testing"

func TestGPUBatchAlignment(t *testing.T) {
	for _, tc := range []struct{ wg, p, want int }{
		{32, 1, 32}, {32, 4, 8}, {32, 8, 4}, {64, 4, 16}, {32, 3, 32}, {1, 4, 1},
	} {
		got := tc.wg / gcdInt(tc.wg, tc.p)
		if got != tc.want {
			t.Errorf("workgroup=%d p=%d got alignment=%d want %d", tc.wg, tc.p, got, tc.want)
		}
	}
}

func TestLoadRealWorldSelfTestParameters(t *testing.T) {
	v, err := selfTestVault()
	if err != nil {
		t.Fatal(err)
	}
	if v.n != 16384 || v.r != 8 || v.p != 4 || v.dklen != 32 || len(v.presalt) == 0 {
		t.Fatalf("unexpected self-test KDF: n=%d r=%d p=%d dklen=%d pre=%v", v.n, v.r, v.p, v.dklen, v.presalt != nil)
	}
}
