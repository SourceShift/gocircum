package securerandom

import (
	"errors"
	"testing"
	"time"
)

func TestInt(t *testing.T) {
	tests := []struct {
		name    string
		min     int
		max     int
		wantErr bool
	}{
		{"equal_bounds", 5, 5, false},
		{"valid_range", 1, 100, false},
		{"invalid_min_greater", 100, 50, true},
		{"negative_numbers", -10, -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := Int(tt.min, tt.max)

			// Check error status
			if (err != nil) != tt.wantErr {
				t.Errorf("Int(%v, %v) error = %v, wantErr %v", tt.min, tt.max, err, tt.wantErr)
				return
			}

			// Only check the value if no error was expected
			if !tt.wantErr {
				if val < tt.min || val > tt.max {
					t.Errorf("Int(%v, %v) = %v, outside range", tt.min, tt.max, val)
				}
			}
		})
	}

	// Distribution test for basic sanity check
	if !testing.Short() {
		min, max := 1, 100
		buckets := make([]int, max-min+1)
		iterations := 100000

		for i := 0; i < iterations; i++ {
			val, err := Int(min, max)
			if err != nil {
				t.Fatalf("Int(%v, %v) failed: %v", min, max, err)
			}
			if val < min || val > max {
				t.Fatalf("Int(%v, %v) returned %v which is outside range", min, max, val)
			}
			buckets[val-min]++
		}

		// Calculate chi-square statistic
		expectedPerBucket := float64(iterations) / float64(max-min+1)
		chiSquare := 0.0
		for _, count := range buckets {
			diff := float64(count) - expectedPerBucket
			chiSquare += (diff * diff) / expectedPerBucket
		}

		// For 99 degrees of freedom (100 buckets - 1), a chi-square value
		// less than 82.5 indicates a likely uniform distribution at p=0.01
		// Adjust threshold if changing range
		if chiSquare > 200 {
			t.Errorf("Distribution appears non-uniform, chi-square = %v", chiSquare)
		}
	}
}

func TestMustInt(t *testing.T) {
	// Test normal case
	val := MustInt(1, 100)
	if val < 1 || val > 100 {
		t.Errorf("MustInt(1, 100) = %v, outside range", val)
	}

	// Test panic case
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("MustInt with invalid range should panic")
		}
	}()

	// This should panic
	_ = MustInt(100, 1)
}

func TestFloat64(t *testing.T) {
	for i := 0; i < 1000; i++ {
		val, err := Float64()
		if err != nil {
			t.Fatalf("Float64() error = %v", err)
		}
		if val < 0 || val >= 1 {
			t.Errorf("Float64() = %v, outside range [0, 1)", val)
		}
	}
}

func TestMustFloat64(t *testing.T) {
	for i := 0; i < 1000; i++ {
		val := MustFloat64()
		if val < 0 || val >= 1 {
			t.Errorf("MustFloat64() = %v, outside range [0, 1)", val)
		}
	}
}

func TestBytes(t *testing.T) {
	buf := make([]byte, 32)
	if err := Bytes(buf); err != nil {
		t.Fatalf("Bytes() error = %v", err)
	}

	// Check that the buffer was filled
	zeroCount := 0
	for _, b := range buf {
		if b == 0 {
			zeroCount++
		}
	}

	// The probability of getting more than 5 zeros in 32 bytes is very small
	if zeroCount > 5 {
		t.Errorf("Bytes() filled buffer with suspicious data, %d zeros out of 32 bytes", zeroCount)
	}
}

func TestDuration(t *testing.T) {
	min := 10 * time.Millisecond
	max := 100 * time.Millisecond

	for i := 0; i < 1000; i++ {
		val, err := Duration(min, max)
		if err != nil {
			t.Fatalf("Duration(%v, %v) error = %v", min, max, err)
		}
		if val < min || val > max {
			t.Errorf("Duration(%v, %v) = %v, outside range", min, max, val)
		}
	}

	// Test error cases
	_, err := Duration(max, min)
	if err == nil {
		t.Errorf("Duration(%v, %v) should return error", max, min)
	}
}

func TestMustDuration(t *testing.T) {
	min := 10 * time.Millisecond
	max := 100 * time.Millisecond

	val := MustDuration(min, max)
	if val < min || val > max {
		t.Errorf("MustDuration(%v, %v) = %v, outside range", min, max, val)
	}

	// Test panic case
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("MustDuration with invalid range should panic")
		}
	}()

	// This should panic
	_ = MustDuration(max, min)
}

func TestShuffle(t *testing.T) {
	// Test string slice
	strings := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	stringsCopy := make([]string, len(strings))
	copy(stringsCopy, strings)

	err := Shuffle(strings, func(i, j int) {
		strings[i], strings[j] = strings[j], strings[i]
	})
	if err != nil {
		t.Fatalf("Shuffle() error = %v", err)
	}

	// Check that the slice was actually shuffled
	different := false
	for i := range strings {
		if strings[i] != stringsCopy[i] {
			different = true
			break
		}
	}
	if !different {
		t.Errorf("Shuffle() didn't appear to shuffle the slice")
	}

	// Check that no elements were lost
	seen := make(map[string]bool)
	for _, s := range strings {
		seen[s] = true
	}
	for _, s := range stringsCopy {
		if !seen[s] {
			t.Errorf("Element %s was lost during shuffle", s)
		}
	}
}

func TestMustShuffle(t *testing.T) {
	// Test int slice
	ints := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	intsCopy := make([]int, len(ints))
	copy(intsCopy, ints)

	MustShuffle(ints, func(i, j int) {
		ints[i], ints[j] = ints[j], ints[i]
	})

	// Check that the slice was actually shuffled
	different := false
	for i := range ints {
		if ints[i] != intsCopy[i] {
			different = true
			break
		}
	}
	if !different {
		t.Errorf("MustShuffle() didn't appear to shuffle the slice")
	}
}

func TestFailSecurely(t *testing.T) {
	err := errors.New("random generation failed")
	defaultVal := 42
	result := FailSecurely(err, defaultVal, "test context")

	if val, ok := result.(int); !ok || val != defaultVal {
		t.Errorf("FailSecurely() = %v, want %v", result, defaultVal)
	}
}
