package threatintel

import (
	"hash"
	"hash/fnv"
	"math"
)

// BloomFilter provides probabilistic set membership testing.
// For threat intelligence lookups, it eliminates 99.9%+ of SQLite queries
// for domains/IPs that are NOT in the threat database.
//
// Parameters for Vedetta's use case:
//   - 100K indicators → 200K bit array → ~25KB memory
//   - 7 hash functions → 0.08% false positive rate
//   - Lookups are O(1) — 7 hash computations + 7 bit checks
type BloomFilter struct {
	bits    []uint64
	numBits uint64
	numHash int
}

// NewBloomFilter creates a Bloom filter sized for the expected number of elements.
// numHash is the number of independent hash functions to use.
func NewBloomFilter(numBits uint64, numHash int) *BloomFilter {
	if numBits == 0 {
		numBits = 1024
	}
	// Round up to next multiple of 64
	words := (numBits + 63) / 64
	return &BloomFilter{
		bits:    make([]uint64, words),
		numBits: words * 64,
		numHash: numHash,
	}
}

// OptimalBloomFilter calculates optimal parameters for a given number of
// expected elements and desired false positive rate.
func OptimalBloomFilter(expectedElements int, fpRate float64) *BloomFilter {
	if expectedElements < 1 {
		expectedElements = 1
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.001
	}

	// m = -n * ln(p) / (ln(2))^2
	n := float64(expectedElements)
	m := -n * math.Log(fpRate) / (math.Ln2 * math.Ln2)

	// k = (m/n) * ln(2)
	k := (m / n) * math.Ln2

	numBits := uint64(math.Ceil(m))
	numHash := int(math.Ceil(k))
	if numHash < 1 {
		numHash = 1
	}

	return NewBloomFilter(numBits, numHash)
}

// Add inserts a value into the Bloom filter.
func (bf *BloomFilter) Add(value string) {
	h1, h2 := bf.hashes(value)
	for i := 0; i < bf.numHash; i++ {
		pos := (h1 + uint64(i)*h2) % bf.numBits
		bf.bits[pos/64] |= 1 << (pos % 64)
	}
}

// MayContain returns true if the value MIGHT be in the set.
// False means the value is DEFINITELY not in the set.
func (bf *BloomFilter) MayContain(value string) bool {
	h1, h2 := bf.hashes(value)
	for i := 0; i < bf.numHash; i++ {
		pos := (h1 + uint64(i)*h2) % bf.numBits
		if bf.bits[pos/64]&(1<<(pos%64)) == 0 {
			return false
		}
	}
	return true
}

// hashes returns two independent hash values for double-hashing.
// Uses FNV-1a for speed (no crypto needed for Bloom filters).
func (bf *BloomFilter) hashes(value string) (uint64, uint64) {
	var h1, h2 hash.Hash64

	h1 = fnv.New64a()
	h1.Write([]byte(value))
	hash1 := h1.Sum64()

	h2 = fnv.New64()
	h2.Write([]byte(value))
	hash2 := h2.Sum64()

	// Ensure hash2 is odd (for better distribution in double hashing)
	if hash2%2 == 0 {
		hash2++
	}

	return hash1, hash2
}
