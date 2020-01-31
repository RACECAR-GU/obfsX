package ctstretch

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math"
	"unsafe"
)

// Swaps bits i and j in data.  Bit 0 is the first bit of data[0].
func BitSwap(data []byte, i, j uint64) {

	if i == j {
		return
	}

	numBits := uint64(len(data) * 8)
	if i >= numBits || j >= numBits {
		panic("ctstretch/bit_manip: index out of bounds")
	}

	var iByte *byte = &data[i/8]
	var jByte *byte = &data[j/8]
	var iBitIdx uint64 = i % 8
	var jBitIdx uint64 = j % 8

	// If we are swapping bits a and b, the least-sig bit of c now contains
	// a XOR b
	var c byte = ((*iByte >> iBitIdx) & byte(1)) ^ ((*jByte >> jBitIdx) & byte(1))

	*iByte = *iByte ^ (c << iBitIdx)
	*jByte = *jByte ^ (c << jBitIdx)
}

func UniformSample(a, b uint64, stream cipher.Stream) uint64 {
	if a >= b {
		panic("ctstretch/bit_manip: invalid range")
	}

	rnge := (b - a + 1)

	var z uint64 = 0
	var r uint64 = 0
	zBytes := (*[unsafe.Sizeof(z)]byte)(unsafe.Pointer(&z))[:]
	rBytes := (*[unsafe.Sizeof(r)]byte)(unsafe.Pointer(&r))[:]

	stream.XORKeyStream(rBytes, zBytes)

	for cont := true; cont; cont = (r >= (math.MaxUint64 - (math.MaxUint64 % rnge))) {
		stream.XORKeyStream(rBytes, zBytes)
	}

	return a + (r % rnge)
}

func BitShuffle(data []byte, rng cipher.Stream, rev bool) {
	numBits := uint64(len(data) * 8)

	shuffleIndices := make([]uint64, numBits-1)

	for idx := uint64(0); idx < (numBits - 1); idx = idx + 1 {
		shuffleIndices[idx] = UniformSample(idx, numBits-1, rng)
	}

	for idx := uint64(0); idx < (numBits - 1); idx = idx + 1 {

		kdx := uint64(0)

		if rev {
			kdx = (numBits - 2) - idx
		} else {
			kdx = idx
		}

		jdx := shuffleIndices[kdx]
		BitSwap(data, kdx, jdx)
	}
}

func PrintBits(data []byte) {
	for _, v := range data {
		fmt.Printf("%08b\n", v)
	}
}

// Bias of 0.8 means 80% probability of outputting 0
func SampleBiasedString(numBits uint64, bias float64, stream cipher.Stream) uint64 {

	if numBits > 64 {
		panic("ctstretch/bit_manip: numBits out of range")
	}

	r := uint64(0)

	for idx := uint64(0); idx < numBits; idx += 1 {
		// Simulate a biased coin flip
		x := float64(UniformSample(0, math.MaxUint64-1, stream)) / float64(math.MaxUint64-1)
		b := uint64(0)
		if x >= bias {
			b += 1
		}

		r ^= (b << idx)
	}

	return r
}

func SampleBiasedStrings(numBits, n uint64, bias float64, stream cipher.Stream) []uint64 {
	vals := make([]uint64, n)
	m := make(map[uint64]bool)

	for idx := uint64(0); idx < n; idx += 1 {

		s := uint64(0)
		have_key := true

		for have_key == true {
			s = SampleBiasedString(numBits, bias, stream)
			_, have_key = m[s]
		}

		vals[idx] = s
		m[s] = true
	}

	return vals
}

func InvertTable(vals []uint64) map[uint64]uint64 {
	m := make(map[uint64]uint64)

	for idx, val := range vals {
		m[val] = uint64(idx)
	}

	return m
}

func BytesToUInt16(data []byte, start_idx, end_idx uint64) uint16 {
	if end_idx <= start_idx || (end_idx-start_idx) > 3 {
		panic("ctstretch/bit_manip: invalid range")
	}

	r := (end_idx - start_idx)

	if r == 1 {
		return uint16(data[start_idx])
	} else { // r == 2
		return binary.BigEndian.Uint16(data[start_idx:end_idx])
	}
}

func ExpandBytes(src, dst []byte, inputBlockBits, outputBlockBits uint64, table16, table8 []uint64, stream cipher.Stream) {
	if inputBlockBits != 8 && inputBlockBits != 16 {
		panic("ctstretch/bit_manip: input bit block size must be 8 or 16")
	}
	if outputBlockBits%8 != 0 || outputBlockBits > 64 {
		panic("ctstretch/bit_manip: output block size must be a multiple of 8 and less than 64")
	}

	srcNBytes := len(src)
	//dstNBytes := len(dst)

	inputBlockBytes := inputBlockBits / 8
	outputBlockBytes := outputBlockBits / 8

	//expansionFactor := float64(outputBlockBits) / float64(inputBlockBits)

	if srcNBytes == 0 {
		return
	}

	if srcNBytes == 1 && inputBlockBits == 16 {
		ExpandBytes(src, dst, 8, outputBlockBits/2, table16, table8, stream)
		return
	}

	if inputBlockBits == 16 && srcNBytes > 1 && srcNBytes%2 == 1 {
		ExpandBytes(src[0:srcNBytes-1], dst[0:uint64(srcNBytes-1)*outputBlockBytes/inputBlockBytes], inputBlockBits, outputBlockBits, table16, table8, stream)
		ExpandBytes(src[srcNBytes-1:], dst[uint64(srcNBytes-1)*outputBlockBytes/inputBlockBytes:], 8, outputBlockBits/2, table16, table8, stream)
		return
	}

	/*
		if float64(dstNBytes)/float64(srcNBytes) < expansionFactor {
			fmt.Println(dstNBytes)
			fmt.Println(srcNBytes)
			fmt.Println(expansionFactor)
			panic("ctstretch/bit_manip: dst has insufficient size")
		}
	*/

	var table *[]uint64
	if inputBlockBits == 8 {
		table = &table8
	} else {
		table = &table16
	}

	inputIdx := uint64(0)
	outputIdx := uint64(0)

	for ; inputIdx < uint64(srcNBytes); inputIdx = inputIdx + inputBlockBytes {
		x := BytesToUInt16(src, inputIdx, inputIdx+inputBlockBytes)
		table_val := (*table)[x]
		// yuck :( no variable length casts in go.
		switch outputBlockBytes {
		case 2:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[2]byte)(unsafe.Pointer(&table_val))[:])
		case 3:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[3]byte)(unsafe.Pointer(&table_val))[:])
		case 4:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[4]byte)(unsafe.Pointer(&table_val))[:])
		case 5:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[5]byte)(unsafe.Pointer(&table_val))[:])
		case 6:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[6]byte)(unsafe.Pointer(&table_val))[:])
		case 7:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[7]byte)(unsafe.Pointer(&table_val))[:])
		case 8:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[8]byte)(unsafe.Pointer(&table_val))[:])
		}

		BitShuffle(dst[outputIdx:outputIdx+outputBlockBytes], stream, false)
		outputIdx += outputBlockBytes
	}
}

func CompressBytes(src, dst []byte, inputBlockBits, outputBlockBits uint64, inversion16, inversion8 map[uint64]uint64, stream cipher.Stream) {
	if inputBlockBits%8 != 0 || outputBlockBits > 64 {
		panic("ctstretch/bit_manip: input block size must be a multiple of 8 and less than 64")
	}
	if outputBlockBits != 8 && outputBlockBits != 16 {
		panic("ctstretch/bit_manip: output bit block size must be 8 or 16")
	}

	//compressionFactor := float64(outputBlockBits) / float64(inputBlockBits)

	srcNBytes := len(src)

	// dstNBytes := len(dst)
	inputBlockBytes := inputBlockBits / 8
	outputBlockBytes := outputBlockBits / 8

	half_block := (uint64(srcNBytes) % inputBlockBytes) != 0
	blocks := uint64(srcNBytes) / inputBlockBytes

	if blocks == 0 && half_block {
		CompressBytes(src, dst, inputBlockBits/2, outputBlockBits/2, inversion16, inversion8, stream)
		return
	}

	if blocks >= 1 && half_block {
		endSrc := blocks * inputBlockBytes
		endDst := blocks * outputBlockBytes
		CompressBytes(src[0:endSrc], dst[0:endDst], inputBlockBits, outputBlockBits, inversion16, inversion8, stream)
		CompressBytes(src[endSrc:], dst[endDst:], inputBlockBits/2, outputBlockBits/2, inversion16, inversion8, stream)
		return
	}

	/*
		if float64(dstNBytes)/float64(srcNBytes) < compressionFactor {
			panic("ctstretch/bit_manip: dst has insufficient size")
		}
	*/

	inputIdx := uint64(0)
	outputIdx := uint64(0)

	var inversion *map[uint64]uint64
	if outputBlockBits == 8 {
		inversion = &inversion8
	} else {
		inversion = &inversion16
	}

	for ; inputIdx < uint64(srcNBytes); inputIdx = inputIdx + inputBlockBytes {
		BitShuffle(src[inputIdx:inputIdx+inputBlockBytes], stream, true)

		var x, y uint64
		x = 0
		y = 0
		copy((*[unsafe.Sizeof(x)]byte)(unsafe.Pointer(&x))[:],
			src[inputIdx:inputIdx+inputBlockBytes])
		y = (*inversion)[x]

		if outputBlockBytes == 1 {
			dst[outputIdx] = uint8(y)
		} else {
			binary.BigEndian.PutUint16(dst[outputIdx:outputIdx+outputBlockBytes], uint16(y))
		}

		outputIdx += outputBlockBytes
	}
}

func ExpandedNBytes(srcLen, inputBlockBits, outputBlockBits uint64) uint64 {
	return srcLen * (outputBlockBits / inputBlockBits)
}

func CompressedNBytes(expandedLen, inputBlockBits, outputBlockBits uint64) uint64 {
	return uint64(math.Ceil(float64(expandedLen) * (float64(outputBlockBits) / float64(inputBlockBits))))
}
