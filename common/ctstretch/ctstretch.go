package ctstretch

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math"
	"unsafe"
	"gitlab.com/yawning/obfs4.git/common/log"
)

// Swaps bits i and j in data.  Bit 0 is the first bit of data[0].
func BitSwap(data []byte, i, j uint64) error {

	if i == j {
		return nil
	}

	numBits := uint64(len(data) * 8)
	if i >= numBits || j >= numBits {
		return fmt.Errorf("ctstretch/bit_manip: index out of bounds")
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
	return nil
}

func UniformSample(a, b uint64, stream cipher.Stream) (uint64, error) {
	if a >= b {
		return nil, fmt.Errorf("ctstretch/bit_manip: invalid range")
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

	return a + (r % rnge), nil
}

func BitShuffle(data []byte, rng cipher.Stream, rev bool) error {
	numBits := uint64(len(data) * 8)

	shuffleIndices := make([]uint64, numBits-1)

	for idx := uint64(0); idx < (numBits - 1); idx = idx + 1 {
		shuffleIndices[idx], err = UniformSample(idx, numBits-1, rng)
		if err != nil {
			return err
		}
	}

	for idx := uint64(0); idx < (numBits - 1); idx = idx + 1 {

		kdx := uint64(0)

		if rev {
			kdx = (numBits - 2) - idx
		} else {
			kdx = idx
		}

		jdx := shuffleIndices[kdx]
		err := BitSwap(data, kdx, jdx)
		if err != nil {
			return err
		}
	}
	return nil
}

func PrintBits(data []byte) {
	for _, v := range data {
		fmt.Printf("%08b\n", v)
	}
}

// Bias of 0.8 means 80% probability of outputting 0
func SampleBiasedString(numBits uint64, bias float64, stream cipher.Stream) (uint64, error) {

	if numBits > 64 {
		return nil, fmt.Errorf("ctstretch/bit_manip: numBits out of range")
	}

	r := uint64(0)

	for idx := uint64(0); idx < numBits; idx++ {
		// Simulate a biased coin flip
		sample, err := UniformSample(0, math.MaxUint64-1, stream)
		if err != nil {
			return r, nil
		}
		x := float64(sample) / float64(math.MaxUint64-1)
		b := uint64(0)
		if x >= bias {
			b++
		}

		r ^= (b << idx)
	}

	return r, nil
}

func SampleBiasedStrings(numBits, n uint64, bias float64, stream cipher.Stream) []uint64 {
	vals := make([]uint64, n)
	m := make(map[uint64]bool)

	for idx := uint64(0); idx < n; idx += 1 {

		s := uint64(0)
		haveKey := true

		for haveKey == true {
			s = SampleBiasedString(numBits, bias, stream)
			_, haveKey = m[s]
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

func BytesToUInt16(data []byte, startIDx, endIDx uint64) (uint16, error) {
	if endIDx <= startIDx || (endIDx-startIDx) > 3 {
		return nil, fmt.Errorf("ctstretch/bit_manip: invalid range")
	}

	r := (endIDx - startIDx)

	if r == 1 {
		return uint16(data[startIDx]), nil
	}
	return binary.BigEndian.Uint16(data[startIDx:endIDx]), nil
}

func ExpandBytes(src, dst []byte, inputBlockBits, outputBlockBits uint64, table16, table8 []uint64, stream cipher.Stream) error {

	if inputBlockBits != 8 && inputBlockBits != 16 {
		return fmt.Errorf("ctstretch/bit_manip: input bit block size must be 8 or 16")
	}
	if outputBlockBits%8 != 0 || outputBlockBits > 64 {
		return fmt.Errorf("ctstretch/bit_manip: output block size must be a multiple of 8 and less than 64") // TODO: Change to error
	}

	srcNBytes := len(src)
	//dstNBytes := len(dst)

	inputBlockBytes := inputBlockBits / 8
	outputBlockBytes := outputBlockBits / 8

	//expansionFactor := float64(outputBlockBits) / float64(inputBlockBits)

	if srcNBytes == 0 {
		return nil
	}

	if srcNBytes == 1 && inputBlockBits == 16 {
		return ExpandBytes(src, dst, 8, outputBlockBits/2, table16, table8, stream)
	}

	if inputBlockBits == 16 && srcNBytes > 1 && srcNBytes%2 == 1 {
		err := ExpandBytes(src[0:srcNBytes-1], dst[0:uint64(srcNBytes-1)*outputBlockBytes/inputBlockBytes], inputBlockBits, outputBlockBits, table16, table8, stream)
		if err != nil {
			return err
		}
		return ExpandBytes(src[srcNBytes-1:], dst[uint64(srcNBytes-1)*outputBlockBytes/inputBlockBytes:], 8, outputBlockBits/2, table16, table8, stream)
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
		x, err := BytesToUInt16(src, inputIdx, inputIdx+inputBlockBytes)
		if err != nil {
			return err
		}
		tableVal := (*table)[x]
		// yuck :( no variable length casts in go.
		switch outputBlockBytes {
		case 2:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[2]byte)(unsafe.Pointer(&tableVal))[:])
		case 3:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[3]byte)(unsafe.Pointer(&tableVal))[:])
		case 4:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[4]byte)(unsafe.Pointer(&tableVal))[:])
		case 5:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[5]byte)(unsafe.Pointer(&tableVal))[:])
		case 6:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[6]byte)(unsafe.Pointer(&tableVal))[:])
		case 7:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[7]byte)(unsafe.Pointer(&tableVal))[:])
		case 8:
			copy(dst[outputIdx:outputIdx+outputBlockBytes], (*[8]byte)(unsafe.Pointer(&tableVal))[:])
		}

		err := BitShuffle(dst[outputIdx:outputIdx+outputBlockBytes], stream, false)
		if err != nil {
			return err
		}
		outputIdx += outputBlockBytes
	}
	return nil
}

func CompressBytes(src, dst []byte, inputBlockBits, outputBlockBits uint64, inversion16, inversion8 map[uint64]uint64, stream cipher.Stream) error {
	log.Debugf("Riverrun: 1")
	if inputBlockBits%8 != 0 || inputBlockBits > 64 {
		return fmt.Errorf("ctstretch/bit_manip: input block size must be a multiple of 8 and less than 64")
	}
	if outputBlockBits != 8 && outputBlockBits != 16 {
		return fmt.Errorf("ctstretch/bit_manip: output bit block size must be 8 or 16")
	}

	//compressionFactor := float64(outputBlockBits) / float64(inputBlockBits)
	log.Debugf("Riverrun: 2")
	srcNBytes := len(src)

	// dstNBytes := len(dst)
	inputBlockBytes := inputBlockBits / 8
	outputBlockBytes := outputBlockBits / 8

	halfBlock := (uint64(srcNBytes) % inputBlockBytes) != 0
	blocks := uint64(srcNBytes) / inputBlockBytes
	log.Debugf("Riverrun: 3")
	if blocks == 0 && halfBlock {
		log.Debugf("Riverrun: 3d")
		return CompressBytes(src, dst, inputBlockBits/2, outputBlockBits/2, inversion16, inversion8, stream)
	}

	if blocks >= 1 && halfBlock {
		log.Debugf("Riverrun: 3d2")
		endSrc := blocks * inputBlockBytes
		endDst := blocks * outputBlockBytes
		err := CompressBytes(src[0:endSrc], dst[0:endDst], inputBlockBits, outputBlockBits, inversion16, inversion8, stream)
		if err != nil {
			return err
		}
		return CompressBytes(src[endSrc:], dst[endDst:], inputBlockBits/2, outputBlockBits/2, inversion16, inversion8, stream)
	}

	/*
		if float64(dstNBytes)/float64(srcNBytes) < compressionFactor {
			panic("ctstretch/bit_manip: dst has insufficient size")
		}
	*/
	log.Debugf("Riverrun: 4")
	inputIdx := uint64(0)
	outputIdx := uint64(0)

	var inversion *map[uint64]uint64
	if outputBlockBits == 8 {
		inversion = &inversion8
	} else {
		inversion = &inversion16
	}
	log.Debugf("Riverrun: 5")
	for ; inputIdx < uint64(srcNBytes); inputIdx = inputIdx + inputBlockBytes {
		log.Debugf("Riverrun: 5a")
		err := BitShuffle(src[inputIdx:inputIdx+inputBlockBytes], stream, true)
		log.Debugf("Riverrun: 5b")
		if err != nil {
			log.Debugf("Riverrun: 5e")
			return err
		}

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
	log.Debugf("Riverrun: 6")
	return nil
}

func ExpandedNBytes(srcLen, inputBlockBits, outputBlockBits uint64) uint64 {
	return srcLen * (outputBlockBits / inputBlockBits)
}

func CompressedNBytes(expandedLen, inputBlockBits, outputBlockBits uint64) uint64 {
	return uint64(math.Ceil(float64(expandedLen) * (float64(outputBlockBits) / float64(inputBlockBits))))
}
