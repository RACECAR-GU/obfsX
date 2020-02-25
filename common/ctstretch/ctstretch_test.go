package ctstretch

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func main() {
	key := make([]byte, 16)
	rand.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	iv := make([]byte, block.BlockSize())
	rand.Read(iv)

	streamClient := cipher.NewCTR(block, iv)
	streamServer := cipher.NewCTR(block, iv)

	bias := float64(0.55)
	msgLens := []uint64{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17}

	outputNBits8 := []uint64{16, 24, 32, 40, 48, 56, 64}
	outputNBits16 := []uint64{32, 48, 64}

	for _, msgLen := range msgLens {
		for _, outputNBits := range outputNBits8 {
			runTest(msgLen, 8, outputNBits, bias, streamClient, streamServer)
		}

		for _, outputNBits := range outputNBits16 {
			runTest(msgLen, 16, outputNBits, bias, streamClient, streamServer)
		}
	}
}

func runTest(msgNBytes, inputBlockBits, outputBlockBits uint64, bias float64,
	streamClient, streamServer cipher.Stream) {

	clientTable16 := ctstretch.SampleBiasedStrings(outputBlockBits, 65536, bias, streamClient)
	serverTable16 := ctstretch.InvertTable(ctstretch.SampleBiasedStrings(outputBlockBits, 65536, bias, streamServer))

	var outputBlockBits8 uint64
	if inputBlockBits == 8 {
		outputBlockBits8 = outputBlockBits
	} else {
		outputBlockBits8 = outputBlockBits / 2
	}

	clientTable8 := ctstretch.SampleBiasedStrings(outputBlockBits8, 256, bias, streamClient)
	serverTable8 := ctstretch.InvertTable(ctstretch.SampleBiasedStrings(outputBlockBits8, 256, bias, streamServer))

	msg := make([]byte, msgNBytes)
	expandedNBytes := ctstretch.ExpandedNBytes(msgNBytes, inputBlockBits, outputBlockBits)
	compressedNBytes := ctstretch.CompressedNBytes(expandedNBytes, outputBlockBits, inputBlockBits)

	expanded := make([]byte, expandedNBytes)
	rand.Read(msg)
	compressed := make([]byte, compressedNBytes)

	ctstretch.ExpandBytes(msg[:], expanded, inputBlockBits, outputBlockBits, clientTable16, clientTable8, streamClient)
	ctstretch.CompressBytes(expanded, compressed, outputBlockBits, inputBlockBits, serverTable16, serverTable8, streamServer)

	if bytes.Equal(msg, compressed) {
		fmt.Println("Pass:", msgNBytes, inputBlockBits, outputBlockBits)
	} else {
		fmt.Println(msg, compressed)
		fmt.Println("Fail:", msgNBytes, inputBlockBits, outputBlockBits)
	}
}
