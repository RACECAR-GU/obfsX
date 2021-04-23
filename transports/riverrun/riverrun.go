package riverrun

import (
	"net"
	"fmt"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"encoding/binary"
	"github.com/RACECAR-GU/obfsX/common/drbg"
	"github.com/RACECAR-GU/obfsX/common/log"
	"github.com/RACECAR-GU/obfsX/common/ctstretch"
	f "github.com/RACECAR-GU/obfsX/common/framing"
)

const (
	PacketTypePayload = iota
)

// Implements the net.Conn interface
type Conn struct {
	// Embeds a net.Conn and inherits its members.
	net.Conn

	bias float64

	Encoder *riverrunEncoder
	Decoder *riverrunDecoder
}

func NewConn(conn net.Conn, isServer bool, seed *drbg.Seed) (*Conn, error) {

	xdrbg, err := drbg.NewHashDrbg(seed)
	if err != nil {
		return nil, err
	}
	rng := rand.New(xdrbg)
	key := make([]byte, 16)
	rng.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, block.BlockSize())
	rng.Read(iv)

	stream := cipher.NewCTR(block, iv)

	// FIXME: Input and output block bits are randomly selected from valid options,
	//        there may be a more optimal selection methedology/initial subset
	compressedBlockBits := uint64((rng.Intn(2)+1) * 8)

	var expandedBlockBits uint64
	var expandedBlockBits8 uint64
	if compressedBlockBits == 8 {
		expandedBlockBits = uint64((rng.Intn(7)+2) * 8)
		expandedBlockBits8 = compressedBlockBits
	} else {
		expandedBlockBits = uint64((rng.Intn(3)+2) * 16)
		expandedBlockBits8 = compressedBlockBits / 2
	}

	bias := rng.Float64() * .7 + .15

	log.Infof("rr: Set bias to %f, compressed block bits to %d, expanded block bits to %d", bias, expandedBlockBits, compressedBlockBits)

	table8, err := ctstretch.SampleBiasedStrings(expandedBlockBits8, 256, bias, stream)
	if err != nil {
		return nil, err
	}
	log.Debugf("riverrun: table8 prepped")
	table16, err := ctstretch.SampleBiasedStrings(expandedBlockBits, 65536, bias, stream)
	if err != nil {
		return nil, err
	}
	log.Debugf("riverrun: table16 prepped")

	var readStream, writeStream cipher.Stream
	readKey := make([]byte, drbg.SeedLength)
	writeKey := make([]byte, drbg.SeedLength)
	log.Debugf("riverrun: r/w keys made")
	// XXX: The only distinction between the read and write streams is the iv... is this secure?
	if isServer {
		readStream = stream
		rng.Read(iv)
		writeStream = cipher.NewCTR(block, iv)
		rng.Read(readKey)
		rng.Read(writeKey)
	} else {
		writeStream = stream
		rng.Read(iv)
		readStream = cipher.NewCTR(block, iv)
		rng.Read(writeKey)
		rng.Read(readKey)
	}
	log.Debugf("riverrun: Loaded keys properly")
	rr := new(Conn)
	rr.Conn = conn
	rr.bias = bias
	// Encoder
	rr.Encoder = newRiverrunEncoder(writeKey, writeStream, table8, table16, compressedBlockBits, expandedBlockBits)
	log.Debugf("riverrun: Encoder initialized")
	// Decoder
	rr.Decoder = newRiverrunDecoder(readKey, readStream, ctstretch.InvertTable(table8), ctstretch.InvertTable(table16), compressedBlockBits, expandedBlockBits)
	log.Debugf("riverrun: Initialized")
	return rr, nil
}

type riverrunEncoder struct {
	f.BaseEncoder

	writeStream cipher.Stream

	table8 []uint64
	table16 []uint64

	compressedBlockBits uint64
	expandedBlockBits uint64
}
func (encoder *riverrunEncoder) payloadOverhead(payloadLen int) int {
	return int(ctstretch.ExpandedNBytes(uint64(payloadLen), encoder.compressedBlockBits, encoder.expandedBlockBits)) - payloadLen
}
func (decoder *riverrunDecoder) payloadOverhead(payloadLen int) int {
	return int(ctstretch.ExpandedNBytes(uint64(payloadLen), decoder.compressedBlockBits, decoder.expandedBlockBits)) - payloadLen
}

func newRiverrunEncoder(key []byte, writeStream cipher.Stream, table8, table16 []uint64, compressedBlockBits, expandedBlockBits uint64) *riverrunEncoder {
	encoder := new(riverrunEncoder)

	encoder.Drbg = f.GenDrbg(key[:])
	encoder.MaxPacketPayloadLength = int(ctstretch.CompressedNBytes_floor(f.MaximumSegmentLength - ctstretch.ExpandedNBytes(uint64(f.LengthLength), compressedBlockBits, expandedBlockBits), expandedBlockBits, compressedBlockBits))
	encoder.LengthLength = int(ctstretch.ExpandedNBytes(uint64(f.LengthLength), compressedBlockBits, expandedBlockBits))
	encoder.PayloadOverhead = encoder.payloadOverhead

	encoder.Encode = encoder.encode
	encoder.ProcessLength = encoder.processLength
	encoder.ChopPayload = encoder.makePayload

	encoder.writeStream = writeStream
	encoder.table8 = table8
	encoder.table16 = table16
	encoder.compressedBlockBits = compressedBlockBits
	encoder.expandedBlockBits = expandedBlockBits

	encoder.Type = "rr"

	return encoder
}

func (encoder *riverrunEncoder) processLength(length uint16) ([]byte, error) {
	lengthBytes := make([]byte, f.LengthLength)
	binary.BigEndian.PutUint16(lengthBytes[:], length)
	lengthBytesEncoded := make([]byte, encoder.LengthLength)
	err := ctstretch.ExpandBytes(lengthBytes[:], lengthBytesEncoded, encoder.compressedBlockBits, encoder.expandedBlockBits, encoder.table16, encoder.table8, encoder.writeStream, rand.Int())
	return lengthBytesEncoded, err
}

func (encoder *riverrunEncoder) encode(frame, payload []byte) (n int, err error) {
	tb := rand.Int()
	expandedNBytes := int(ctstretch.ExpandedNBytes(uint64(len(payload)), encoder.compressedBlockBits, encoder.expandedBlockBits))
	frameLen := encoder.LengthLength + expandedNBytes
	log.Debugf("Encoding frame of length %d, with payload of length %d. TB: %d", frameLen, expandedNBytes, tb)
	err = ctstretch.ExpandBytes(payload[:], frame, encoder.compressedBlockBits, encoder.expandedBlockBits, encoder.table16, encoder.table8, encoder.writeStream, tb)
	if err != nil {
		return 0, err
	}
	return expandedNBytes, err
}
func (encoder *riverrunEncoder) makePayload(pktType uint8, payload []byte) []byte {
	if pktType != PacketTypePayload {
		panic(fmt.Sprintf("BUG: pktType was not packetTypePayload for Riverrun"))
	}
	return payload[:]
}

type riverrunDecoder struct {
	f.BaseDecoder

	readStream cipher.Stream

	revTable8 map[uint64]uint64
	revTable16 map[uint64]uint64

	compressedBlockBits uint64
	expandedBlockBits uint64
}

func newRiverrunDecoder(key []byte, readStream cipher.Stream, revTable8, revTable16 map[uint64]uint64, compressedBlockBits, expandedBlockBits uint64) *riverrunDecoder {
	decoder := new(riverrunDecoder)

	decoder.Drbg = f.GenDrbg(key[:])
	decoder.LengthLength = int(ctstretch.ExpandedNBytes(uint64(f.LengthLength), compressedBlockBits, expandedBlockBits))
	decoder.MinPayloadLength = int(ctstretch.ExpandedNBytes(uint64(1), compressedBlockBits, expandedBlockBits))
	decoder.PacketOverhead = 0 // f.LengthLength
	decoder.MaxFramePayloadLength = f.MaximumSegmentLength - decoder.LengthLength

	// NextLength is set programatically
	// NextLengthInvalid is set programatically

	decoder.PayloadOverhead = decoder.payloadOverhead

	decoder.DecodeLength = decoder.decodeLength
	decoder.DecodePayload = decoder.decodePayload
	decoder.ParsePacket = decoder.parsePacket
	decoder.Cleanup = decoder.cleanup

	decoder.InitBuffers()

	decoder.readStream = readStream
	decoder.revTable8 = revTable8
	decoder.revTable16 = revTable16
	decoder.compressedBlockBits = compressedBlockBits
	decoder.expandedBlockBits = expandedBlockBits

	return decoder
}

func (decoder *riverrunDecoder) cleanup() error {
	return nil
}

func (decoder *riverrunDecoder) decodeLength(lengthBytes []byte) (uint16, error) {
	var decodedBytes [f.LengthLength]byte
	err := decoder.compressBytes(lengthBytes[:decoder.LengthLength], decodedBytes[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(decodedBytes[:f.LengthLength]), err
}

func (decoder *riverrunDecoder) parsePacket(decoded []byte, decLen int) error {
	/*
	originalNBytes := binary.BigEndian.Uint16(decoded[:f.LengthLength]) // TODO: Ensure this is encoded
	if int(originalNBytes) > decLen-decoder.PacketOverhead {
		return f.InvalidPayloadLengthError(int(originalNBytes))
	}
	*/
	decoder.ReceiveDecodedBuffer.Write(decoded[decoder.PacketOverhead : decLen])
	return nil
}

func (decoder *riverrunDecoder) decodePayload(frames *bytes.Buffer) ([]byte, error) {
	//var frame []byte
	//var frameLen int
	frameLen, frame, err := decoder.GetFrame(frames)
	if err != nil {
		return nil, err
	}

	compressedNBytes := ctstretch.CompressedNBytes(uint64(frameLen), decoder.expandedBlockBits, decoder.compressedBlockBits)
	decodedPayload := make([]byte, compressedNBytes)
	err = decoder.compressBytes(frame[:frameLen], decodedPayload[:compressedNBytes])
	if err != nil {
		log.Debugf("Max payload length is %d", int(ctstretch.CompressedNBytes_floor(f.MaximumSegmentLength - ctstretch.ExpandedNBytes(uint64(f.LengthLength), decoder.compressedBlockBits, decoder.expandedBlockBits), decoder.expandedBlockBits, decoder.compressedBlockBits)))
		log.Debugf("CompressedNBytes: %d", compressedNBytes)
		log.Debugf("Got payload of len %d", frameLen)
		return nil, err
	}

	return decodedPayload[:], nil
}

func (decoder *riverrunDecoder) compressBytes(raw, res []byte) error {
	return ctstretch.CompressBytes(raw, res, decoder.expandedBlockBits, decoder.compressedBlockBits, decoder.revTable16, decoder.revTable8, decoder.readStream, rand.Int())
}

func (rr *Conn) Write(b []byte) (n int, err error) {

	var frameBuf bytes.Buffer
	frameBuf, n, err = rr.Encoder.Chop(b, PacketTypePayload)
	if err != nil {
		return
	}

	_, err = rr.Conn.Write(frameBuf.Bytes())

	//log.Debugf("Riverrun: %d expanded to %d ->", n, lowerConnN)
	// TODO: What does spec say about returned numbers?
	//	 Should they be bytes written, or the raw bytes before expansion expanded?
	// Idea: Bytes written (raw), Bytes written (processed), err - raw bytes is equivalent to old n
	return
}

func (rr *Conn) Read(b []byte) (int, error) {
	//originalLen := len(b)
	n, err := rr.Decoder.Read(b, rr.Conn)
	//log.Debugf("Riverrun: %d compressed to %d <-", originalLen, n)
	return n, err
}
