package graylog

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"unicode"
)

// START 1 OMIT
// Client is a Writer for graylog over UDP or other Packet Connection
type Client struct {
	instanceID [4]byte
	addr       net.Addr
	conn       net.PacketConn

	countMux     sync.Mutex
	messageCount uint32

	writeMux sync.Mutex   // HLupdated
	zip      *gzip.Writer // HLupdated
	buf      bytes.Buffer // HLupdated
}

// END 1 OMIT

// Config is used to set up a new Client
type Config struct {
	CompressionLevel int
	ServerAddr       net.Addr
	ClientPacketConn net.PacketConn
}

// New creates a Client with the Config provided
func New(c Config) (*Client, error) {
	if c.ClientPacketConn == nil {
		return nil, fmt.Errorf("cannot create new Client without a connection")
	}

	if c.CompressionLevel != gzip.NoCompression &&
		c.CompressionLevel != gzip.DefaultCompression &&
		(c.CompressionLevel > gzip.BestCompression || c.CompressionLevel < gzip.BestSpeed) {
		return nil, fmt.Errorf(
			"compression level of %d is not a valid compression level",
			c.CompressionLevel,
		)
	}

	// START 2 OMIT
	gl := &Client{
		addr: c.ServerAddr,
		conn: c.ClientPacketConn,
	}
	gl.zip, _ = gzip.NewWriterLevel(&gl.buf, c.CompressionLevel) // HLupdated
	// END 2 OMIT

	if _, err := rand.Read(gl.instanceID[0:4]); err != nil {
		return nil, fmt.Errorf("creating unique ID for logging client: %+v", err)
	}

	return gl, nil
}

// START 3 OMIT
// Write sends the contents of a byte slice over a Packet Connection with the graylog protocol.
func (gl *Client) Write(p []byte) (int, error) {
	if len(p) == 0 { // OMIT
		return 0, nil // OMIT
	} // OMIT
	if !bytes.HasSuffix(p, []byte("\n")) { // OMIT
		return 0, ErrMissingNewline // OMIT
	} // OMIT
	// OMIT
	gl.writeMux.Lock() // HLupdated
	defer func() {     // HLupdated
		gl.buf.Reset()        // HLupdated
		gl.zip.Reset(&gl.buf) // HLupdated
		gl.writeMux.Unlock()  // HLupdated
	}() // HLupdated
	n, err := gl.zip.Write(bytes.TrimFunc(p, unicode.IsSpace))
	gl.zip.Close()
	if err != nil && err != io.EOF {
		return 0, err
	}

	length := gl.buf.Len()
	count, rem := length/maxChunkSize, length%maxChunkSize
	if rem > 0 {
		count++
	}

	if count > maxChunkCount {
		return 0, fmt.Errorf("message exceeds maximum size, %d > %d", length, maxChunkCount*maxChunkSize)
	}

	// END 3 OMIT

	id := gl.messageID()
	packet := make([]byte, 0, mtuSize)
	chunk := make([]byte, maxChunkSize)
	for i := 0; i < count; i++ {
		packet = append(packet, gelfMagicByteA, gelfMagicByteB) // magic GELF bytes
		packet = append(packet, id[0:8]...)
		packet = append(packet, uint8(i), uint8(count)) // sequence

		chunkSize, err := gl.buf.Read(chunk)
		if err != nil && err != io.EOF {
			return 0, fmt.Errorf("reading into chunked response payload: %+v", err)
		}
		packet = append(packet, chunk[:chunkSize]...)

		if _, err := gl.conn.WriteTo(packet, gl.addr); err != nil {
			return 0, fmt.Errorf("writing to udp connection: %+v", err)
		}

		packet = packet[:0]
		chunk = chunk[:maxChunkSize]
	}

	return n, nil
}

var ErrMissingNewline = errors.New("missing newline terminating write")

func (gl *Client) messageID() (id [8]byte) {
	copy(id[0:4], gl.instanceID[0:4])
	gl.countMux.Lock()
	gl.messageCount++
	count := make([]byte, 4)
	binary.LittleEndian.PutUint32(count, gl.messageCount)
	copy(id[4:8], count)
	gl.countMux.Unlock()
	return id
}

const (
	mtuSize        = 1500
	maxChunkSize   = 1420 // based on MTU of 1500 and chunked GELF over UDP
	maxChunkCount  = 128  // based on 1-byte int sequence max
	gelfMagicByteA = 0x1e
	gelfMagicByteB = 0x0f
)
