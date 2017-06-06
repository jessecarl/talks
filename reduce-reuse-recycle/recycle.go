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

	msgPool sync.Pool // HLupdated
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
	gl.msgPool = sync.Pool{New: func() interface{} { // HLupdated
		msg := new(message)                                            // HLupdated
		msg.zip, _ = gzip.NewWriterLevel(&msg.buf, c.CompressionLevel) // HLupdated
		return msg                                                     // HLupdated
	}}
	// END 2 OMIT

	if _, err := rand.Read(gl.instanceID[0:4]); err != nil {
		return nil, fmt.Errorf("creating unique ID for logging client: %+v", err)
	}

	return gl, nil
}

// START 5 OMIT
// Write sends the contents of a byte slice over a Packet Connection with the graylog protocol.
func (gl *Client) Write(p []byte) (int, error) {
	if len(p) == 0 { // OMIT
		return 0, nil // OMIT
	} // OMIT
	if !bytes.HasSuffix(p, []byte("\n")) { // OMIT
		return 0, ErrMissingNewline // OMIT
	} // OMIT
	msg := gl.newMessage()    // HLupdated
	defer gl.freeMessage(msg) // HLupdated
	return msg.Write(p)
}

// END 5 OMIT

var ErrMissingNewline = errors.New("missing newline terminating write")

// START 4 OMIT
func (gl *Client) newMessage() *message {
	msg := gl.msgPool.Get().(*message) // HLupdated
	msg.id = gl.messageID()
	msg.conn = gl.conn
	msg.addr = gl.addr
	return msg
}

func (gl *Client) freeMessage(msg *message) {
	msg.buf.Reset()                    // HLupdated
	msg.zip.Reset(&msg.buf)            // HLupdated
	copy(msg.id[0:8], make([]byte, 8)) // HLupdated
	gl.msgPool.Put(msg)                // HLupdated
}

// END 4 OMIT

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

// START 3 OMIT
type message struct { // HLupdated
	buf  bytes.Buffer
	zip  *gzip.Writer
	id   [8]byte
	conn net.PacketConn
	addr net.Addr
}

// END 3 OMIT

// START 6 OMIT
func (msg *message) Write(p []byte) (int, error) { // HLupdated
	n, err := msg.zip.Write(bytes.TrimFunc(p, unicode.IsSpace))
	msg.zip.Close()
	if err != nil && err != io.EOF { // OMIT
		return 0, err // OMIT
	} // OMIT
	// OMIT
	// …
	length := msg.buf.Len()                                // OMIT
	count, rem := length/maxChunkSize, length%maxChunkSize // OMIT
	if rem > 0 {                                           // OMIT
		count++ // OMIT
	} // OMIT
	// OMIT
	if count > maxChunkCount { // OMIT
		return 0, fmt.Errorf("message exceeds maximum size, %d > %d", length, maxChunkCount*maxChunkSize) // OMIT
	} // OMIT
	// OMIT
	packet := make([]byte, 0, mtuSize)  // OMIT
	chunk := make([]byte, maxChunkSize) // OMIT
	for i := 0; i < count; i++ {
		packet = append(packet, gelfMagicByteA, gelfMagicByteB) // magic GELF bytes // OMIT
		packet = append(packet, msg.id[0:8]...)                 // OMIT
		packet = append(packet, uint8(i), uint8(count))         // sequence // OMIT
		// OMIT
		chunkSize, err := msg.buf.Read(chunk) // …
		if err != nil && err != io.EOF {      // OMIT
			return 0, fmt.Errorf("reading into chunked response payload: %+v", err) // OMIT
		} // OMIT
		packet = append(packet, chunk[:chunkSize]...) // …
		// OMIT
		if _, err := msg.conn.WriteTo(packet, msg.addr); err != nil {
			return 0, fmt.Errorf("writing to udp connection: %+v", err)
		}
		// OMIT
		packet = packet[:0]          // OMIT
		chunk = chunk[:maxChunkSize] // OMIT
	}
	// OMIT
	return n, nil
}

// END 6 OMIT

const (
	mtuSize        = 1500
	maxChunkSize   = 1420 // based on MTU of 1500 and chunked GELF over UDP
	maxChunkCount  = 128  // based on 1-byte int sequence max
	gelfMagicByteA = 0x1e
	gelfMagicByteB = 0x0f
)
