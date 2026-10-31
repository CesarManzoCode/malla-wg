package relay

import (
	"bufio"
	"net"
	"sync"
	"time"
)

// Protocol constants of the Upgrade (contract §3.2).
const (
	Path     = "/v1/relay"
	Protocol = "malla-relay/1"
)

// Timing of a relay connection, on both sides: each side sends a
// KeepAlive every KeepAliveInterval and gives up on a connection that
// sent nothing for ReadTimeout.
const (
	KeepAliveInterval = 30 * time.Second
	ReadTimeout       = 90 * time.Second
	writeTimeout      = 10 * time.Second
	handshakeTimeout  = 10 * time.Second
)

// sendQueue is how many frames may wait for one connection's writer; a
// frame that finds the queue full is dropped, as UDP would drop it.
const sendQueue = 1024

// frameConn is a connection after the Upgrade: one writer goroutine
// drains a queue of encoded frames and sends the keepalives; the owner
// reads frames itself.
type frameConn struct {
	nc   net.Conn
	q    chan []byte
	done chan struct{}
	once sync.Once
}

func newFrameConn(nc net.Conn) *frameConn {
	c := &frameConn{nc: nc, q: make(chan []byte, sendQueue), done: make(chan struct{})}
	go c.writeLoop()
	return c
}

// enqueue queues an encoded frame without blocking and reports whether it
// was queued.
func (c *frameConn) enqueue(frame []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.q <- frame:
		return true
	default:
		return false
	}
}

func (c *frameConn) close() {
	c.once.Do(func() {
		close(c.done)
		c.nc.Close()
	})
}

func (c *frameConn) writeLoop() {
	bw := bufio.NewWriterSize(c.nc, 64<<10)
	ka := time.NewTicker(KeepAliveInterval)
	defer ka.Stop()
	keepalive := AppendFrame(nil, TypeKeepAlive)
	for {
		var err error
		select {
		case <-c.done:
			return
		case f := <-c.q:
			c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, err = bw.Write(f)
			// Batch whatever else is already queued into one flush.
			for n := len(c.q); err == nil && n > 0; n-- {
				_, err = bw.Write(<-c.q)
			}
		case <-ka.C:
			c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, err = bw.Write(keepalive)
		}
		if err == nil {
			err = bw.Flush()
		}
		if err != nil {
			c.close()
			return
		}
	}
}
