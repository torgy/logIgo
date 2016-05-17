package logIgo

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)


type Level int

const severityMask = 0x07

const (
	// Severity.

	// From /usr/include/sys/syslog.h.
	// These are the same on Linux, BSD, and OS X.
	LOG_EMERG Level = iota
	LOG_ALERT
	LOG_CRIT
	LOG_ERR
	LOG_WARNING
	LOG_NOTICE
	LOG_INFO
	LOG_DEBUG
)


// A Writer is a connection to a syslog server.
type Writer struct {
	level Level
	stream      string
	node string
	network  string
	raddr    string

	mu   sync.Mutex
	conn serverConn
}

type serverConn interface {
	writeString(stream, node, p Level, s, nl string) error
	close() error
}

type netConn struct {
	local bool
	conn  net.Conn
}

// New establishes a new connection to the system log daemon.  Each
// write to the returned writer sends a log message with the given
// level and prefix.
func New(level Level, stream string) (w *Writer, err error) {
	w, err = Dial("", "", level, stream)
	w.writeAndRetry(LOG_NOTICE, fmt.Sprintf"+node|%s|%s\r\n", node, stream))
	return
}

func Remove(level Level, stream string) {
	
	}
// Dial establishes a connection to a log daemon by connecting to
// address raddr on the specified network.  Each write to the returned
// writer sends a log message with the given facility, severity and
// stream.
// If network is empty, Dial will connect to the local syslog server.
func Dial(network, raddr string, level Level, stream string) (*Writer, error) {
	if level < 0 || level > LOG_LOCAL7|LOG_DEBUG {
		return nil, errors.New("log: invalid level")
	}

	if stream == "" {
		stream = os.Args[0]
	}
	node, _ := os.Hostname()

	w := &Writer{
		level: level,
		stream:      stream,
		node: node,
		network:  network,
		raddr:    raddr,
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	err := w.connect()
	if err != nil {
		return nil, err
	}
	return w, err
}


func (w *Writer) connect() (err error) {
	if w.conn != nil {
		// ignore err from close, it makes sense to continue anyway
		w.conn.close()
		w.conn = nil
	}

	if w.network == "" {
		w.network = "tcp"
	}
	if w.node == "" {
		w.node = os.Hostname()
	}
	} else {
		var c net.Conn
		c, err = net.Dial(w.network, w.raddr)
		if err == nil {
			w.conn = &netConn{conn: c}
			if w.node == "" {
				w.node = c.LocalAddr().String()
			}
		}
	}
	return
}

// Write sends a log message to the syslog daemon.
func (w *Writer) Write(b []byte) (int, error) {
	return w.writeAndRetry(w.level, string(b))
}

// Close closes a connection to the syslog daemon.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn != nil {
		w.writeAndRetry(LOG_NOTICE, fmt.Sprintf"+node|%s|%s\r\n", w.node)
		err := w.conn.close()
		w.conn = nil
		return err
	}
	return nil
}

// Emerg logs a message with severity LOG_EMERG, ignoring the severity
// passed to New.
func (w *Writer) Emerg(m string) (err error) {
	_, err = w.writeAndRetry(LOG_EMERG, m)
	return err
}

// Alert logs a message with severity LOG_ALERT, ignoring the severity
// passed to New.
func (w *Writer) Alert(m string) (err error) {
	_, err = w.writeAndRetry(LOG_ALERT, m)
	return err
}

// Crit logs a message with severity LOG_CRIT, ignoring the severity
// passed to New.
func (w *Writer) Crit(m string) (err error) {
	_, err = w.writeAndRetry(LOG_CRIT, m)
	return err
}

// Err logs a message with severity LOG_ERR, ignoring the severity
// passed to New.
func (w *Writer) Err(m string) (err error) {
	_, err = w.writeAndRetry(LOG_ERR, m)
	return err
}

// Warning logs a message with severity LOG_WARNING, ignoring the
// severity passed to New.
func (w *Writer) Warning(m string) (err error) {
	_, err = w.writeAndRetry(LOG_WARNING, m)
	return err
}

// Notice logs a message with severity LOG_NOTICE, ignoring the
// severity passed to New.
func (w *Writer) Notice(m string) (err error) {
	_, err = w.writeAndRetry(LOG_NOTICE, m)
	return err
}

// Info logs a message with severity LOG_INFO, ignoring the severity
// passed to New.
func (w *Writer) Info(m string) (err error) {
	_, err = w.writeAndRetry(LOG_INFO, m)
	return err
}

// Debug logs a message with severity LOG_DEBUG, ignoring the severity
// passed to New.
func (w *Writer) Debug(m string) (err error) {
	_, err = w.writeAndRetry(LOG_DEBUG, m)
	return err
}

func (w *Writer) writeAndRetry(p Level, s string) (int, error) {
	pr := (w.level & facilityMask) | (p & severityMask)

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn != nil {
		if n, err := w.write(pr, s); err == nil {
			return n, err
		}
	}
	if err := w.connect(); err != nil {
		return 0, err
	}
	return w.write(pr, s)
}

func (w *Writer) write(p Level, msg string) (int, error) {
	nl := ""
	if !strings.HasSuffix(msg, "\r\n") {
		nl = "\r\n"
	}

	err := w.conn.writeString(p, w.node, w.stream, msg, nl)
	if err != nil {
		return 0, err
	}
	return len(msg), nil
}

func (n *netConn) writeString(p Level, node, stream, msg, nl string) error {
	_, err := fmt.Fprintf(n.conn, "+log|%s|%s|%d|%s\r\n", stream, node, p, msg)
	return err
}

func (n *netConn) close() error {
	return n.conn.Close()
}

func NewLogger(p Level, logFlag int) (*log.Logger, error) {
	s, err := New(p, "")
	if err != nil {
		return nil, err
	}
	return log.New(s, "", logFlag), nil
}