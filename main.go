package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// LogstashService is a wrapper around a locally running logstash server.
// Specify as a raw string like `tcp://localhost:3000`, then it is parsed into
// a URL, and eventually it's opened as an io.Writer that we can write to
type LogstashService struct {
	url  *url.URL
	raw  string
	sink io.Writer
}

// We can parse command line flags directly into a LogstashService value
var _ flag.Value = (*LogstashService)(nil)

// Open a connection to a logstash service by dialing TCP.
func (s *LogstashService) Open() error {
	f, err := net.Dial("tcp", s.url.Host)
	if err != nil {
		return err
	}
	s.sink = f
	return nil
}

// Set the hostname/port of a logstash service as read in from the command line.
func (s *LogstashService) Set(r string) error {
	url, err := url.Parse(r)
	if err != nil {
		return err
	}
	s.url = url
	s.raw = r
	return nil
}

// String representation of a logstash service
func (s *LogstashService) String() string {
	return s.raw
}

// BaseStream is the base class for incoming log streams, which contains a "tag"
// to apply to all loglines in the stream, a "raw" value that specifies where
// the stream comes from and the tag, and a "source" from which we can read lines.
type BaseStream struct {
	tag    string
	raw    string
	source *bufio.Reader
}

// Source returns the buffered IO reader that's the source of this incoming
// log stream.
func (b *BaseStream) Source() *bufio.Reader {
	return b.source
}

// MarkClosed marks this Stream as closed.
func (b *BaseStream) MarkClosed() {
	b.source = nil
}

// Raw returns the raw string specification of what this stream is.
func (b *BaseStream) Raw() string {
	return b.raw
}

// Tag returns the 'tag' that identifies this incoming log stream. Examples
// might include 'ngingx.access' or 'app.error'.
func (b *BaseStream) Tag() string {
	return b.tag
}

// NamedPipeStream is a subclass of a BaseStream that's made from opening a
// named pipe at the given path.
type NamedPipeStream struct {
	BaseStream
	path string
}

// Open a NamedPipeStream. If no file exists, then make a FIFO. If one exists,
// that's a FIFO, then return it. Otherwise, error out.
func (n *NamedPipeStream) Open() error {
	s, err := os.Stat(n.path)

	if err != nil {
		err = syscall.Mkfifo(n.path, 0666)
	} else if (s.Mode() & os.ModeNamedPipe) == 0 {
		err = fmt.Errorf("not overwriting non-named pipe: %s", n.path)
	}
	if err != nil {
		return err
	}
	return nil
}

// Preread is called before every read. It allows us to reopen a
// NamedPipeStream if it had been closed the previous iteration in the read
// loop.
func (n *NamedPipeStream) Preread() error {
	if n.source != nil {
		return nil
	}
	file, err := os.OpenFile(n.path, os.O_RDONLY, os.ModeNamedPipe)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "opened named pipe for tag %s: %s\n", n.tag, n.path)
	n.source = newBufferedReader(file)
	return nil
}

// PipeStream wraps a standard nameless pipe, as handed to the process by a
// file descript. It can't be reopened once it closes.
type PipeStream struct {
	BaseStream
	fd int64
}

// Preread is called before a PipeStream incoming log stream is read from.
// If the source has been closed, then we just return EOF and abandon ship,
// since we can't reopen it.
func (p *PipeStream) Preread() error {
	if p.source == nil {
		return io.EOF
	}
	return nil
}

// Open is called to open a PipeStream, which simply wraps the given file descriptor
// in a buffered reader.
func (p *PipeStream) Open() error {
	p.source = newBufferedReader(os.NewFile(uintptr(p.fd), fmt.Sprintf("fd=%d", p.fd)))
	return nil
}

// Stream is the interface to either a PipeStream or a NamedPipeStream. Most
// methods are handled by the BaseStream class, but openings and prereads
// are handled by the subclasses.
type Stream interface {
	Open() error
	Preread() error
	Raw() string
	MarkClosed()
	Source() *bufio.Reader
	Tag() string
}

// PipeStream and NamedPipeStream are the two instantiations of the Stream interface.
var _ Stream = (*PipeStream)(nil)
var _ Stream = (*NamedPipeStream)(nil)

// Mux is the high level object that has all of the configuration for this run
// of logmux. Meaning, it knows where the logs are coming from, and to which
// logstash service they are going to.
type Mux struct {
	logstash LogstashService
	streams  []Stream
}

// Configure a Mux, opening the logstash connection and all of the incoming
// log streams.
func (m *Mux) Configure() error {
	err := m.logstash.Open()
	if err != nil {
		return err
	}
	for _, s := range m.streams {
		if err := s.Open(); err != nil {
			return err
		}
	}
	return nil
}

func newBufferedReader(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, 1024*1024*4)
}

func hasNonSpace(buf []byte) bool {
	for _, b := range buf {
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			return true
		}
	}
	return false
}

func processLine(buf []byte, tag string) []byte {
	buf = bytes.TrimSpace(buf)
	if len(buf) == 0 {
		return buf
	}
	lst := len(buf) - 1
	if buf[0] == '{' && buf[lst] == '}' {
		if hasNonSpace(buf[1:lst]) {
			buf = append(buf[0:lst], []byte(fmt.Sprintf(",\"tag\":%q}", tag))...)
		} else {
			buf = []byte(fmt.Sprintf("{\"tag\":%q}", tag))
		}
	} else {
		tmp := append([]byte(tag), []byte(": ")...)
		buf = append(tmp, buf...)
	}
	buf = append(buf, '\n')
	return buf
}

func readOne(s Stream, l *LogstashService) error {
	err := s.Preread()
	if err != nil {
		return err
	}
	buf, err := s.Source().ReadBytes('\n')
	var e2 error
	if len(buf) > 0 {
		buf = processLine(buf, s.Tag())
		_, e2 = l.sink.Write(buf)
	}
	if err == io.EOF {
		s.MarkClosed()
		return nil
	}
	if err != nil {
		return err
	}
	if e2 != nil {
		return e2
	}
	return nil
}

// Run the given stream, reading incoming log lines from it, and outputting
// tagged lines to logstash.  If there's an error, the send it to the given
// channel.
func Run(s Stream, l *LogstashService, ch chan<- error, single bool) {
	for {
		err := readOne(s, l)
		if err != nil {
			if !single {
				fmt.Fprintf(os.Stderr, "%s: ending log read loop on condition: %s\n", s.Tag(), err)
			}
			ch <- err
			break
		}
	}
	return
}

// Run the logmux, by first configuring it, and then by running each incoming
// log stream in its own go routine. End the program with an error when the first
// incoming stream dies on an non-EOF error.
func (m *Mux) Run() error {
	err := m.Configure()
	if err != nil {
		return err
	}
	ch := make(chan error, 10)
	n := 0
	isSingle := len(m.streams) == 1
	for _, s := range m.streams {
		n++
		go Run(s, &m.logstash, ch, isSingle)
	}
	for err := range ch {
		n--
		if err != io.EOF {
			return err
		}
		if n == 0 {
			return nil
		}
	}
	return nil
}

// parseStreamArg takes an input a raw stream specification (as collected
// from the OS CLI), and returns a stream object that represents an incoming
// log stream. The format is <specifier>:<tag>. Integer specifiers are treated
// as nameless pipes, while string specifiers are treated as paths that indicate
// named pipes.
func parseStreamArg(raw string) (ret Stream, err error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("Specified stream %s has wrong number of components (%d)", raw, len(parts))
	}
	baseStream := BaseStream{tag: parts[1], raw: raw}
	fd, err := strconv.ParseInt(parts[0], 10, 64)
	if err == nil {
		ret = &PipeStream{BaseStream: baseStream, fd: fd}
	} else {
		ret = &NamedPipeStream{BaseStream: baseStream, path: parts[0]}
	}
	return ret, nil
}

func printHelp(fs *flag.FlagSet) {
	fmt.Printf(`NAME
	logmux -- mux several input log streams into one

OVERVIEW
	A simple program that takes one or more log streams, and smashes them
	together into one stream that's sent into a logstash server process.
	Likely that process is on localhost, but it doesn't have to be. Each
	incoming stream gets it own tag so that the streams can be disambiguated
	in ELK.

	Specify the logstash location with:

		--logstash tcp://<hostname>:<port>

	And specify incoming streams in <specifier>:<tag> pairs.  For instance:

	    logmux --logstash tcp://localhost:5000 \
	    	6:app.error 7:launch.log \
	    	/ngingx/log/access_log:nginx.access

	You can specify 1 or more incoming log streams. Named pipes are reopened
	indefinitely, but pipes passed as FDs are left close as soon as they crash.
	The program exits on the first non-EOF exit condition.

	That's it!

OPTIONS
`)
	fs.PrintDefaults()
	fmt.Printf("\n")
}

// parseArgs parses the command line arguments and outputs a Mux object,
// which should have a logstash service to output to, and one or more incoming
// log streams.
func parseArgs() (*Mux, error) {
	var ret Mux
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.Var(&ret.logstash, "logstash", "A URI for logstash in tcp://<hostname>:<port> format")
	helpPtr := fs.Bool("help", false, "print help")
	err := fs.Parse(os.Args[1:])
	if err != nil {
		return nil, err
	}
	if *helpPtr {
		printHelp(fs)
		return nil, errors.New("help wanted")
	}

	if ret.logstash.url == nil {
		return nil, errors.New("require a --logstash parameter")
	}
	if n := len(fs.Args()); n == 0 {
		return nil, fmt.Errorf("neet at least 1 stream for input; got 0")
	}
	for _, arg := range fs.Args() {
		stream, err := parseStreamArg(arg)
		if err != nil {
			return nil, err
		}
		ret.streams = append(ret.streams, stream)
	}
	return &ret, err
}

// mainInner is the main loop that returns an error when the program
// is completed.
func mainInner() error {
	mux, err := parseArgs()
	if err != nil {
		return err
	}
	return mux.Run()
}

func main() {
	err := mainInner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "logmux fatal error: %s\n", err)
		os.Exit(-1)
	}
}
