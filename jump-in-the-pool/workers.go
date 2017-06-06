// +build OMIT

package main

import (
	"bufio"
	"io"
	"math/rand"
	"os"
	"sync"
	"time"
)

// START MAIN OMIT
func main() {
	messages := []string{
		"foo\n",
		"bar\n",
		"baz\n",
		"the answer is 42\n",
		"i am root\n",
		"gopher\n",
		"blue is the best dog\n",
	}
	uw := muxWriter{w: os.Stdout}
	w := NewWriter(3, &uw) // HL

	for _, msg := range messages {
		w.Write([]byte(msg)) // HL
	}
	w.Close()
}

// END MAIN OMIT

// START TYPE OMIT
type writer struct {
	ch chan writeArgs
	wg sync.WaitGroup //OMIT
}

type writeArgs struct {
	p     []byte
	resCh chan<- writeResults
}

type writeResults struct {
	n   int
	err error
}

func (w *writer) Write(p []byte) (int, error) {
	resCh := make(chan writeResults)
	w.ch <- writeArgs{p: p, resCh: resCh}
	res := <-resCh
	return res.n, res.err
}

// END TYPE OMIT

func (w *writer) Close() error {
	close(w.ch)
	w.wg.Wait()
	return nil
}

// START CONSTRUCT OMIT
func NewWriter(capacity int, uw io.Writer) *writer {
	w := writer{ch: make(chan writeArgs)}
	for i := 0; i < capacity; i++ {
		w.wg.Add(1) // OMIT
		go func(i int, ch <-chan writeArgs) {
			defer w.wg.Done()          // OMIT
			buf := bufio.NewWriter(uw) // HL
			var res writeResults       // HL
			for arg := range ch {
				res.n, res.err = buf.Write(arg.p)
				buf.Flush()
				arg.resCh <- res

				buf.Reset(uw)           // HL
				res.n, res.err = 0, nil // HL
			}
		}(i, w.ch)
	}
	return &w
}

// END CONSTRUCT OMIT

type muxWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *muxWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	<-time.After(time.Duration(rand.Intn(100)+1) * time.Millisecond)
	n, err := w.w.Write(p)
	w.mu.Unlock()
	return n, err
}
