package app

import (
	"bytes"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// The standard Bubble Tea renderer ends every frame by moving the terminal
// cursor to the first column of the last rendered line, which is also where an
// IME anchors its composition window. Appending a CUP to the view string does
// not survive that write, so the anchor is applied here, after the frame bytes
// have gone out: the renderer's trailing "move to last line" is immediately
// overridden with the composer caret.
var (
	cursorAnchor atomic.Value // string
	outputOnce   sync.Once
	wrappedOut   io.Writer
)

// OutputWriter returns the writer to hand to tea.WithOutput. It forwards to
// stdout and re-anchors the cursor after each renderer frame.
func OutputWriter() io.Writer {
	outputOnce.Do(func() { wrappedOut = &anchorWriter{under: os.Stdout} })
	return wrappedOut
}

type anchorWriter struct {
	under io.Writer
}

// Fd exposes the underlying terminal so Bubble Tea's term.File assertion still
// holds; without it the program skips TTY setup and renders a blank frame.
func (w *anchorWriter) Fd() uintptr {
	if f, ok := w.under.(interface{ Fd() uintptr }); ok {
		return f.Fd()
	}
	return os.Stdout.Fd()
}

func (w *anchorWriter) Write(p []byte) (int, error) {
	n, err := w.under.Write(p)
	if anchor, ok := cursorAnchor.Load().(string); ok && anchor != "" && endsWithCursorMove(p) {
		_, _ = w.under.Write([]byte(anchor))
	}
	return n, err
}

// endsWithCursorMove reports whether the chunk ends with a CUP (cursor position)
// sequence, which is how the renderer terminates a frame.
func endsWithCursorMove(p []byte) bool {
	if len(p) < 4 || p[len(p)-1] != 'H' {
		return false
	}
	tail := p
	if len(tail) > 16 {
		tail = tail[len(tail)-16:]
	}
	return bytes.Contains(tail, []byte("\x1b["))
}

func setCursorAnchor(escape string) {
	cursorAnchor.Store(escape)
}
