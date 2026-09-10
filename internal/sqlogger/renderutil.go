package sqlogger

import (
	"bytes"
	"log"
	"os"
	"strconv"
	"strings"
)

var stdlog = log.New(os.Stdout, "", 0)

type ByteRenderer struct {
	bytes.Buffer
}

func (r *ByteRenderer) Render(inputs ...any) {
	for _, s := range inputs {
		switch v := s.(type) {
		case string:
			r.WriteString(v)
		case []byte:
			r.Write(v)
		case int:
			r.WriteString(strconv.FormatInt(int64(v), 10))
		case byte:
			r.WriteByte(v)
		case rune:
			r.WriteRune(v)
		default:
			stdlog.Panicf("attemping to write something not a string, int, rune, []byte or byte: %T", s)
		}
	}
}

func (r *ByteRenderer) Renderln(inputs ...any) {
	r.Render(inputs...)
	r.Render('\n')
}

// CloneBytes returns a copy of the buffer contents, so the returned copy is owned by the caller
func (r *ByteRenderer) CloneBytes() []byte {
	return bytes.Clone(r.Bytes())
}

type StringRenderer struct {
	strings.Builder
}

func (r *StringRenderer) Render(inputs ...any) {
	for _, s := range inputs {
		r.render(s)
	}
}

func (r *StringRenderer) RenderWithSeparator(separator string, inputs ...any) {
	for _, s := range inputs {
		r.render(s)
		if len(separator) > 0 {
			r.WriteString(separator)
		}
	}
}

func (r *StringRenderer) Renderln(inputs ...any) {
	r.Render(inputs...)
	r.Render('\n')
}

func (r *StringRenderer) render(s any) {
	switch v := s.(type) {
	case string:
		r.WriteString(v)
	case []byte:
		r.Write(v)
	case int:
		r.WriteString(strconv.FormatInt(int64(v), 10))
	case uint:
		r.WriteString(strconv.FormatInt(int64(v), 10))
	case int8:
		r.WriteString(strconv.FormatInt(int64(v), 10))
	case int64:
		r.WriteString(strconv.FormatInt(v, 10))

	case byte:
		r.WriteByte(v)
	case rune:
		r.WriteRune(v)
	default:
		stdlog.Panicf("attemping to write something not a string, int, rune, []byte or byte: %T", s)
	}
}
