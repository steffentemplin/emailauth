package emailauth

import (
	"io"
	"net/textproto"
)

type Result string

func (r Result) String() string {
	return string(r)
}

const (
	None      = Result("none")
	Pass      = Result("pass")
	Fail      = Result("fail")
	Policy    = Result("policy")
	Neutral   = Result("neutral")
	Softfail  = Result("softfail")
	Temperror = Result("temperror")
	Permerror = Result("permerror")
)

type Message struct {
	Headers *textproto.MIMEHeader
	Body    io.Reader
}
