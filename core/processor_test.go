package core

import (
	"testing"
)

func TestProcessor(t *testing.T) {
	c, err := NewPilotCtl(nil, PilotOptions{
		Tracing: false,
	})
	if err != nil {
		t.Fatalf(err.Error())
	}
	p, err := NewTelemCtl()
	if err != nil {
		t.Fatalf(err.Error())
	}
	p.Start(c)
}
