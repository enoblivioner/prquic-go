package main

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

func main() {
	f1 := *wire.GetPRStreamFrame()
	f2 := wire.GetStreamFrame()
	fmt.Printf("f1: %v\n", f1.Length(protocol.Version1))
	fmt.Printf("f2: %v\n", f2.Length(protocol.Version1))
}

