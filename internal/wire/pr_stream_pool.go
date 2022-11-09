package wire

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var prStreamFramepool sync.Pool

func init() {
	prStreamFramepool.New = func() interface{} {
		return &PRStreamFrame{
			Data:     make([]byte, 0, protocol.MaxPacketBufferSize),
			fromPool: true,
		}
	}
}

func GetPRStreamFrame() *PRStreamFrame {
	f := prStreamFramepool.Get().(*PRStreamFrame)
	return f
}

func putPRStreamFrame(f *PRStreamFrame) {
	if !f.fromPool {
		return
	}
	if protocol.ByteCount(cap(f.Data)) != protocol.MaxPacketBufferSize {
		panic("wire.PutStreamFrame called with packet of wrong size!")
	}
	prStreamFramepool.Put(f)
}
