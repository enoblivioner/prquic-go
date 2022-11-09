package wire

import (
	"bytes"
	"errors"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// A PRStreamFrame of QUIC
type PRStreamFrame struct {
	StreamID       protocol.StreamID
	Offset         protocol.ByteCount
	Data           []byte
	Fin            bool
	DataLenPresent bool

	PTDA byte	// 高位4bits用于存放PTDA
	P	bool	// probability标志位，基于概率PR
	T	bool	// times标志位，基于次数PR
	D	bool	// deadline标志位，基于时限PR
	A	bool	// 标志位，基于内容优先级PR
	ptdaC	uint64	// PTDA标志位所代表的PR策略的内容

	fromPool bool
}

func parsePRStreamFrame(r *bytes.Reader, _ protocol.VersionNumber) (*PRStreamFrame, error) {
	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	hasOffset := typeByte&0b100 > 0
	fin := typeByte&0b1 > 0
	hasDataLen := typeByte&0b10 > 0

	streamID, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	var offset uint64
	if hasOffset {
		offset, err = quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
	}

	var dataLen uint64
	if hasDataLen {
		var err error
		dataLen, err = quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
	} else {
		// The rest of the packet is data
		dataLen = uint64(r.Len())
	}

	var frame *PRStreamFrame

	// 获取PTDAC的信息
	frame.PTDA, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch frame.PTDA&0xf0 {
	case 0x10:  // A
		frame.A = true
	case 0x20:  // D
		frame.D = true
	case 0x40:  // T
		frame.T = true
	case 0x80:  // P
		frame.P = true
	}
	frame.ptdaC, err = quicvarint.Read(r)
	if err != nil {
		return nil, err
	}

	if dataLen < protocol.MinStreamFrameBufferSize {
		frame = &PRStreamFrame{Data: make([]byte, dataLen)}
	} else {
		frame = GetPRStreamFrame()
		// The PRSTREAM frame can't be larger than the PRStreamFrame we obtained from the buffer,
		// since those PRStreamFrames have a buffer length of the maximum packet size.
		if dataLen > uint64(cap(frame.Data)) {
			return nil, io.EOF
		}
		frame.Data = frame.Data[:dataLen]
	}

	frame.StreamID = protocol.StreamID(streamID)
	frame.Offset = protocol.ByteCount(offset)
	frame.Fin = fin
	frame.DataLenPresent = hasDataLen

	if dataLen != 0 {
		if _, err := io.ReadFull(r, frame.Data); err != nil {
			return nil, err
		}
	}
	if frame.Offset+frame.DataLen() > protocol.MaxByteCount {
		return nil, errors.New("PRstream data overflows maximum offset")
	}
	return frame, nil
}

// Append writes a PRSTREAM frame
func (f *PRStreamFrame) Append(b []byte, _ protocol.VersionNumber) ([]byte, error) {
	if len(f.Data) == 0 && !f.Fin {
		return nil, errors.New("StreamFrame: attempting to write empty frame without FIN")
	}

	typeByte := byte(0x8)
	if f.Fin {
		typeByte ^= 0b1
	}
	hasOffset := f.Offset != 0
	if f.DataLenPresent {
		typeByte ^= 0b10
	}
	if hasOffset {
		typeByte ^= 0b100
	}
	b = append(b, typeByte)
	b = quicvarint.Append(b, uint64(f.StreamID))
	if hasOffset {
		b = quicvarint.Append(b, uint64(f.Offset))
	}
	if f.DataLenPresent {
		b = quicvarint.Append(b, uint64(f.DataLen()))
	}

	//添加存放PTDA信息的字节
	b = append(b, f.PTDA)  
	b = append(b, byte(f.ptdaC))

	b = append(b, f.Data...)
	return b, nil
}

// Length returns the total length of the PRSTREAM frame
func (f *PRStreamFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	length := 1 + quicvarint.Len(uint64(f.StreamID))
	if f.Offset != 0 {
		length += quicvarint.Len(uint64(f.Offset))
	}
	if f.DataLenPresent {
		length += quicvarint.Len(uint64(f.DataLen()))
	}
	
	// 还要加上PR字段的开销
	length ++   // PTDA字节
	length += quicvarint.Len(uint64(f.ptdaC))

	return length + f.DataLen()
}

// DataLen gives the length of data in bytes
func (f *PRStreamFrame) DataLen() protocol.ByteCount {
	return protocol.ByteCount(len(f.Data))
}

// MaxDataLen returns the maximum data length
// If 0 is returned, writing will fail (a STREAM frame must contain at least 1 byte of data).
func (f *PRStreamFrame) MaxDataLen(maxSize protocol.ByteCount, version protocol.VersionNumber) protocol.ByteCount {
	headerLen := 1 + quicvarint.Len(uint64(f.StreamID))
	if f.Offset != 0 {
		headerLen += quicvarint.Len(uint64(f.Offset))
	}
	if f.DataLenPresent {
		// pretend that the data size will be 1 bytes
		// if it turns out that varint encoding the length will consume 2 bytes, we need to adjust the data length afterwards
		headerLen++
	}
	if headerLen > maxSize {
		return 0
	}

	// PR字段消耗的头部长度
	headerLen--
	headerLen -= quicvarint.Len(uint64(f.ptdaC))

	maxDataLen := maxSize - headerLen
	if f.DataLenPresent && quicvarint.Len(uint64(maxDataLen)) != 1 {
		maxDataLen--
	}
	return maxDataLen
}

// MaybeSplitOffFrame splits a frame such that it is not bigger than n bytes.
// It returns if the frame was actually split.
// The frame might not be split if:
// * the size is large enough to fit the whole frame
// * the size is too small to fit even a 1-byte frame. In that case, the frame returned is nil.
func (f *PRStreamFrame) MaybeSplitOffFrame(maxSize protocol.ByteCount, version protocol.VersionNumber) (*PRStreamFrame, bool /* was splitting required */) {
	if maxSize >= f.Length(version) {
		return nil, false
	}

	n := f.MaxDataLen(maxSize, version)
	if n == 0 {
		return nil, true
	}

	new := GetPRStreamFrame()
	new.StreamID = f.StreamID
	new.Offset = f.Offset
	new.Fin = false
	new.DataLenPresent = f.DataLenPresent

	// 如果切分了，新帧也要更新旧帧的PR信息
	new.PTDA = f.PTDA
	new.P = f.P
	new.T = f.T
	new.D = f.D
	new.A = f.A
	new.ptdaC = f.ptdaC

	// swap the data slices
	new.Data, f.Data = f.Data, new.Data
	new.fromPool, f.fromPool = f.fromPool, new.fromPool

	f.Data = f.Data[:protocol.ByteCount(len(new.Data))-n]
	copy(f.Data, new.Data[n:])
	new.Data = new.Data[:n]
	f.Offset += n

	return new, true
}

func (f *PRStreamFrame) PutBack() {
	putPRStreamFrame(f)
}
