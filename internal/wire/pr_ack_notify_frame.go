package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// 当PR_Stream帧丢失时，根据PR策略决定是否重传，如果不重传该帧，
// 就将该帧除去所携带的数据(data)，复制到PRAckNotifyFrame，
// 后者多记录一个data的长度，随后将后者代替PR_Stream帧加入重传队列
// 当接收方收到这样一个帧时，就知道是PR策略导致不重传，
// 于是根据该帧记录的流号、偏移、数据长度信息，将该帧改为原来的PR_Stream帧，
// 只是此时的PR_Stream帧所携带数据全部填0，这就要求PR_Stream帧不能太大。
// 因为我们想要的是细粒度的丢帧策略。最理想的是视频一帧的画面分多个块，
// 每一块由一个PR_Stream帧编码，这样当一帧丢失时，该画面仍能正常显示，不影响帧率。
type PRAckNotifyFrame struct {
	StreamID       protocol.StreamID
	Offset         protocol.ByteCount
	PRDataLen      uint64 // 存放不重传的数据的长度
	Fin            bool
	DataLenPresent bool

	PTDA  byte   // 高位4bits用于存放PTDA
	P     bool   // probability标志位，基于概率PR
	T     bool   // times标志位，基于次数PR
	D     bool   // deadline标志位，基于时限PR
	A     bool   // 标志位，基于内容优先级PR
	PtdaC uint64 // PTDA标志位所代表的PR策略的内容

	// fromPool bool
}

func parsePRAckNotifyFrame(r *bytes.Reader, _ protocol.VersionNumber) (*PRAckNotifyFrame, error) {
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

	// 获取PtdaC的信息
	var P bool
	var T bool
	var D bool
	var A bool
	PTDA, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch PTDA & 0xf0 {
	case 0x10: // A
		A = true
	case 0x20: // D
		D = true
	case 0x40: // T
		T = true
	case 0x80: // P
		P = true
	}
	PtdaC, err := quicvarint.Read(r)
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

	dataLen, err = quicvarint.Read(r)
	if err != nil {
		return nil, err
	}

	// var frame *PRAckNotifyFrame  // need initial, otherwise wrong

	frame := &PRAckNotifyFrame{
		StreamID:       protocol.StreamID(streamID),
		Offset:         protocol.ByteCount(offset),
		Fin:            fin,
		DataLenPresent: hasDataLen,
		P:              P,
		T:              T,
		D:              D,
		A:              A,
		PTDA:           PTDA,
		PtdaC:          PtdaC,
		PRDataLen:      dataLen,
	}

	return frame, nil
}

// Append writes a PRAckNotify frame
func (f *PRAckNotifyFrame) Append(b []byte, _ protocol.VersionNumber) ([]byte, error) {
	typeByte := byte(0x58)
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
	b = append(b, typeByte)                      // 1. type
	b = quicvarint.Append(b, uint64(f.StreamID)) // 2. StreamID

	//添加存放PTDA信息的字节
	b = append(b, f.PTDA)                     // 3. PTDA
	b = quicvarint.Append(b, uint64(f.PtdaC)) // 4.PtdaC

	if hasOffset {
		b = quicvarint.Append(b, uint64(f.Offset)) // 5. Offset
	}

	// 假的携带数据长度
	b = quicvarint.Append(b, uint64(f.PRDataLen)) // 6. PRDataLen

	return b, nil
}

// Length returns the total length of the PRSTREAM frame
func (f *PRAckNotifyFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	length := 1 + quicvarint.Len(uint64(f.StreamID))
	if f.Offset != 0 {
		length += quicvarint.Len(uint64(f.Offset))
	}
	// if f.DataLenPresent {
	// 	length += quicvarint.Len(uint64(f.DataLen()))
	// }
	length += quicvarint.Len(uint64(f.DataLen())) // PRDataLen

	// 还要加上PR字段的开销
	length++ // PTDA字节
	length += quicvarint.Len(uint64(f.PtdaC))

	return length
}

// DataLen gives the length of data in bytes
func (f *PRAckNotifyFrame) DataLen() protocol.ByteCount {
	return protocol.ByteCount(f.PRDataLen)
}

// MaxDataLen returns the maximum data length
// If 0 is returned, writing will fail (a STREAM frame must contain at least 1 byte of data).
func (f *PRAckNotifyFrame) MaxDataLen(maxSize protocol.ByteCount, version protocol.VersionNumber) protocol.ByteCount {
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
	headerLen -= quicvarint.Len(uint64(f.PtdaC))

	maxDataLen := maxSize - headerLen
	if f.DataLenPresent && quicvarint.Len(uint64(maxDataLen)) != 1 {
		maxDataLen--
	}
	return maxDataLen
}
