package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// 该帧用于Datagram帧的PR传输
type PRDatagramFrame struct {
	DataLenPresent bool
	Data           []byte

	PTDA byte	// 高位4bits用于存放PTDA
	P	bool	// probability标志位，基于概率PR
	T	bool	// times标志位，基于次数PR
	D	bool	// deadline标志位，基于时限PR
	A	bool	// 标志位，基于内容优先级PR
	ptdaC	uint64	// PTDA标志位所代表的PR策略的内容
}

func parsePRDatagramFrame(r *bytes.Reader, _ protocol.VersionNumber) (*PRDatagramFrame, error) {
	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	f := &PRDatagramFrame{}
	f.DataLenPresent = typeByte&0x1 > 0  //最低位为1则存在length字段

	var length uint64
	if f.DataLenPresent {
		var err error
		len, err := quicvarint.Read(r)  
		if err != nil {
			return nil, err
		}
		if len > uint64(r.Len()) {
			return nil, io.EOF
		}
		length = len
	} else {
		length = uint64(r.Len())
	}

	// 获取PTDAC的信息
	f.PTDA, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch f.PTDA&0xf0 {
	case 0x10:  // A
		f.A = true
	case 0x20:  // D
		f.D = true
	case 0x40:  // T
		f.T = true
	case 0x80:  // P
		f.P = true
	}
	f.ptdaC, err = quicvarint.Read(r)
	if err != nil {
		return nil, err
	}

	f.Data = make([]byte, length)
	if _, err := io.ReadFull(r, f.Data); err != nil {
		return nil, err
	}
	return f, nil
}

// 按照type length PTDA ptdaC data顺序组装帧
func (f *PRDatagramFrame) Append(b []byte, _ protocol.VersionNumber) ([]byte, error) {
	typeByte := uint8(0x52)
	if f.DataLenPresent {
		typeByte ^= 0b1  //二进制异或
	}
	b = append(b, typeByte)
	if f.DataLenPresent {
		b = quicvarint.Append(b, uint64(len(f.Data)))
	}

	//添加存放PTDA信息的字节
	b = append(b, f.PTDA)  
	b = append(b, byte(f.ptdaC))
	
	b = append(b, f.Data...)
	return b, nil
}

// MaxDataLen returns the maximum data length
func (f *PRDatagramFrame) MaxDataLen(maxSize protocol.ByteCount, version protocol.VersionNumber) protocol.ByteCount {
	headerLen := protocol.ByteCount(1)
	if f.DataLenPresent {
		// pretend that the data size will be 1 bytes
		// if it turns out that varint encoding the length will consume 2 bytes, we need to adjust the data length afterwards
		headerLen++
	}
	if headerLen > maxSize {
		return 0
	}
	maxDataLen := maxSize - headerLen
	if f.DataLenPresent && quicvarint.Len(uint64(maxDataLen)) != 1 {
		maxDataLen--
	}
	return maxDataLen
}

// Length of a written frame
func (f *PRDatagramFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	length := 1 + protocol.ByteCount(len(f.Data))
	if f.DataLenPresent {
		length += quicvarint.Len(uint64(len(f.Data)))
	}
	return length
}
