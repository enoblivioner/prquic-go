package quic

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type sendStreamI interface {
	SendStream
	handleStopSendingFrame(*wire.StopSendingFrame)
	hasData() bool
	popStreamFrame(maxBytes protocol.ByteCount) (*ackhandler.Frame, bool)
	closeForShutdown(error)
	updateSendWindow(protocol.ByteCount)
}

type sendStream struct {
	mutex sync.Mutex

	numOutstandingFrames int64
	retransmissionQueue  []*wire.StreamFrame
	prAckNotifyRetransmissionQueue []*wire.PRAckNotifyFrame

	ctx       context.Context
	ctxCancel context.CancelFunc

	streamID protocol.StreamID
	sender   streamSender

	writeOffset protocol.ByteCount

	cancelWriteErr      error
	closeForShutdownErr error

	closedForShutdown bool // set when CloseForShutdown() is called
	finishedWriting   bool // set once Close() is called
	canceledWrite     bool // set when CancelWrite() is called, or a STOP_SENDING frame is received
	finSent           bool // set when a STREAM_FRAME with FIN bit has been sent
	completed         bool // set when this stream has been reported to the streamSender as completed

	dataForWriting []byte // during a Write() call, this slice is the part of p that still needs to be sent out
	nextFrame      *wire.StreamFrame

	writeChan chan struct{}
	writeOnce chan struct{}
	deadline  time.Time

	flowController flowcontrol.StreamFlowController

	version protocol.VersionNumber
}

var (
	_ SendStream  = &sendStream{}
	_ sendStreamI = &sendStream{}
)

func newSendStream(
	streamID protocol.StreamID,
	sender streamSender,
	flowController flowcontrol.StreamFlowController,
	version protocol.VersionNumber,
) *sendStream {
	s := &sendStream{
		streamID:       streamID,
		sender:         sender,
		flowController: flowController,
		writeChan:      make(chan struct{}, 1),
		writeOnce:      make(chan struct{}, 1), // cap: 1, to protect against concurrent use of Write
		version:        version,
	}
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())
	return s
}

func (s *sendStream) StreamID() protocol.StreamID {
	return s.streamID // same for receiveStream and sendStream
}

func (s *sendStream) Write(p []byte) (int, error) {

	// Concurrent use of Write is not permitted (and doesn't make any sense),
	// but sometimes people do it anyway.
	// Make sure that we only execute one call at any given time to avoid hard to debug failures.
	s.writeOnce <- struct{}{}
	defer func() { <-s.writeOnce }()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.finishedWriting {
		return 0, fmt.Errorf("write on closed stream %d", s.streamID)
	}
	if s.canceledWrite {
		return 0, s.cancelWriteErr
	}
	if s.closeForShutdownErr != nil {
		return 0, s.closeForShutdownErr
	}
	if !s.deadline.IsZero() && !time.Now().Before(s.deadline) {
		return 0, errDeadline
	}
	if len(p) == 0 {
		return 0, nil
	}

	s.dataForWriting = p

	var (
		deadlineTimer  *utils.Timer
		bytesWritten   int
		notifiedSender bool
	)
	for {
		var copied bool
		var deadline time.Time
		// As soon as dataForWriting becomes smaller than a certain size x, we copy all the data to a STREAM frame (s.nextFrame),
		// which can the be popped the next time we assemble a packet.
		// This allows us to return Write() when all data but x bytes have been sent out.
		// When the user now calls Close(), this is much more likely to happen before we popped that last STREAM frame,
		// allowing us to set the FIN bit on that frame (instead of sending an empty STREAM frame with FIN).
		// FIN bit在Stream Frame的首字节（Type字节）的第二bit位，置为1时表示发送结束
		if s.canBufferStreamFrame() && len(s.dataForWriting) > 0 {
			// 空的话就直接添加，不空就加载nextFrame.Data中
			if s.nextFrame == nil {
				f := wire.GetStreamFrame()  //只是生成一个空的StreamFrame
				f.Offset = s.writeOffset
				f.StreamID = s.streamID
				f.DataLenPresent = true
				f.Data = f.Data[:len(s.dataForWriting)]
				copy(f.Data, s.dataForWriting)
				s.nextFrame = f
			} else {
				l := len(s.nextFrame.Data)
				s.nextFrame.Data = s.nextFrame.Data[:l+len(s.dataForWriting)]
				copy(s.nextFrame.Data[l:], s.dataForWriting)
			}
			s.dataForWriting = nil
			bytesWritten = len(p)
			copied = true
		} else {
			bytesWritten = len(p) - len(s.dataForWriting)
			deadline = s.deadline
			if !deadline.IsZero() {
				if !time.Now().Before(deadline) {
					s.dataForWriting = nil
					return bytesWritten, errDeadline
				}
				if deadlineTimer == nil {
					deadlineTimer = utils.NewTimer()
					defer deadlineTimer.Stop()
				}
				deadlineTimer.Reset(deadline)
			}
			if s.dataForWriting == nil || s.canceledWrite || s.closedForShutdown {
				break
			}
		}

		s.mutex.Unlock()
		if !notifiedSender {
			s.sender.onHasStreamData(s.streamID) // must be called without holding the mutex
			notifiedSender = true
		}
		if copied {
			s.mutex.Lock()
			break
		}
		if deadline.IsZero() {
			<-s.writeChan
		} else {
			select {
			case <-s.writeChan:
			case <-deadlineTimer.Chan():
				deadlineTimer.SetRead()
			}
		}
		s.mutex.Lock()
	}

	if bytesWritten == len(p) {
		return bytesWritten, nil
	}
	if s.closeForShutdownErr != nil {
		return bytesWritten, s.closeForShutdownErr
	} else if s.cancelWriteErr != nil {
		return bytesWritten, s.cancelWriteErr
	}
	return bytesWritten, nil
}

//检查待写入的帧能否存下要写入的数据，
//检查方式为比较帧中已有数据的大小加上要写入数据的大小是否小于QUIC报文允许的最大数据大小，
//如果返回True，则代表能装下。
func (s *sendStream) canBufferStreamFrame() bool {
	var l protocol.ByteCount
	if s.nextFrame != nil {
		l = s.nextFrame.DataLen()
	}
	return l+protocol.ByteCount(len(s.dataForWriting)) <= protocol.MaxPacketBufferSize
}

// popStreamFrame returns the next STREAM frame that is supposed to be sent on this stream
// maxBytes is the maximum length this frame (including frame header) will have.
func (s *sendStream) popStreamFrame(maxBytes protocol.ByteCount) (*ackhandler.Frame, bool /* has more data to send */) {
	s.mutex.Lock()

	pr_maxBytes := maxBytes
	if PR_ENABLED {
		pr_maxBytes = maxBytes - (1 + 8)  // pr字段的开销，后面一个8也可能是4或2或1，根据PtdaC的内容而不同，这里保守写8，可以更精确识别
	}
	
	f, hasMoreData := s.popNewOrRetransmittedStreamFrame(pr_maxBytes)
	
	if f != nil {
		s.numOutstandingFrames++
	}
	s.mutex.Unlock()

	if f == nil {
		return nil, hasMoreData
	}

	// 假如采用PR策略：
	if PR_ENABLED {
		// 将Stream帧转为PRStream帧
		prf := &wire.PRStreamFrame{
			StreamID: f.StreamID,
			Offset: f.Offset,
			Data: f.Data,
			Fin: f.Fin,
			DataLenPresent: f.DataLenPresent,
			PTDA: PTDA,  
			PtdaC: PtadC,  
			// fromPool: f.fromPool,  // 首字母小写的结构变量不能在外面用
		}
		switch PTDA {
		case 0x80:
			prf.P = true
		case 0x40:
			prf.T = true
		case 0x20:
			prf.D = true
		case 0x10:
			prf.A = true
		default:
			fmt.Println("PR Policy wrong!")
		}
		// 改变返回的帧，以及OnLost()与OnAcked()方法
		return &ackhandler.Frame{Frame: prf, OnLost: s.prQueueRetransmission, OnAcked: s.prStreamframeAcked}, hasMoreData
	}

	return &ackhandler.Frame{Frame: f, OnLost: s.queueRetransmission, OnAcked: s.frameAcked}, hasMoreData
}

func (s *sendStream) popNewOrRetransmittedStreamFrame(maxBytes protocol.ByteCount) (*wire.StreamFrame, bool /* has more data to send */) {
	if s.canceledWrite || s.closeForShutdownErr != nil {
		return nil, false
	}

	if len(s.retransmissionQueue) > 0 {
		f, hasMoreRetransmissions := s.maybeGetRetransmission(maxBytes)
		if f != nil || hasMoreRetransmissions {
			if f == nil {
				return nil, true
			}
			// We always claim that we have more data to send.
			// This might be incorrect, in which case there'll be a spurious call to popStreamFrame in the future.
			return f, true
		}
	}

	if len(s.dataForWriting) == 0 && s.nextFrame == nil {
		if s.finishedWriting && !s.finSent {
			s.finSent = true
			return &wire.StreamFrame{
				StreamID:       s.streamID,
				Offset:         s.writeOffset,
				DataLenPresent: true,
				Fin:            true,
			}, false
		}
		return nil, false
	}

	sendWindow := s.flowController.SendWindowSize()
	if sendWindow == 0 {
		if isBlocked, offset := s.flowController.IsNewlyBlocked(); isBlocked {
			s.sender.queueControlFrame(&wire.StreamDataBlockedFrame{
				StreamID:          s.streamID,
				MaximumStreamData: offset,
			})
			return nil, false
		}
		return nil, true
	}

	f, hasMoreData := s.popNewStreamFrame(maxBytes, sendWindow)
	if dataLen := f.DataLen(); dataLen > 0 {
		s.writeOffset += f.DataLen()
		s.flowController.AddBytesSent(f.DataLen())
	}
	f.Fin = s.finishedWriting && s.dataForWriting == nil && s.nextFrame == nil && !s.finSent
	if f.Fin {
		s.finSent = true
	}
	return f, hasMoreData
}

func (s *sendStream) popNewStreamFrame(maxBytes, sendWindow protocol.ByteCount) (*wire.StreamFrame, bool) {
	if s.nextFrame != nil {
		nextFrame := s.nextFrame
		s.nextFrame = nil

		maxDataLen := utils.Min(sendWindow, nextFrame.MaxDataLen(maxBytes, s.version))
		if nextFrame.DataLen() > maxDataLen {
			s.nextFrame = wire.GetStreamFrame()
			s.nextFrame.StreamID = s.streamID
			s.nextFrame.Offset = s.writeOffset + maxDataLen
			s.nextFrame.Data = s.nextFrame.Data[:nextFrame.DataLen()-maxDataLen]
			s.nextFrame.DataLenPresent = true
			copy(s.nextFrame.Data, nextFrame.Data[maxDataLen:])
			nextFrame.Data = nextFrame.Data[:maxDataLen]
		} else {
			s.signalWrite()
		}
		return nextFrame, s.nextFrame != nil || s.dataForWriting != nil
	}

	f := wire.GetStreamFrame()
	f.Fin = false
	f.StreamID = s.streamID
	f.Offset = s.writeOffset
	f.DataLenPresent = true
	f.Data = f.Data[:0]

	hasMoreData := s.popNewStreamFrameWithoutBuffer(f, maxBytes, sendWindow)
	if len(f.Data) == 0 && !f.Fin {
		f.PutBack()
		return nil, hasMoreData
	}
	return f, hasMoreData
}

func (s *sendStream) popNewStreamFrameWithoutBuffer(f *wire.StreamFrame, maxBytes, sendWindow protocol.ByteCount) bool {
	maxDataLen := f.MaxDataLen(maxBytes, s.version)
	if maxDataLen == 0 { // a STREAM frame must have at least one byte of data
		return s.dataForWriting != nil || s.nextFrame != nil || s.finishedWriting
	}
	s.getDataForWriting(f, utils.Min(maxDataLen, sendWindow))

	return s.dataForWriting != nil || s.nextFrame != nil || s.finishedWriting
}

func (s *sendStream) maybeGetRetransmission(maxBytes protocol.ByteCount) (*wire.StreamFrame, bool /* has more retransmissions */) {
	f := s.retransmissionQueue[0]
	newFrame, needsSplit := f.MaybeSplitOffFrame(maxBytes, s.version)
	if needsSplit {
		return newFrame, true
	}
	s.retransmissionQueue = s.retransmissionQueue[1:]
	return f, len(s.retransmissionQueue) > 0
}

func (s *sendStream) hasData() bool {
	s.mutex.Lock()
	hasData := len(s.dataForWriting) > 0
	s.mutex.Unlock()
	return hasData
}

func (s *sendStream) getDataForWriting(f *wire.StreamFrame, maxBytes protocol.ByteCount) {
	if protocol.ByteCount(len(s.dataForWriting)) <= maxBytes {
		f.Data = f.Data[:len(s.dataForWriting)]
		copy(f.Data, s.dataForWriting)
		s.dataForWriting = nil
		s.signalWrite()
		return
	}
	f.Data = f.Data[:maxBytes]
	copy(f.Data, s.dataForWriting)
	s.dataForWriting = s.dataForWriting[maxBytes:]
	if s.canBufferStreamFrame() {
		s.signalWrite()
	}
}

func (s *sendStream) frameAcked(f wire.Frame) {
	f.(*wire.StreamFrame).PutBack()

	s.mutex.Lock()
	if s.canceledWrite {
		s.mutex.Unlock()
		return
	}
	s.numOutstandingFrames--
	if s.numOutstandingFrames < 0 {
		panic("numOutStandingFrames negative")
	}
	newlyCompleted := s.isNewlyCompleted()
	s.mutex.Unlock()

	if newlyCompleted {
		s.sender.onStreamCompleted(s.streamID)
	}
}

// frameAcked()方法的PR化
func (s *sendStream) prStreamframeAcked(f wire.Frame) {
	f.(*wire.PRStreamFrame).PutBack()

	s.mutex.Lock()
	if s.canceledWrite {
		s.mutex.Unlock()
		return
	}
	s.numOutstandingFrames--
	if s.numOutstandingFrames < 0 {
		panic("numOutStandingFrames negative")
	}
	newlyCompleted := s.isNewlyCompleted()
	s.mutex.Unlock()

	if newlyCompleted {
		s.sender.onStreamCompleted(s.streamID)
	}
}

func (s *sendStream) isNewlyCompleted() bool {
	completed := (s.finSent || s.canceledWrite) && s.numOutstandingFrames == 0 && len(s.retransmissionQueue) == 0
	if completed && !s.completed {
		s.completed = true
		return true
	}
	return false
}

func (s *sendStream) queueRetransmission(f wire.Frame) {
	sf := f.(*wire.StreamFrame)
	sf.DataLenPresent = true
	s.mutex.Lock()
	if s.canceledWrite {
		s.mutex.Unlock()
		return
	}
	s.retransmissionQueue = append(s.retransmissionQueue, sf)
	s.numOutstandingFrames--
	if s.numOutstandingFrames < 0 {
		panic("numOutStandingFrames negative")
	}
	s.mutex.Unlock()

	s.sender.onHasStreamData(s.streamID)
}

// queueRetransmission()方法的PR化
// PR策略：首先选择四种策略之一，进行重传判定，如果重传则将PR_stream转为Stream帧放入Stream重传队列
// 如果不重传，则放一个PR_Ack_Notify帧到重传队列
func (s *sendStream) prQueueRetransmission(f wire.Frame) {
	frame := f.(*wire.PRStreamFrame)

	pr_retran_enabled := false
	switch frame.PtdaC {
	case 0x80: // 概率重传策略,生成0-10000的随机值，ptdaC>它则PR重传，小于则正常重传
		pC :=  int(frame.PtdaC)
		rand.Seed(time.Now().Unix())
		retran_threshold := rand.Intn(10000)
		if pC > int(retran_threshold) {
			pr_retran_enabled = true
		}
	case 0x40:
	case 0x20:
	case 0x10:
	}
	
	if !pr_retran_enabled {  // 正常重传
		sf := wire.StreamFrame{
			StreamID: frame.StreamID,
			Offset: frame.Offset,
			Data: frame.Data,
			Fin: frame.Fin,
			DataLenPresent: frame.DataLenPresent,
		}
		s.queueRetransmission(&sf)
	} else {
		prAckNf := wire.PRAckNotifyFrame {
			StreamID: frame.StreamID,
			Offset: frame.Offset,
			PRDataLen: uint64(frame.DataLen()),
			Fin: frame.Fin,
			DataLenPresent: frame.DataLenPresent,
			PTDA: frame.PTDA,
			P: frame.P,
			T: frame.T,
			D: frame.D,
			A: frame.A,
			PtdaC: frame.PtdaC,
		}
		s.prAckNotifyQueueRetransmission(&prAckNf)
	}
	
}

func (s *sendStream) prAckNotifyQueueRetransmission (f wire.Frame){
	prAckNf := f.(*wire.PRAckNotifyFrame)
	prAckNf.DataLenPresent = true
	s.mutex.Lock()
	if s.canceledWrite {
		s.mutex.Unlock()
		return
	}
	s.prAckNotifyRetransmissionQueue = append(s.prAckNotifyRetransmissionQueue, prAckNf)
	s.numOutstandingFrames--
	if s.numOutstandingFrames < 0 {
		panic("numOutStandingFrames negative")
	}
	s.mutex.Unlock()

	s.sender.onHasStreamData(s.streamID)
}

func (s *sendStream) Close() error {
	s.mutex.Lock()
	if s.closedForShutdown {
		s.mutex.Unlock()
		return nil
	}
	if s.canceledWrite {
		s.mutex.Unlock()
		return fmt.Errorf("close called for canceled stream %d", s.streamID)
	}
	s.ctxCancel()
	s.finishedWriting = true
	s.mutex.Unlock()

	s.sender.onHasStreamData(s.streamID) // need to send the FIN, must be called without holding the mutex
	return nil
}

func (s *sendStream) CancelWrite(errorCode StreamErrorCode) {
	s.cancelWriteImpl(errorCode, fmt.Errorf("Write on stream %d canceled with error code %d", s.streamID, errorCode))
}

// must be called after locking the mutex
func (s *sendStream) cancelWriteImpl(errorCode qerr.StreamErrorCode, writeErr error) {
	s.mutex.Lock()
	if s.canceledWrite {
		s.mutex.Unlock()
		return
	}
	s.ctxCancel()
	s.canceledWrite = true
	s.cancelWriteErr = writeErr
	s.numOutstandingFrames = 0
	s.retransmissionQueue = nil
	newlyCompleted := s.isNewlyCompleted()
	s.mutex.Unlock()

	s.signalWrite()
	s.sender.queueControlFrame(&wire.ResetStreamFrame{
		StreamID:  s.streamID,
		FinalSize: s.writeOffset,
		ErrorCode: errorCode,
	})
	if newlyCompleted {
		s.sender.onStreamCompleted(s.streamID)
	}
}

func (s *sendStream) updateSendWindow(limit protocol.ByteCount) {
	s.mutex.Lock()
	hasStreamData := s.dataForWriting != nil || s.nextFrame != nil
	s.mutex.Unlock()

	s.flowController.UpdateSendWindow(limit)
	if hasStreamData {
		s.sender.onHasStreamData(s.streamID)
	}
}

func (s *sendStream) handleStopSendingFrame(frame *wire.StopSendingFrame) {
	s.cancelWriteImpl(frame.ErrorCode, &StreamError{
		StreamID:  s.streamID,
		ErrorCode: frame.ErrorCode,
	})
}

func (s *sendStream) Context() context.Context {
	return s.ctx
}

func (s *sendStream) SetWriteDeadline(t time.Time) error {
	s.mutex.Lock()
	s.deadline = t
	s.mutex.Unlock()
	s.signalWrite()
	return nil
}

// CloseForShutdown closes a stream abruptly.
// It makes Write unblock (and return the error) immediately.
// The peer will NOT be informed about this: the stream is closed without sending a FIN or RST.
func (s *sendStream) closeForShutdown(err error) {
	s.mutex.Lock()
	s.ctxCancel()
	s.closedForShutdown = true
	s.closeForShutdownErr = err
	s.mutex.Unlock()
	s.signalWrite()
}

// signalWrite performs a non-blocking send on the writeChan
func (s *sendStream) signalWrite() {
	select {
	case s.writeChan <- struct{}{}:
	default:
	}
}
