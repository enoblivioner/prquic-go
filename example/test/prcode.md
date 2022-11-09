## 实现quic-go的部分可靠(PR)传输的代码记录

相关的内容在 `connection.go`文件的`run()`方法中，包括三个方法：

+ `handlePacketImpl()`
+ `OnLossDetectionTimeout()`
+ `sendPackets()` 

先看`handlePacketImpl()`的代码，功能是处理收到的包，主要内容为：

+ 如果是长头包，则用`handleLongHeaderPacket()`方法处理
+ 如果是短头包，则用`handleShortHeaderPacket()`方法处理

```go
func (s *connection) handlePacketImpl(rp *receivedPacket) bool {
    ···
    if wire.IsLongHeaderPacket(p.data[0]) {
        ···
        if wasProcessed := s.handleLongHeaderPacket(p, hdr); wasProcessed {
            processed = true
        }
        ···
    } else {
        ···
        processed = s.handleShortHeaderPacket(p, destConnID)
        ···
    }
    ···
}
```

其中`handleLongHeaderPacket()`方法的代码，主要进行的操作是解包，再调用`handleUnpackedPacket`方法处理。类似地，在`handleShortHeaderPacket()`方法中，解压短头包后，调用了`handleUnpackedShortHeaderPacket()`方法进行处理：

```go
func (s *connection) handleLongHeaderPacket(p *receivedPacket, hdr *wire.Header) bool /* was the packet successfully processed */ {
	···
	if err := s.handleUnpackedPacket(packet, p.ecn, p.rcvTime, p.Size()); err != nil {
		s.closeLocal(err)
		return false
	}
	return true
}
```

首先分析`handleUnpackedPacket()`方法的代码，主要是调用`handleFrames()`方法处理包：

```go
func (s *connection) handleUnpackedPacket(···) error { 
	···
	isAckEliciting, err := s.handleFrames(packet.data, packet.hdr.DestConnectionID, packet.encryptionLevel, log)
	···
}
```

`handleFrames()`方法中，首先使用`frameParser.ParseNext()`方法获取包中每一帧，再判断是否是能触发ACK的帧，然后调用`handleFrame()`方法。代码如下：

```go
func (s *connection) handleFrames(...) (isAckEliciting bool, _ error) {
	// Only used for tracing.
	// If we're not tracing, this slice will always remain empty.
	var frames []wire.Frame
	for len(data) > 0 {
		l, frame, err := s.frameParser.ParseNext(data, encLevel)
		...
        if ackhandler.IsFrameAckEliciting(frame) {
			isAckEliciting = true
		}
        ···
	}

	if log != nil {
        ...
		for _, frame := range frames {
			if err := s.handleFrame(frame, encLevel, destConnID); err != nil {
				return false, err
			}
		}
	}
	return
}
```

`frameParser.ParseNext()`方法内部调用了`frameParser.parseNext()`方法。后者调用`parseFrame()`获取帧。代码如下。该方法读取首字节，并据此判断帧类型，再调用相应的帧处理方法。因此，在此处新增上述四种帧的类型并调用处理方法，处理方法的定义在各自帧的文件中(wire/...frame.go)。四种帧的类型码定义如下，参考见RFC9000中19章：
+ PRStream帧: 0x48...0x4f
+ PRAck帧: 0x50
+ PRAck_Notify帧: 0x51
+ PRDatagram帧: 0x52

```go
func (p *frameParser) parseFrame(r *bytes.Reader, typeByte byte, encLevel protocol.EncryptionLevel) (Frame, error) {
	var frame Frame
	var err error
	if typeByte&0xf8 == 0x8 {
		frame, err = parseStreamFrame(r, p.version)
	} else if typeByte&0xf8 == 0x48{  //0x48..0x4f是PR_STREAM帧
		frame, err = parsePRStreamFrame(r, p.version) // 添加PRStreamFrame类型及处理
	} else {
		switch typeByte {
		case 0x1:
			frame, err = parsePingFrame(r, p.version)
		···
		// RFC9000:此注册表中的永久注册项遵循（[RFC8126]第4.6节）规约策略进行分配，但0x00和0x3f（十六进制）之间的值除外
		// 0x50 51 52/53 分别为新增的PR_Ack、PR_AcK_Notify、PR_Datagram帧
		case 0x50:
			ackDelayExponent := p.ackDelayExponent
			if encLevel != protocol.Encryption1RTT {
				ackDelayExponent = protocol.DefaultAckDelayExponent
			}
			frame, err = parsePRAckFrame(r, ackDelayExponent, p.version)
		case 0x51:
			ackDelayExponent := p.ackDelayExponent
			if encLevel != protocol.Encryption1RTT {
				ackDelayExponent = protocol.DefaultAckDelayExponent
			}
			frame, err = parsePRAckNotifyFrame(r, ackDelayExponent, p.version)
		case 0x52, 0x53:
            if p.supportsDatagrams {
				frame, err = parsePRDatagramFrame(r, p.version)
				break
			} else {
                err = errors.New("unknown frame type")
            }
			
		case 0x30, 0x31:
			if p.supportsDatagrams {
				frame, err = parseDatagramFrame(r, p.version)
				break
			}
			fallthrough
		default:
			err = errors.New("unknown frame type")
		}
	}
	···
	return frame, nil
}
```

获取完帧后，调用`handleFrame()`方法对不同类型的帧采取相应的处理方法。

```go
func (s *connection) handleFrame(f wire.Frame, encLevel protocol.EncryptionLevel, destConnID protocol.ConnectionID) error {
	var err error
	wire.LogFrame(s.logger, f, false)
	switch frame := f.(type) {
	case *wire.CryptoFrame:
		err = s.handleCryptoFrame(frame, encLevel)
	case *wire.StreamFrame:
		err = s.handleStreamFrame(frame)
	case *wire.AckFrame:
		err = s.handleAckFrame(frame, encLevel)
		wire.PutAckFrame(frame)
	...
	default:
		err = fmt.Errorf("unexpected frame type: %s", reflect.ValueOf(&frame).Elem().Type().Name())
	}
	return err
}
```

根据我们的prquic逻辑来说，相关的帧有五种：
+ **ACK帧**，发送方用于判断包丢失随后触发相应的部分重传(PR)行为
+ **PR_ACK_NOTIFY帧**，发送方PR行为之后，发送该帧告诉接收方强制更新ACK累积确认，哪怕有的数据并未重传
+ **PR_ACK帧**，接收方想要启用PR机制，发送该帧给发送方，发送方据此执行自己的PR策略
+ **PR_STREAM帧**，PR行为中用于承载数据的帧，对于完全可靠传输中的STREAM帧，对于该帧，发送方可以执行PR行为
+ **PR_DATAGRAM帧**，同PR_STREAM帧，另一种实现方式

**因此需要添加后四种帧类型，以及相应的方法。同时添加到`handleFrame()`方法的`switch case`中。**

帧的类型定义在`/internal/wire/`目录下定义相应文件：
+ pr_ack_frame.go
+ pr_ack_notify_frame.go
+ pr_datagram_frame.go
+ pr_stream_frame.go

每个文件中都应定义相应帧的结构体和方法。目前还没分析到相应内容，因此暂时都为空。

首先来分析Ack帧的`handleAckFrame()`方法，其中与pr相关的代码就是调用了`sentPacketHandler.ReceivedAck()`方法。具体来说，后者调用了`detectLostPackets()`方法来探测丢失的包并处理，该方法中要关注的是调用了`queueFramesForRetransmission()`方法：

```go
func (h *sentPacketHandler) queueFramesForRetransmission(p *Packet) {
	if len(p.Frames) == 0 {
		panic("no frames")
	}
	for _, f := range p.Frames {
		f.OnLost(f.Frame)  //钩子函数，针对不同帧有不同处理，丢失的帧加入重传队列
	}
	p.Frames = nil
}
```

该方法对丢失包中的逐帧调用相应的`OnLost()`方法，该方法是个钩子函数，用于在不同帧丢失时采取不同的方法。

由于发送方是先发送包，再定义包若丢失时其中各帧的`OnLost()`方法，最后在收到Ack帧或发送超时时才判断丢包，执行该方法，因此先不看`OnLost()`方法的具体内容，等到分析完发包的方法再回过来看。

而在`handlePRStreamFrame()`方法之中，则以流为基本单位，接收PR_Stream帧。因为采用部分可靠传输后存在强制Ack，该方法应在`handleStreamFrame()`方法的基础上作一定修改以满足：实际未收到相应的帧(PR_Stream帧)，但在接收方更新相应帧所带的数据（如填0）。

同样，PR_Datagram帧的处理方法`handleDatagramFrame()`也应作相应更改。

与`handleLongHeaderPacket()`方法一样，`handleUnpackedShortHeaderPacket()`方法也是调用`handleFrames()`方法处理包，不再赘述。

再看`OnLossDetectionTimeout()`方法的代码，该方法发生在检测到超时(认为丢失)时，调用`detectLostPackets()`方法探测丢失的包，并设置ptoMode为 `SendPTOInitial`、`SendPTOHandshake`、`SendPTOAppData`之一。

```go
func (h *sentPacketHandler) OnLossDetectionTimeout() error {
	···
	if !earliestLossTime.IsZero() {
		···
		// Early retransmit or time loss detection
		return h.detectLostPackets(time.Now(), encLevel)
	}
    ···
}
```

`detectLostPackets()`方法代码如下，它对所有发送过的包进行是否丢失的判断，丢失的情况有两种：超时和空洞过大(包号小于当前允许未确认的最小包号)。若丢失，则触发丢失声明、重传和拥塞控制。其中我们关注的是重传，调用的方法是`queueFramesForRetransmission()`。

```go
func (h *sentPacketHandler) detectLostPackets(now time.Time, encLevel protocol.EncryptionLevel) error {
	···
	return pnSpace.history.Iterate(func(p *Packet) (bool, error) {
		···
		if packetLost {  //检查所有包，如果丢了就声明并加入重传队列
			p = pnSpace.history.DeclareLost(p)
			// the bytes in flight need to be reduced no matter if the frames in this packet will be retransmitted
			h.removeFromBytesInFlight(p)
			h.queueFramesForRetransmission(p)
			if !p.IsPathMTUProbePacket {
				h.congestion.OnPacketLost(p.PacketNumber, p.Length, priorInFlight)
			}
		}
		return true, nil
	})
}
```

`queueFramesForRetransmission()`方法则调用了方法`OnLost()`，前面已经说过，不同帧的该方法不同。

```go
func (h *sentPacketHandler) queueFramesForRetransmission(p *Packet) {
	if len(p.Frames) == 0 {
		panic("no frames")
	}
	for _, f := range p.Frames {
		f.OnLost(f.Frame)  //钩子函数，针对不同帧有不同处理，丢失的帧加入重传队列
	}
	p.Frames = nil
}
```

最后看`sendPackets()`的代码，功能是检测不同发送模式，开始包的发送。

```go
func (s *connection) sendPackets() error {
	s.pacingDeadline = time.Time{}  
	var sentPacket bool // only used in for packets sent in send mode SendAny
	for {
		sendMode := s.sentPacketHandler.SendMode()  //sendMode()获取当前可以发送的包类型
		···
		switch sendMode {
		case ackhandler.SendNone:
			return nil
		case ackhandler.SendAck:
			// If we already sent packets, and the send mode switches to SendAck,
			// as we've just become congestion limited.
			// There's no need to try to send an ACK at this moment.
			if sentPacket {
				return nil
			}
			// We can at most send a single ACK only packet.
			// There will only be a new ACK after receiving new packets.
			// SendAck is only returned when we're congestion limited, so we don't need to set the pacing timer.
			return s.maybeSendAckOnlyPacket()
		case ackhandler.SendPTOInitial:
			if err := s.sendProbePacket(protocol.EncryptionInitial); err != nil {
				return err
			}
		case ackhandler.SendPTOHandshake:
			if err := s.sendProbePacket(protocol.EncryptionHandshake); err != nil {
				return err
			}
		case ackhandler.SendPTOAppData:
			if err := s.sendProbePacket(protocol.Encryption1RTT); err != nil {
				return err
			}
		case ackhandler.SendAny:
			sent, err := s.sendPacket()
			if err != nil || !sent {
				return err
			}
			sentPacket = true
		default:
			return fmt.Errorf("BUG: invalid send mode %d", sendMode)
		}
		// Prioritize receiving of packets over sending out more packets.
		if len(s.receivedPackets) > 0 {
			s.pacingDeadline = deadlineSendImmediately
			return nil
		}
		if s.sendQueue.WouldBlock() {
			return nil
		}
	}
}
```

在`SendAck()`模式时，可能不发送或调用`maybeSendAckOnlyPacket()`方法发送包。该方法代码如下：

```go
func (s *connection) maybeSendAckOnlyPacket() error {
	if !s.handshakeConfirmed {
		packet, err := s.packer.PackCoalescedPacket(true)
		···
		s.logCoalescedPacket(packet)
		for _, p := range packet.packets {
			s.sentPacketHandler.SentPacket(p.ToAckHandlerPacket(time.Now(), s.retransmissionQueue))
		}
		s.connIDManager.SentPacket()
		s.sendQueue.Send(packet.buffer)
		return nil
	}

	packet, err := s.packer.PackPacket(true)
	if err != nil {
		return err
	}
	if packet == nil {
		return nil
	}
	s.sendPackedPacket(packet, time.Now())
	return nil
}
```

上述代码
+ 首先判断是否完成握手，若未完成，则：
	1. 先`PackCoalescedPacket()`方法获取合并的数据包，该方法只能在握手未完成时调用。它分别：
		- 调用`maybeGetCryptoPacket()`获取initial包和handshake包
		- 调用`maybeGetAppDataPacketFor0RTT()`和`maybeGetShortHeaderPacket()`来获取0-RTT和1-RTT包（这两种包用于承载应用数据）。
		- 最后用`appendPacket()`方法装包，存放到切片packet.packets中。
	2. 接着调用`ToAckHandlerPacket()`方法对联合包中的每一帧设置`OnLost()`方法（Stream帧除外），`sentPacketHandler.SentPacket()`方法被调用用来做一些要发送的包的处理，比如丢包和拥塞窗口更新。
	3. 最后用`sendQueue.Send()`方法加入队列，由于在`conn.run()`中启动了`sendQueue.run()`方法，使得`sendQueue.Send()`添加的数据能被持续发送。
+ 随后调用`packer.PackPacket()`方法：
	1. 调用`maybeGetShortHeaderPacket()`方法 -> 调用`maybeGetAppDataPacket()` -> 调用`composeNextPacket()`：
		- `GetAckFrame()` 获取Ack帧
		- `datagramQueue.Get()` 获取Datagram帧，注意在该方法下还设置了其丢失方法`OnLost()`为空
		- `retransmissionQueue.GetAppDataFrame()` 获取除了StreamFrame的重传内容
		- `AppendControlFrames()` 加入控制帧
		- `AppendStreamFrames()` **加入Stream帧**  -> 调用`popStreamFrame()` -> 调用`popNewOrRetransmittedStreamFrame()` 同时设置`OnLost: s.queueRetransmission, OnAcked: s.frameAcked` 其中s为*sendStream:
			* `maybeGetRetransmission()` **获取重传Stream帧**
			* `popNewStreamFrame()` 获取新的Stream帧
	2. 调用`appendPacket()`方法装包
+ 调用`sendPackedPacket()`方法发送包

其他模式的发送方式也类似。
