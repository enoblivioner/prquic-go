package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// 1
// 是否启用PR行为
var PR_ENABLED bool = true

// PR策略选项
var P bool = true    // 概率重传
var T bool           // 次数重传
var D bool           // 时限重传
var A bool           // 优先级重传（流、内容）
var PTDA byte = 0x80 // PTDA的字节存储
var PtadC uint64 = 0 // 存放PR策略选项对应的内容/值
var PR_ERROR error

// ----------------------2----------------------------
// // 是否启用PR行为
// var PR_ENABLED bool = true

// // PR策略选项
// var P	bool // 概率重传
// var T	bool = true	// 次数重传
// var D	bool	// 时限重传
// var A	bool	// 优先级重传（流、内容）
// var PTDA byte = 0x40 // PTDA的字节存储
// var PtadC uint64  = 3 // 存放PR策略选项对应的内容/值  次数
// var PR_ERROR error

// -----------------------3--------------------------
// // 是否启用PR行为
// var PR_ENABLED bool = true

// // PR策略选项
// var P	bool // 概率重传
// var T	bool 	// 次数重传
// var D	bool = true	// 时限重传
// var A	bool	// 优先级重传（流、内容）
// var PTDA byte = 0x20 // PTDA的字节存储
// var PtadC uint64  = 1000 // 存放PR策略选项对应的内容/值  时间(毫秒)
// var PR_ERROR error

// -----------------------4--------------------------
// // 是否启用PR行为
// var PR_ENABLED bool = true

// // PR策略选项
// var P	bool // 概率重传
// var T	bool 	// 次数重传
// var D	bool 	// 时限重传
// var A	bool = true	// 优先级重传（流、内容）
// var PTDA byte = 0x10 // PTDA的字节存储
// var PtadC uint64   // 存放PR策略选项对应的内容/值
// var PR_ERROR error

// 存sendStream.prAckNotifyRetransmissionQueue中的PRAckNotify Frame
// 供packetContents.retransmissionQueue获取
var PRAckNotifyFrames []wire.Frame
var pr_version protocol.VersionNumber

var Frames_recv_num int
