package congestion

import (
	"time"
	//点操作，导入该包后调用该包函数时，可以省略前缀的包名
	//ginkgo是测试工具
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Bandwidth", func() {
	It("converts from time delta", func() {
		Expect(BandwidthFromDelta(1, time.Millisecond)).To(Equal(1000 * BytesPerSecond))
	})
})
