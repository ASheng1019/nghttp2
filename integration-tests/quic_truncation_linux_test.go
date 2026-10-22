//go:build quic && linux

package nghttp2

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestH3DropsTruncatedDatagrams(t *testing.T) {
	// ASan can define recvmsg in the executable and still forward to the
	// injected function. Only the ngtcp2 symbol must be imported directly.
	for _, flags := range []string{"payload", "control", "both"} {
		t.Run(flags, func(t *testing.T) {
			env, record := faultLibrary(t, "quic_truncation", "ngtcp2_pkt_decode_version_cid")
			env = append(env, "NGHTTP2_TEST_TRUNCATION="+flags)
			st := newServerTester(t, options{quic: true, env: env})
			defer st.Close()
			for i := 0; i < 2; i++ {
				res, err := st.http3(requestParam{name: t.Name()})
				if err != nil || res.status != http.StatusOK {
					t.Fatalf("request %d after %s truncation: response=%v error=%v", i, flags, res, err)
				}
			}
			data, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			trace := string(data)
			if !strings.Contains(trace, "truncation-injected") ||
				!strings.Contains(trace, "truncated-input-discarded") ||
				strings.Contains(trace, "truncated-input-reached-parser") {
				t.Fatalf("truncated datagram processing: %s", trace)
			}
		})
	}
}
