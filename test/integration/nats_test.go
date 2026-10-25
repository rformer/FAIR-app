//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/audit/audittest"
)

// TestNATSJetStreamSink checks the real JetStream path: the AUDIT stream is
// created, events are acknowledged, land on audit.<type>, and survive as
// stored messages. Needs FAIR_TEST_NATS_URL pointing at a JetStream server.
func TestNATSJetStreamSink(t *testing.T) {
	url := os.Getenv("FAIR_TEST_NATS_URL")
	if url == "" {
		t.Skip("FAIR_TEST_NATS_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	audittest.RunContract(t, func(t *testing.T) audittest.Harness {
		prefix := "audit_it_" + randHex(3)
		sink, err := audit.DialNATS(ctx, url, prefix)
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.Ping(ctx); err != nil {
			t.Fatal(err)
		}
		nc, err := nats.Connect(url)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(nc.Close)
		js, _ := jetstream.New(nc)
		return audittest.Harness{Emitter: sink, Received: func(t *testing.T, want int) []audit.Event {
			// The contract only checks subjects under this test's prefix.
			st, err := js.Stream(ctx, audit.StreamName(prefix))
			if err != nil {
				t.Fatal(err)
			}
			c, err := st.OrderedConsumer(ctx, jetstream.OrderedConsumerConfig{FilterSubjects: []string{prefix + ".>"}})
			if err != nil {
				t.Fatal(err)
			}
			var out []audit.Event
			deadline := time.Now().Add(3 * time.Second)
			for len(out) < want && time.Now().Before(deadline) {
				batch, err := c.FetchNoWait(100)
				if err != nil {
					t.Fatal(err)
				}
				for m := range batch.Messages() {
					var e audit.Event
					if err := json.Unmarshal(m.Data(), &e); err != nil {
						t.Fatal(err)
					}
					if m.Subject() != prefix+"."+e.Type {
						t.Fatalf("subject %s for type %s", m.Subject(), e.Type)
					}
					out = append(out, e)
				}
				if len(out) < want {
					time.Sleep(50 * time.Millisecond)
				}
			}
			return out
		}}
	})
}
