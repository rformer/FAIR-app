package scope_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	yaml "go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/internal/scope"
	"github.com/rformer/fair-app/pkg/settings"
)

// TestNATSStreams (F-014 T-04, design §3.6): deploy/k8s/nats-streams.yaml
// holds the streams the installer provisions, in JetStream's own form, and
// they capture exactly the subjects published with an acknowledgement: the
// scope worker's (it refuses to start otherwise) and settings changes.
func TestNATSStreams(t *testing.T) {
	b, err := os.ReadFile("../../deploy/k8s/nats-streams.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cm struct {
		Kind     string `yaml:"kind"`
		Metadata struct{ Name, Namespace string }
		Data     map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(b, &cm); err != nil {
		t.Fatal(err)
	}
	if cm.Kind != "ConfigMap" || cm.Metadata.Name != "fair-nats-streams" || cm.Metadata.Namespace != "fair-platform" || len(cm.Data) != 1 {
		t.Fatalf("not the fair-nats-streams ConfigMap: %+v", cm)
	}
	var streams []jetstream.StreamConfig
	if err := json.Unmarshal([]byte(cm.Data["streams.json"]), &streams); err != nil {
		t.Fatalf("streams.json: %v", err)
	}
	want := append(slices.Clone(scope.Subjects), settings.SubjectChanged)
	var got, names []string
	for _, s := range streams {
		if s.Name == "" || slices.Contains(names, s.Name) || len(s.Subjects) == 0 {
			t.Errorf("stream %q: unnamed, repeated or without subjects", s.Name)
		}
		names = append(names, s.Name)
		// Durable, kept, de-duplicated (the outbox redelivers by message id).
		if s.Storage != jetstream.FileStorage || s.Retention != jetstream.LimitsPolicy || s.Discard != jetstream.DiscardOld ||
			s.MaxAge < 24*time.Hour || s.Duplicates < time.Minute || s.Replicas < 1 || s.Replicas > 3 {
			t.Errorf("stream %s: %+v", s.Name, s)
		}
		for _, sub := range s.Subjects {
			if slices.Contains(got, sub) {
				t.Errorf("subject %s is in two streams", sub)
			}
			got = append(got, sub)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the streams capture %v, want %v", got, want)
	}
	if slices.Contains(got, settings.SubjectHeartbeat) {
		t.Error("heartbeats are core NATS, never stored")
	}
}
