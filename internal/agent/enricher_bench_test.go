package agent

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/podtrace/podtrace/internal/events"
)

// BenchmarkEnricherLookup measures the raw hot-path cost of a
// PodEnricher.Lookup.
func BenchmarkEnricherLookup(b *testing.B) {
	e := NewPodEnricher()
	entries := makeBenchEntries(64)
	e.Snapshot(entries)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.Lookup(uint64(i % 64))
	}
}

// BenchmarkEnrichBatch covers the production hot path: enrichBatch is
// what Router.Export calls once per batch.
func BenchmarkEnrichBatch(b *testing.B) {
	e := NewPodEnricher()
	entries := makeBenchEntries(8)
	e.Snapshot(entries)

	const batchSize = 128
	batch := make([]*events.Event, batchSize)
	for i := range batch {
		batch[i] = &events.Event{CgroupID: uint64(i % 8)}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := range batch {
			batch[j].K8s = nil
		}
		enrichBatch(e, batch)
	}
}

// BenchmarkRouterExportWithEnricher exercises the full per-event path
// (filter match + enrichment + delivery) so the cost of enrichment
// can be compared against BenchmarkRouterExportWithoutEnricher below.
func BenchmarkRouterExportWithEnricher(b *testing.B) {
	r, _ := newBenchRouter(b, true)
	batch := newBenchBatch(128)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := range batch {
			batch[j].K8s = nil
		}
		_ = r.Export(context.Background(), batch)
	}
}

// BenchmarkRouterExportWithoutEnricher is the control case: same
// batch, same router shape, no enricher attached.
func BenchmarkRouterExportWithoutEnricher(b *testing.B) {
	r, _ := newBenchRouter(b, false)
	batch := newBenchBatch(128)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := range batch {
			batch[j].K8s = nil
		}
		_ = r.Export(context.Background(), batch)
	}
}

// makeBenchEntries produces n PodCgroupEntry values bound to n
// distinct pods so the owner resolution and metadata-build paths
// exercise realistic data shapes.
func makeBenchEntries(n int) []PodCgroupEntry {
	tc := true
	out := make([]PodCgroupEntry, 0, n)
	for i := 0; i < n; i++ {
		uid := types.UID(uidFor(i))
		out = append(out, PodCgroupEntry{
			CgroupID:      uint64(i),
			ContainerName: "app",
			Pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns",
					Name:      "pod-" + uidFor(i),
					UID:       uid,
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "ReplicaSet", Name: "web-7d8c9c", Controller: &tc},
					},
				},
				Spec: corev1.PodSpec{NodeName: "node-1"},
			},
		})
	}
	return out
}

func newBenchRouter(b *testing.B, withEnricher bool) (*Router, *PodEnricher) {
	b.Helper()
	r := NewRouter(nil)
	var enricher *PodEnricher
	if withEnricher {
		enricher = NewPodEnricher()
		enricher.Snapshot(makeBenchEntries(8))
		r = r.WithEnricher(enricher)
	}
	r.Publish([]CRRule{{
		Key:       CRKey{Namespace: "ns", Name: "cr"},
		CgroupIDs: cgroupSet(0, 1, 2, 3, 4, 5, 6, 7),
		Filters:   map[events.EventType]struct{}{events.EventDNS: {}},
		Exporter:  &nullExporter{},
	}})
	return r, enricher
}

func newBenchBatch(n int) []*events.Event {
	out := make([]*events.Event, n)
	for i := range out {
		out[i] = &events.Event{CgroupID: uint64(i % 8), Type: events.EventDNS}
	}
	return out
}

func cgroupSet(ids ...uint64) map[uint64]struct{} {
	out := make(map[uint64]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

// nullExporter discards every event — it's the "no work past the
// router" baseline so the benchmark isolates router+enrichment cost.
type nullExporter struct{}

func (nullExporter) Name() string                                          { return "null" }
func (nullExporter) Export(_ context.Context, batch []*events.Event) error { return nil }
func (nullExporter) Close(_ context.Context) error                         { return nil }

func uidFor(i int) string {
	const hex = "0123456789abcdef"
	// 16-char synthetic UID; uniqueness is what we care about.
	out := make([]byte, 16)
	for j := range out {
		out[j] = hex[(i+j)%16]
	}
	return string(out)
}