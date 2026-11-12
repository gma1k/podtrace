package exporter

import (
	"bytes"
	"context"
	"fmt"
)

// maxBatchBytes bounds one request body of the JSON exporters, so an
// export is a few sized POSTs instead of one request per trace or span.
const maxBatchBytes = 512 * 1024

// encodedElement is one JSON element of a request body and the number of
// the trace's spans it carries.
type encodedElement struct {
	body  []byte
	spans int
}

// encodedTrace is one trace already serialised for a backend, its elements
// in span order.
type encodedTrace struct {
	traceID  string
	elements []encodedElement
}

// bodyFrame is how a backend joins elements into one request body.
type bodyFrame struct {
	open, separator, close string
}

var (
	jsonArrayFrame = bodyFrame{open: "[", separator: ",", close: "]"}
	hecFrame       = bodyFrame{separator: "\n", close: "\n"}
)

// collectorDownAfter is how many requests carrying a single trace the
// collector must refuse with a 5xx, before it has accepted anything in this
// export, to be judged down rather than choking on particular traces. Until
// then a 5xx batch is bisected; once any request succeeded the collector is
// known to work and a 5xx never stops the export.
const collectorDownAfter = 3

// maxIsolationPosts caps the requests one export spends bisecting failed
// batches; isolating one bad trace among n costs about 2*log2(n). Past it,
// failed batches are resolved one trace per request, as every trace was
// sent before batching, so many bad traces never cost a good trace its
// delivery.
const maxIsolationPosts = 64

// batchShare is the part of one trace a request body carries.
type batchShare struct {
	traceID  string
	elements []encodedElement
	spans    int
}

// batchSender delivers the batches of one export.
type batchSender struct {
	ctx            context.Context
	outcome        *exportOutcome
	frame          bodyFrame
	post           func(context.Context, []byte) error
	answered       bool
	singleRefusals int
	isolationPosts int
	stopped        bool
}

// sendTraceBatches packs the elements of every trace into request bodies of
// at most maxBytes (an element larger than that travels alone) and posts
// them in order.
//
// A permanent failure drops only its own batch. A 5xx answer is isolated:
// the batch is split in halves until the traces the collector refuses are
// found, so every other trace is still delivered and only the refused ones
// are offered again. The export stops, offering every trace not yet
// delivered again, when the collector does not answer (transport error,
// deadline), answers 408 or 429, or is judged down (collectorDownAfter): a
// failing collector costs about 2*log2(n) requests, not one per trace.
//
// A trace split across batches records how many of its leading spans were
// settled (delivered or permanently refused); once a part of it is offered
// again, its later parts are not sent, so the settled spans stay a prefix.
func sendTraceBatches(ctx context.Context, outcome *exportOutcome, traces []encodedTrace, maxBytes int, frame bodyFrame,
	post func(context.Context, []byte) error) {
	s := &batchSender{ctx: ctx, outcome: outcome, frame: frame, post: post}
	var shares []batchShare
	size := 0

	for i, t := range traces {
		for _, e := range t.elements {
			added := len(frame.separator) + len(e.body)
			if len(shares) > 0 && size+added+len(frame.close) > maxBytes {
				s.deliver(shares)
				shares, size = nil, 0
				if s.stopped {
					outcome.retry(remainingTraceIDs(traces[i:])...)
					return
				}
			}
			if len(shares) == 0 {
				size = len(frame.open) + len(e.body)
			} else {
				size += added
			}
			if last := len(shares) - 1; last >= 0 && shares[last].traceID == t.traceID {
				shares[last].elements = append(shares[last].elements, e)
				shares[last].spans += e.spans
				continue
			}
			shares = append(shares, batchShare{traceID: t.traceID, elements: []encodedElement{e}, spans: e.spans})
		}
	}
	if len(shares) > 0 {
		s.deliver(shares)
	}
}

// deliver sends one batch, leaving out the parts of traces already offered
// again, and isolates the traces a 5xx answer refused.
func (s *batchSender) deliver(shares []batchShare) {
	pending := shares[:0:0]
	for _, sh := range shares {
		if _, retried := s.outcome.failed[sh.traceID]; !retried {
			pending = append(pending, sh)
		}
	}
	if len(pending) == 0 {
		return
	}
	if err := s.attempt(pending); err != nil {
		s.resolve(pending, err)
	}
}

// attempt posts shares once. A delivered or permanently refused batch is
// settled; the error of a transient failure is returned for the caller to
// resolve.
func (s *batchSender) attempt(shares []batchShare) error {
	err := s.post(s.ctx, s.body(shares))
	switch {
	case err == nil:
		s.answered = true
		s.settle(shares)
		return nil
	case isPermanent(err):
		s.answered = true
		s.outcome.record(fmt.Errorf("batch of %d traces: %w", len(shares), err))
		s.settle(shares)
		return nil
	case isServerError(err):
		if !s.answered && len(shares) == 1 {
			s.singleRefusals++
			s.stopped = s.singleRefusals >= collectorDownAfter
		}
	default:
		s.stopped = true
	}
	return err
}

// resolve handles a batch that failed transiently: a 5xx answer is split in
// halves, both halves are posted, and each half that fails again is
// resolved in turn, until single traces remain. Past the isolation budget
// the rest is sent one trace per request. Whatever stays unresolved is
// offered again on the next export.
func (s *batchSender) resolve(shares []batchShare, err error) {
	if s.stopped || !isServerError(err) || len(shares) == 1 {
		s.outcome.record(fmt.Errorf("batch of %d traces: %w", len(shares), err), shareTraceIDs(shares)...)
		return
	}
	if s.isolationPosts+2 > maxIsolationPosts {
		s.onePerRequest(shares)
		return
	}
	mid := len(shares) / 2
	halves := [2][]batchShare{shares[:mid], shares[mid:]}
	var errs [2]error
	var posted [2]bool
	for i, half := range halves {
		if s.stopped {
			break
		}
		s.isolationPosts++
		errs[i] = s.attempt(half)
		posted[i] = true
	}
	for i, half := range halves {
		switch {
		case !posted[i]:
			s.outcome.retry(shareTraceIDs(half)...)
		case errs[i] != nil:
			s.resolve(half, errs[i])
		}
	}
}

func (s *batchSender) onePerRequest(shares []batchShare) {
	for i, sh := range shares {
		if s.stopped {
			s.outcome.retry(shareTraceIDs(shares[i:])...)
			return
		}
		one := []batchShare{sh}
		if err := s.attempt(one); err != nil {
			s.outcome.record(fmt.Errorf("batch of 1 traces: %w", err), sh.traceID)
		}
	}
}

func (s *batchSender) body(shares []batchShare) []byte {
	var b bytes.Buffer
	b.WriteString(s.frame.open)
	first := true
	for _, sh := range shares {
		for _, e := range sh.elements {
			if !first {
				b.WriteString(s.frame.separator)
			}
			first = false
			b.Write(e.body)
		}
	}
	b.WriteString(s.frame.close)
	return b.Bytes()
}

func (s *batchSender) settle(shares []batchShare) {
	for _, sh := range shares {
		s.outcome.settle(sh.traceID, sh.spans)
	}
}

func shareTraceIDs(shares []batchShare) []string {
	ids := make([]string, len(shares))
	for i, sh := range shares {
		ids[i] = sh.traceID
	}
	return ids
}

func remainingTraceIDs(traces []encodedTrace) []string {
	out := make([]string, 0, len(traces))
	for _, t := range traces {
		if len(t.elements) > 0 {
			out = append(out, t.traceID)
		}
	}
	return out
}

// encodeSpans marshals every item into its own element carrying one span.
func encodeSpans[T any](items []T) ([]encodedElement, error) {
	out := make([]encodedElement, 0, len(items))
	for _, item := range items {
		b, err := marshalJSON(item)
		if err != nil {
			return nil, err
		}
		out = append(out, encodedElement{body: b, spans: 1})
	}
	return out, nil
}
