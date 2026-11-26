// Package otlpresponse reads what an OTLP collector answered from the error
// the OpenTelemetry exporters return.
package otlpresponse

import (
	"errors"
	"reflect"
	"strings"
)

// otlpModulePrefix is the module every OpenTelemetry OTLP exporter lives
// under.
const otlpModulePrefix = "go.opentelemetry.io/otel/exporters/otlp/"

// RejectedSpans reports whether err only carries OTLP partial-success
// answers: the collector accepted the request and kept every span except
// the ones it names as rejected.
func RejectedSpans(err error) (int64, bool) {
	if err == nil {
		return 0, false
	}
	var rejected int64
	if !onlyPartialSuccess(err, &rejected) {
		return 0, false
	}
	return rejected, true
}

func onlyPartialSuccess(err error, rejected *int64) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		errs := joined.Unwrap()
		if len(errs) == 0 {
			return false
		}
		for _, e := range errs {
			if !onlyPartialSuccess(e, rejected) {
				return false
			}
		}
		return true
	}
	if n, ok := partialSuccessItems(err); ok {
		*rejected += n
		return true
	}
	if next := errors.Unwrap(err); next != nil {
		return onlyPartialSuccess(next, rejected)
	}
	return false
}

func partialSuccessItems(err error) (int64, bool) {
	v := reflect.ValueOf(err)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return 0, false
		}
		v = v.Elem()
	}
	t := v.Type()
	if v.Kind() != reflect.Struct || t.Name() != "PartialSuccess" ||
		!strings.HasPrefix(t.PkgPath(), otlpModulePrefix) || !strings.HasSuffix(t.PkgPath(), "/internal") {
		return 0, false
	}
	return rejectedItems(v)
}

// rejectedItems reads the RejectedItems count of a PartialSuccess value,
// refusing a shape it does not recognise rather than guessing.
func rejectedItems(v reflect.Value) (int64, bool) {
	items := v.FieldByName("RejectedItems")
	if !items.IsValid() || !items.CanInt() {
		return 0, false
	}
	return max(items.Int(), 0), true
}
