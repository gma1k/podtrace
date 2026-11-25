package criticalpath

import (
	"regexp"
	"strings"
)

// idSegment replaces a path segment that identifies one resource rather
// than naming a route.
const idSegment = "{id}"

// minOpaqueIDLength is the shortest segment treated as an opaque identifier
// (a hash, token or ULID) when it mixes digits into an otherwise plain word.
const minOpaqueIDLength = 16

var uuidSegment = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// endpointTemplate groups requests to one route under one endpoint. The
// target as seen on the wire carries the query string and the ids of the
// resources a route serves, so keyed by it every request to /users/{id} was
// its own endpoint and the by-endpoint view filled with single requests
// before the second route was seen. The query and fragment are dropped and
// every id-like path segment becomes idSegment.
func endpointTemplate(endpoint string) string {
	method, target, hasMethod := strings.Cut(endpoint, " ")
	if !hasMethod || !strings.HasPrefix(target, "/") {
		method, target, hasMethod = "", endpoint, false
	}
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	segments := strings.Split(target, "/")
	for i, segment := range segments {
		if isIDSegment(segment) {
			segments[i] = idSegment
		}
	}
	target = strings.Join(segments, "/")
	if hasMethod {
		return method + " " + target
	}
	return target
}

// isIDSegment reports whether a path segment is a number, a UUID, or a long
// token mixing letters and digits.
func isIDSegment(segment string) bool {
	if segment == "" {
		return false
	}
	if uuidSegment.MatchString(segment) {
		return true
	}
	digits := 0
	for _, r := range segment {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '-', r == '_':
		default:
			return false
		}
	}
	if digits == len(segment) {
		return true
	}
	return digits > 0 && len(segment) >= minOpaqueIDLength
}
