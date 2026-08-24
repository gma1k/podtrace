// Command crdcompat compares two sets of generated CRD manifests and reports
// schema changes that break existing objects: a field that disappears from a
// served version, or one whose type changes.
//
// It exists because the graduation contract in docs/api-versioning.md depends
// on such changes being deliberate and recorded. A policy that relies on
// remembering is not a policy — the v0.11.10 rename of
// PodTraceSession.status.phase shipped in a patch release without a BREAKING
// CHANGE footer, which is exactly what this catches.
//
// The tool only reports. Whether a report is a failure is decided by the
// caller, so that a commit carrying a BREAKING CHANGE footer can proceed.
package main

import (
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// Change is one breaking schema difference between two revisions of a CRD.
type Change struct {
	CRD     string
	Version string
	Path    string
	Kind    ChangeKind
	Detail  string
}

// ChangeKind distinguishes why a change breaks existing objects.
type ChangeKind string

const (
	FieldRemoved   ChangeKind = "field removed"
	TypeChanged    ChangeKind = "type changed"
	VersionRemoved ChangeKind = "served version removed"
)

func (c Change) String() string {
	if c.Detail == "" {
		return fmt.Sprintf("%s: %s %s: %s", c.CRD, c.Version, c.Kind, c.Path)
	}
	return fmt.Sprintf("%s: %s %s: %s (%s)", c.CRD, c.Version, c.Kind, c.Path, c.Detail)
}

// crd is the subset of a CustomResourceDefinition this tool reads.
type crd struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Versions []struct {
			Name   string `json:"name"`
			Served bool   `json:"served"`
			Schema struct {
				OpenAPIV3Schema map[string]any `json:"openAPIV3Schema"`
			} `json:"schema"`
		} `json:"versions"`
	} `json:"spec"`
}

// field is a leaf or branch of a schema, keyed by its dotted path.
type field struct {
	openAPIType string
}

// Compare reports the breaking differences between the old and new revision of
// a single CRD manifest. Additions are not breaking and are not reported.
func Compare(oldYAML, newYAML []byte) ([]Change, error) {
	oldCRD, err := parse(oldYAML)
	if err != nil {
		return nil, fmt.Errorf("parsing previous revision: %w", err)
	}
	newCRD, err := parse(newYAML)
	if err != nil {
		return nil, fmt.Errorf("parsing new revision: %w", err)
	}

	name := newCRD.Metadata.Name
	if name == "" {
		name = oldCRD.Metadata.Name
	}

	var changes []Change
	newVersions := servedSchemas(newCRD)
	for version, oldFields := range servedSchemas(oldCRD) {
		newFields, ok := newVersions[version]
		if !ok {
			changes = append(changes, Change{
				CRD:     name,
				Version: version,
				Kind:    VersionRemoved,
				Path:    version,
				Detail:  "requires a storage migration first",
			})
			continue
		}
		changes = append(changes, compareFields(name, version, oldFields, newFields)...)
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Version != changes[j].Version {
			return changes[i].Version < changes[j].Version
		}
		return changes[i].Path < changes[j].Path
	})
	return changes, nil
}

func compareFields(crdName, version string, oldFields, newFields map[string]field) []Change {
	var changes []Change
	for path, oldField := range oldFields {
		newField, ok := newFields[path]
		if !ok {
			changes = append(changes, Change{
				CRD:     crdName,
				Version: version,
				Kind:    FieldRemoved,
				Path:    path,
			})
			continue
		}
		if oldField.openAPIType != "" && newField.openAPIType != "" &&
			oldField.openAPIType != newField.openAPIType {
			changes = append(changes, Change{
				CRD:     crdName,
				Version: version,
				Kind:    TypeChanged,
				Path:    path,
				Detail:  oldField.openAPIType + " -> " + newField.openAPIType,
			})
		}
	}
	return changes
}

func parse(data []byte) (*crd, error) {
	var c crd
	if err := yaml.Unmarshal(stripTemplateLines(data), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// stripTemplateLines drops the Helm control lines that
// hack/inject-crd-annotations.sh wraps around each generated manifest, so the
// committed chart templates can be parsed as plain YAML.
func stripTemplateLines(data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "{{") {
			continue
		}
		kept = append(kept, line)
	}
	return []byte(strings.Join(kept, "\n"))
}

// servedSchemas flattens each served version's schema into dotted field paths.
// Unserved versions are skipped: nothing reads them, so changing them breaks
// nobody.
func servedSchemas(c *crd) map[string]map[string]field {
	out := map[string]map[string]field{}
	for _, v := range c.Spec.Versions {
		if !v.Served {
			continue
		}
		fields := map[string]field{}
		walk("", v.Schema.OpenAPIV3Schema, fields)
		out[v.Name] = fields
	}
	return out
}

// walk descends a structural schema, recording one entry per addressable
// field. Array element schemas are recorded under the array's own path with a
// "[]" suffix so that a type change inside a list is still visible.
func walk(prefix string, schema map[string]any, out map[string]field) {
	if schema == nil {
		return
	}

	if properties, ok := schema["properties"].(map[string]any); ok {
		for name, raw := range properties {
			child, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			out[path] = field{openAPIType: stringValue(child, "type")}
			walk(path, child, out)
		}
	}

	if items, ok := schema["items"].(map[string]any); ok && prefix != "" {
		path := prefix + "[]"
		out[path] = field{openAPIType: stringValue(items, "type")}
		walk(path, items, out)
	}

	if additional, ok := schema["additionalProperties"].(map[string]any); ok && prefix != "" {
		path := prefix + "{}"
		out[path] = field{openAPIType: stringValue(additional, "type")}
		walk(path, additional, out)
	}
}

func stringValue(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// Report renders changes as a newline-terminated block, most significant
// first, suitable for a CI annotation.
func Report(changes []Change) string {
	var b strings.Builder
	for _, c := range changes {
		b.WriteString(c.String())
		b.WriteString("\n")
	}
	return b.String()
}
