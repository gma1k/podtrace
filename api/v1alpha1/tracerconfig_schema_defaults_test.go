package v1alpha1_test

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

type schemaNode struct {
	Type       string                `json:"type"`
	Default    any                   `json:"default"`
	Properties map[string]schemaNode `json:"properties"`
}

func tracerConfigSpecSchema(t *testing.T) schemaNode {
	t.Helper()
	path := filepath.Join("..", "..", "deploy", "charts", "podtrace", "templates", "crds", "podtrace.io_tracerconfigs.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var kept []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "{{") {
			kept = append(kept, line)
		}
	}
	var crd struct {
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema schemaNode `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal([]byte(strings.Join(kept, "\n")), &crd); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(crd.Spec.Versions) == 0 {
		t.Fatalf("%s has no versions", path)
	}
	return crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"]
}

func booleanDefaults(node schemaNode, prefix string, out map[string]bool) {
	for name, child := range node.Properties {
		path := strings.TrimPrefix(prefix+"."+name, ".")
		if child.Type == "boolean" && child.Default != nil {
			out[path] = child.Default == true
		}
		booleanDefaults(child, path, out)
	}
}

func lookup(node schemaNode, path string) (schemaNode, bool) {
	for _, part := range strings.Split(path, ".") {
		child, ok := node.Properties[part]
		if !ok {
			return schemaNode{}, false
		}
		node = child
	}
	return node, true
}

func goFieldType(t *testing.T, path string) reflect.Type {
	t.Helper()
	typ := reflect.TypeOf(podtracev1alpha1.TracerConfigSpec{})
	for _, part := range strings.Split(path, ".") {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		var found bool
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if strings.Split(f.Tag.Get("json"), ",")[0] == part {
				typ, found = f.Type, true
				break
			}
		}
		if !found {
			t.Fatalf("spec.%s is in the schema but has no Go field", path)
		}
	}
	return typ
}

func TestEverySchemaToggleDefaultMatchesTheGoDefault(t *testing.T) {
	schema := booleanDefaultsOf(t)
	known := map[string]toggle{}
	for _, tg := range toggles() {
		known[tg.path] = tg
	}

	var paths []string
	for path := range schema {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		tg, ok := known[path]
		if !ok {
			t.Errorf("spec.%s has a schema default but no accessor in toggles(); add one, or "+
				"the operator reads the raw field and an object stored before the default "+
				"existed runs with the zero value", path)
			continue
		}
		if got := tg.read(&podtracev1alpha1.TracerConfigSpec{}); got != schema[path] {
			t.Errorf("spec.%s defaults to %v in the schema but reads %v when unset in Go; "+
				"the API server and the operator would disagree about what an unset field "+
				"means", path, schema[path], got)
		}
	}
	for path := range known {
		if _, ok := schema[path]; !ok {
			t.Errorf("spec.%s has a Go default but no +kubebuilder:default marker; "+
				"kubectl get would show it unset while it is on", path)
		}
	}
}

func TestEveryDefaultedToggleIsAPointer(t *testing.T) {
	for path, value := range booleanDefaultsOf(t) {
		if !value {
			continue
		}
		if typ := goFieldType(t, path); typ.Kind() != reflect.Pointer {
			t.Errorf("spec.%s defaults to true but is a %s in Go; with omitempty an explicit "+
				"false is dropped on the wire and the API server defaults it back to true", path, typ)
		}
	}
}

func TestEveryBlockAboveADefaultedToggleDefaultsToEmpty(t *testing.T) {
	spec := tracerConfigSpecSchema(t)
	for path := range booleanDefaultsOf(t) {
		parts := strings.Split(path, ".")
		for i := 1; i < len(parts); i++ {
			block := strings.Join(parts[:i], ".")
			node, ok := lookup(spec, block)
			if !ok {
				t.Fatalf("spec.%s missing from the schema", block)
			}
			if def, isObject := node.Default.(map[string]any); !isObject || len(def) != 0 {
				t.Errorf("spec.%s has no default of {}, so spec.%s is only defaulted when the "+
					"user writes the block; leaving the block out would leave the toggle "+
					"unset in the stored object", block, path)
			}
		}
	}
}

func booleanDefaultsOf(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	booleanDefaults(tracerConfigSpecSchema(t), "", out)
	for path := range out {
		if !strings.HasPrefix(path, "agent.") {
			delete(out, path)
		}
	}
	if len(out) == 0 {
		t.Fatal("found no boolean defaults under spec.agent; the schema walk is broken")
	}
	return out
}
