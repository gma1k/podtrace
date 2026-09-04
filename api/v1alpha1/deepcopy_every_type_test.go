package v1alpha1_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strings"
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func everyDeepCopyType() map[string]any {
	return map[string]any{
		"AgentAlertingSpec":               populated[podtracev1alpha1.AgentAlertingSpec](),
		"AgentMetricsLabelsSpec":          populated[podtracev1alpha1.AgentMetricsLabelsSpec](),
		"AgentMetricsSpec":                populated[podtracev1alpha1.AgentMetricsSpec](),
		"AgentSpec":                       populated[podtracev1alpha1.AgentSpec](),
		"ApplicationTrace":                populated[podtracev1alpha1.ApplicationTrace](),
		"ApplicationTraceList":            populated[podtracev1alpha1.ApplicationTraceList](),
		"ApplicationTraceSpec":            populated[podtracev1alpha1.ApplicationTraceSpec](),
		"ApplicationTraceStatus":          populated[podtracev1alpha1.ApplicationTraceStatus](),
		"AppSelector":                     populated[podtracev1alpha1.AppSelector](),
		"CaptureSpec":                     populated[podtracev1alpha1.CaptureSpec](),
		"DataDogExporter":                 populated[podtracev1alpha1.DataDogExporter](),
		"ExporterConfig":                  populated[podtracev1alpha1.ExporterConfig](),
		"ExporterConfigList":              populated[podtracev1alpha1.ExporterConfigList](),
		"ExporterConfigSpec":              populated[podtracev1alpha1.ExporterConfigSpec](),
		"ExporterConfigStatus":            populated[podtracev1alpha1.ExporterConfigStatus](),
		"JaegerExporter":                  populated[podtracev1alpha1.JaegerExporter](),
		"ObjectStoreReference":            populated[podtracev1alpha1.ObjectStoreReference](),
		"OTLPExporter":                    populated[podtracev1alpha1.OTLPExporter](),
		"OTLPHeader":                      populated[podtracev1alpha1.OTLPHeader](),
		"OTLPMetrics":                     populated[podtracev1alpha1.OTLPMetrics](),
		"PodRef":                          populated[podtracev1alpha1.PodRef](),
		"PodTrace":                        populated[podtracev1alpha1.PodTrace](),
		"PodTraceList":                    populated[podtracev1alpha1.PodTraceList](),
		"PodTraceNodeStatus":              populated[podtracev1alpha1.PodTraceNodeStatus](),
		"PodTraceSchedule":                populated[podtracev1alpha1.PodTraceSchedule](),
		"PodTraceScheduleList":            populated[podtracev1alpha1.PodTraceScheduleList](),
		"PodTraceScheduleSpec":            populated[podtracev1alpha1.PodTraceScheduleSpec](),
		"PodTraceScheduleStatus":          populated[podtracev1alpha1.PodTraceScheduleStatus](),
		"PodTraceSession":                 populated[podtracev1alpha1.PodTraceSession](),
		"PodTraceSessionList":             populated[podtracev1alpha1.PodTraceSessionList](),
		"PodTraceSessionSpec":             populated[podtracev1alpha1.PodTraceSessionSpec](),
		"PodTraceSessionStatus":           populated[podtracev1alpha1.PodTraceSessionStatus](),
		"PodTraceSessionTemplateMetadata": populated[podtracev1alpha1.PodTraceSessionTemplateMetadata](),
		"PodTraceSessionTemplateSpec":     populated[podtracev1alpha1.PodTraceSessionTemplateSpec](),
		"PodTraceSpec":                    populated[podtracev1alpha1.PodTraceSpec](),
		"PodTraceStatus":                  populated[podtracev1alpha1.PodTraceStatus](),
		"PolicyStatus":                    populated[podtracev1alpha1.PolicyStatus](),
		"RedactionRule":                   populated[podtracev1alpha1.RedactionRule](),
		"RedactionSpec":                   populated[podtracev1alpha1.RedactionSpec](),
		"ReportReference":                 populated[podtracev1alpha1.ReportReference](),
		"SecretKeySelector":               populated[podtracev1alpha1.SecretKeySelector](),
		"SessionJobRef":                   populated[podtracev1alpha1.SessionJobRef](),
		"SessionRuntimeSpec":              populated[podtracev1alpha1.SessionRuntimeSpec](),
		"SessionSummary":                  populated[podtracev1alpha1.SessionSummary](),
		"SplunkExporter":                  populated[podtracev1alpha1.SplunkExporter](),
		"Thresholds":                      populated[podtracev1alpha1.Thresholds](),
		"TracerConfig":                    populated[podtracev1alpha1.TracerConfig](),
		"TracerConfigList":                populated[podtracev1alpha1.TracerConfigList](),
		"TracerConfigSpec":                populated[podtracev1alpha1.TracerConfigSpec](),
		"TracerConfigStatus":              populated[podtracev1alpha1.TracerConfigStatus](),
		"TriggerFiring":                   populated[podtracev1alpha1.TriggerFiring](),
		"TriggerSource":                   populated[podtracev1alpha1.TriggerSource](),
		"TriggerSpec":                     populated[podtracev1alpha1.TriggerSpec](),
		"TriggerStatus":                   populated[podtracev1alpha1.TriggerStatus](),
		"ZipkinExporter":                  populated[podtracev1alpha1.ZipkinExporter](),
	}
}

func TestEveryTypeDeepCopiesWithoutAliasing(t *testing.T) {
	for name, obj := range everyDeepCopyType() {
		t.Run(name, func(t *testing.T) {
			method := reflect.ValueOf(obj).MethodByName("DeepCopy")
			if !method.IsValid() {
				t.Fatalf("%s has no DeepCopy method", name)
			}

			copied := method.Call(nil)[0].Interface()
			if !reflect.DeepEqual(obj, copied) {
				t.Fatalf("%s: DeepCopy did not reproduce a fully populated value", name)
			}

			reference := method.Call(nil)[0].Interface()
			if !mutateEveryReference(reflect.ValueOf(obj).Elem(), 0) {
				t.Skipf("%s has no mutable field, so aliasing cannot be observed", name)
			}

			if !reflect.DeepEqual(copied, reference) {
				t.Errorf("%s: mutating the original changed the copy. A deepcopy that assigns a "+
					"slice, map or pointer instead of allocating shares storage, and the "+
					"operator then edits a cached informer object in place", name)
			}
		})
	}
}

func TestEveryGeneratedDeepCopyTypeIsExercised(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "zz_generated.deepcopy.go", nil, 0)
	if err != nil {
		t.Fatalf("parse zz_generated.deepcopy.go: %v", err)
	}

	generated := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "DeepCopy" || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if ident, ok := star.X.(*ast.Ident); ok {
			generated[ident.Name] = true
		}
	}
	if len(generated) == 0 {
		t.Fatal("parsed no DeepCopy methods, so this guard would pass vacuously")
	}

	exercised := everyDeepCopyType()
	var missing []string
	for name := range generated {
		if _, ok := exercised[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these generated types are never deep-copied by a test: %s\n"+
			"Add them to everyDeepCopyType. A new API type whose deepcopy shares storage "+
			"would otherwise ship unnoticed.", strings.Join(missing, ", "))
	}
}

func TestEveryTypeDeepCopyIsNilSafe(t *testing.T) {
	for name, obj := range everyDeepCopyType() {
		t.Run(name, func(t *testing.T) {
			nilPtr := reflect.Zero(reflect.TypeOf(obj))
			method := nilPtr.MethodByName("DeepCopy")
			if !method.IsValid() {
				t.Fatalf("%s has no DeepCopy method", name)
			}

			result := method.Call(nil)[0]
			if !result.IsNil() {
				t.Errorf("%s: DeepCopy on a nil receiver returned %v, want a nil pointer. "+
					"Reconcilers call DeepCopy on optional sub-structs without a nil check, so "+
					"returning a non-nil zero value would silently invent configuration",
					name, result.Interface())
			}
		})
	}
}
