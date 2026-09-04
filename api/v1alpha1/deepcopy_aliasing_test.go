package v1alpha1_test

import (
	"reflect"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

var (
	timeType     = reflect.TypeOf(time.Time{})
	durationType = reflect.TypeOf(time.Duration(0))
	quantityType = reflect.TypeOf(resource.Quantity{})
	metaTimeType = reflect.TypeOf(metav1.Time{})
)

func fill(v reflect.Value, depth int) {
	if depth > 12 || !v.CanSet() {
		return
	}

	switch v.Type() {
	case quantityType:
		v.Set(reflect.ValueOf(resource.MustParse("250m")))
		return
	case metaTimeType:
		v.Set(reflect.ValueOf(metav1.NewTime(time.Unix(1700000000, 0).UTC())))
		return
	case timeType:
		v.Set(reflect.ValueOf(time.Unix(1700000000, 0).UTC()))
		return
	case durationType:
		v.SetInt(int64(90 * time.Second))
		return
	}

	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(v.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath != "" {
				continue
			}
			fill(v.Field(i), depth+1)
		}
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 2, 2)
		for i := 0; i < 2; i++ {
			fill(s.Index(i), depth+1)
		}
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		for _, k := range []string{"alpha", "beta"} {
			key := reflect.New(v.Type().Key()).Elem()
			if key.Kind() == reflect.String {
				key.SetString(k)
			} else {
				fill(key, depth+1)
			}
			val := reflect.New(v.Type().Elem()).Elem()
			fill(val, depth+1)
			m.SetMapIndex(key, val)
		}
		v.Set(m)
	case reflect.String:
		v.SetString("filled")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	}
}

func populated[T any]() *T {
	var obj T
	fill(reflect.ValueOf(&obj).Elem(), 0)
	return &obj
}

func rootObjects() map[string]runtime.Object {
	return map[string]runtime.Object{
		"PodTrace":             populated[podtracev1alpha1.PodTrace](),
		"PodTraceList":         populated[podtracev1alpha1.PodTraceList](),
		"PodTraceSession":      populated[podtracev1alpha1.PodTraceSession](),
		"PodTraceSessionList":  populated[podtracev1alpha1.PodTraceSessionList](),
		"PodTraceSchedule":     populated[podtracev1alpha1.PodTraceSchedule](),
		"PodTraceScheduleList": populated[podtracev1alpha1.PodTraceScheduleList](),
		"TracerConfig":         populated[podtracev1alpha1.TracerConfig](),
		"TracerConfigList":     populated[podtracev1alpha1.TracerConfigList](),
		"ExporterConfig":       populated[podtracev1alpha1.ExporterConfig](),
		"ExporterConfigList":   populated[podtracev1alpha1.ExporterConfigList](),
		"ApplicationTrace":     populated[podtracev1alpha1.ApplicationTrace](),
		"ApplicationTraceList": populated[podtracev1alpha1.ApplicationTraceList](),
	}
}

func TestDeepCopyOfAFullyPopulatedObjectIsEqual(t *testing.T) {
	for name, obj := range rootObjects() {
		t.Run(name, func(t *testing.T) {
			copied := obj.DeepCopyObject()
			if !reflect.DeepEqual(obj, copied) {
				t.Errorf("%s: DeepCopyObject did not reproduce a fully populated object. Every "+
					"optional field is set here, so a field the generated deepcopy forgot shows "+
					"up as an inequality that a sparsely populated fixture would miss", name)
			}
		})
	}
}

func mutateEveryReference(v reflect.Value, depth int) bool {
	if depth > 12 {
		return false
	}
	changed := false

	switch v.Type() {
	case quantityType, metaTimeType, timeType:
		return false
	}

	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			changed = mutateEveryReference(v.Elem(), depth+1) || changed
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath != "" {
				continue
			}
			changed = mutateEveryReference(v.Field(i), depth+1) || changed
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			changed = mutateEveryReference(v.Index(i), depth+1) || changed
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			val := reflect.New(v.Type().Elem()).Elem()
			val.Set(v.MapIndex(key))
			if mutateEveryReference(val, depth+1) {
				v.SetMapIndex(key, val)
				changed = true
			}
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString("mutated")
			changed = true
		}
	case reflect.Bool:
		if v.CanSet() {
			v.SetBool(false)
			changed = true
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.CanSet() {
			v.SetInt(99)
			changed = true
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v.CanSet() {
			v.SetUint(99)
			changed = true
		}
	}
	return changed
}

func TestDeepCopyDoesNotAliasTheOriginal(t *testing.T) {
	for name, obj := range rootObjects() {
		t.Run(name, func(t *testing.T) {
			copied := obj.DeepCopyObject()
			before := copied.DeepCopyObject()

			if !mutateEveryReference(reflect.ValueOf(obj).Elem(), 0) {
				t.Fatalf("%s: the mutator changed nothing, so this test would pass vacuously", name)
			}

			if !reflect.DeepEqual(copied, before) {
				t.Errorf("%s: mutating the original changed the copy. A generated deepcopy that "+
					"assigns a slice, map or pointer instead of allocating a new one shares "+
					"storage, and the operator then edits a cached informer object in place",
					name)
			}
			if reflect.DeepEqual(obj, copied) {
				t.Errorf("%s: the original still equals the copy after mutation, so the mutation "+
					"did not take effect and the aliasing check proved nothing", name)
			}
		})
	}
}

func TestDeepCopyIntoOverwritesAnExistingTarget(t *testing.T) {
	source := populated[podtracev1alpha1.PodTrace]()
	target := populated[podtracev1alpha1.PodTrace]()
	target.Spec.Filters = nil
	target.Labels = nil

	source.DeepCopyInto(target)

	if !reflect.DeepEqual(source, target) {
		t.Error("DeepCopyInto left the target unequal to the source. A target with fields the " +
			"source does not set must be fully overwritten, or a reused object keeps stale state")
	}
}
