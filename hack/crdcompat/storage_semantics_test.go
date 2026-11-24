package main

import (
	"strings"
	"testing"
)

func specWith(field string) string {
	return `          spec:
            type: object
            properties:
              ` + field + `
`
}

func TestStorageAndMergeSemanticChangesAreBreaking(t *testing.T) {
	cases := []struct {
		name          string
		before, after string
		want          string
	}{
		{"nullable removed", `ref: {type: string, nullable: true}`, `ref: {type: string}`, "nullable removed spec.ref"},
		{"unknown fields pruned", `extra: {type: object, x-kubernetes-preserve-unknown-fields: true}`, `extra: {type: object}`, "unknown fields no longer preserved spec.extra"},
		{"format added", `at: {type: string}`, `at: {type: string, format: date-time}`, "format changed spec.at"},
		{"format changed", `at: {type: string, format: date}`, `at: {type: string, format: date-time}`, "format changed spec.at"},
		{"atomic list becomes a set", `tags: {type: array, items: {type: string}}`, `tags: {type: array, x-kubernetes-list-type: set, items: {type: string}}`, "list type changed spec.tags"},
		{"set list becomes atomic", `tags: {type: array, x-kubernetes-list-type: set, items: {type: string}}`, `tags: {type: array, items: {type: string}}`, "list type changed spec.tags"},
		{"list map keys changed", `ports: {type: array, x-kubernetes-list-type: map, x-kubernetes-list-map-keys: [name], items: {type: object}}`, `ports: {type: array, x-kubernetes-list-type: map, x-kubernetes-list-map-keys: [port], items: {type: object}}`, "list type changed spec.ports"},
		{"map type changed", `labels: {type: object, additionalProperties: {type: string}}`, `labels: {type: object, x-kubernetes-map-type: atomic, additionalProperties: {type: string}}`, "map type changed spec.labels"},
		{"oneOf added", `mode: {type: object}`, `mode: {type: object, oneOf: [{required: [a]}, {required: [b]}]}`, "schema composition changed spec.mode"},
		{"anyOf changed", `mode: {type: object, anyOf: [{required: [a]}]}`, `mode: {type: object, anyOf: [{required: [b]}]}`, "schema composition changed spec.mode"},
		{"not added", `mode: {type: string}`, `mode: {type: string, not: {enum: [legacy]}}`, "schema composition changed spec.mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changes := compareSpec(t, specWith(tc.before), specWith(tc.after))
			requireChanges(t, changes, tc.want)
		})
	}
}

func TestLooseningStorageSemanticsIsNotBreaking(t *testing.T) {
	cases := []struct {
		name          string
		before, after string
	}{
		{"nullable added", `ref: {type: string}`, `ref: {type: string, nullable: true}`},
		{"unknown fields preserved", `extra: {type: object}`, `extra: {type: object, x-kubernetes-preserve-unknown-fields: true}`},
		{"format removed", `at: {type: string, format: date-time}`, `at: {type: string}`},
		{"explicit atomic list", `tags: {type: array, items: {type: string}}`, `tags: {type: array, x-kubernetes-list-type: atomic, items: {type: string}}`},
		{"explicit granular map", `labels: {type: object, additionalProperties: {type: string}}`, `labels: {type: object, x-kubernetes-map-type: granular, additionalProperties: {type: string}}`},
		{"allOf removed", `mode: {type: object, allOf: [{required: [a]}]}`, `mode: {type: object}`},
		{"unchanged oneOf", `mode: {type: object, oneOf: [{required: [a]}]}`, `mode: {type: object, oneOf: [{required: [a]}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireChanges(t, compareSpec(t, specWith(tc.before), specWith(tc.after)))
		})
	}
}

func TestIdentityModeComparesEverySchemaAspectNotOnlyTheType(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want string
	}{
		{"pattern", `name: {type: string, pattern: "^a$"}`, `name: {type: string}`, "pattern"},
		{"enum", `mode: {type: string, enum: [a, b]}`, `mode: {type: string, enum: [a]}`, "enum"},
		{"bounds", `n: {type: integer, maximum: 10}`, `n: {type: integer, maximum: 20}`, "bounds"},
		{"nullable", `ref: {type: string, nullable: true}`, `ref: {type: string}`, "nullable"},
		{"rules", `ref: {type: string, x-kubernetes-validations: [{rule: "size(self) > 1"}]}`, `ref: {type: string}`, "validation rules"},
		{"list type", `tags: {type: array, x-kubernetes-list-type: set, items: {type: string}}`, `tags: {type: array, items: {type: string}}`, "list type"},
		{"composition", `mode: {type: object, oneOf: [{required: [a]}]}`, `mode: {type: object}`, "composition"},
		{"int-or-string", `port: {x-kubernetes-int-or-string: true}`, `port: {}`, "int-or-string"},
		{"exclusive bounds", `n: {type: number, minimum: 0, exclusiveMinimum: true, maximum: 1, exclusiveMaximum: true}`, `n: {type: number, minimum: 0, maximum: 1}`, "exclusiveMinimum, exclusiveMaximum"},
		{"format", `at: {type: string, format: date-time}`, `at: {type: string}`, "format"},
		{"preserve unknown", `extra: {type: object, x-kubernetes-preserve-unknown-fields: true}`, `extra: {type: object}`, "preserve-unknown-fields"},
		{"map type", `labels: {type: object, x-kubernetes-map-type: atomic}`, `labels: {type: object}`, "map type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found, err := CheckIdentity(crdYAML(oneVersion("v1alpha1", true, specWith(tc.a)) + oneVersion("v1beta1", true, specWith(tc.b))))
			if err != nil {
				t.Fatal(err)
			}
			if len(found) != 1 || !strings.HasSuffix(found[0].Detail, "different "+tc.want) {
				t.Fatalf("divergences = %v, want one on %s", found, tc.want)
			}
		})
	}
}

func TestIdentityModeTreatsEnumAndRequiredOrderAsIrrelevant(t *testing.T) {
	a := `          spec:
            type: object
            required: [a, b]
            properties:
              a: {type: string, enum: [x, y]}
              b: {type: string, default: z}
`
	b := `          spec:
            type: object
            required: [b, a]
            properties:
              a: {type: string, enum: [y, x]}
              b: {type: string, default: z}
`
	found, err := CheckIdentity(crdYAML(oneVersion("v1alpha1", true, a) + oneVersion("v1beta1", true, b)))
	if err != nil {
		t.Fatal(err)
	}
	requireDivergences(t, found)
}
