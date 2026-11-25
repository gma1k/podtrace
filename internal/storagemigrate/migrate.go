// Package storagemigrate rewrites stored custom resources into a CRD's
// current storage version and then unpins the versions that no longer hold
// any data.
package storagemigrate

import (
	"context"
	"fmt"
	"sort"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

type Result struct {
	CRD            string
	StorageVersion string
	Objects        int
	Rewritten      int
	Deleted        int
	Conflicts      int
	StoredVersions []string
	Unpinned       []string
}

// CRDClient is the subset of the apiextensions client this package needs.
// Narrow so tests can supply a fake without a full clientset.
type CRDClient interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*apiextensionsv1.CustomResourceDefinition, error)
	UpdateStatus(ctx context.Context, crd *apiextensionsv1.CustomResourceDefinition, opts metav1.UpdateOptions) (*apiextensionsv1.CustomResourceDefinition, error)
}

// StorageVersionOf returns the version a CRD currently persists into.
func StorageVersionOf(crd *apiextensionsv1.CustomResourceDefinition) (string, error) {
	for _, v := range crd.Spec.Versions {
		if v.Storage {
			return v.Name, nil
		}
	}
	return "", fmt.Errorf("%s: no version is marked storage: true", crd.Name)
}

func StaleStoredVersions(stored []string, storageVersion string) []string {
	var stale []string
	for _, v := range stored {
		if v != storageVersion {
			stale = append(stale, v)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	sort.Strings(stale)
	return stale
}

// Migrate rewrites every object of one CRD into its storage version, then
// removes the now-empty versions from status.storedVersions.
func Migrate(ctx context.Context, crds CRDClient, dyn dynamic.Interface, crdName string, dryRun bool) (Result, error) {
	crd, err := crds.Get(ctx, crdName, metav1.GetOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("get CRD %s: %w", crdName, err)
	}

	storageVersion, err := StorageVersionOf(crd)
	if err != nil {
		return Result{}, err
	}

	res := Result{
		CRD:            crdName,
		StorageVersion: storageVersion,
		StoredVersions: append([]string(nil), crd.Status.StoredVersions...),
	}

	gvr := schema.GroupVersionResource{
		Group:    crd.Spec.Group,
		Version:  storageVersion,
		Resource: crd.Spec.Names.Plural,
	}

	objects, err := listAll(ctx, dyn, gvr, crd.Spec.Scope)
	if err != nil {
		return res, err
	}
	res.Objects = len(objects)

	if !dryRun {
		for i := range objects {
			outcome, err := rewrite(ctx, dyn, gvr, crd.Spec.Scope, &objects[i])
			if err != nil {
				return res, err
			}
			switch outcome {
			case rewritten:
				res.Rewritten++
			case deleted:
				res.Deleted++
			default:
				res.Conflicts++
			}
		}
	}

	stale := StaleStoredVersions(crd.Status.StoredVersions, storageVersion)
	if len(stale) == 0 {
		return res, nil
	}
	res.Unpinned = stale

	if dryRun {
		return res, nil
	}

	if res.Conflicts > 0 {
		return res, fmt.Errorf("%s: %d object(s) could not be rewritten; re-run before unpinning %v",
			crdName, res.Conflicts, stale)
	}

	fresh, err := crds.Get(ctx, crdName, metav1.GetOptions{})
	if err != nil {
		return res, fmt.Errorf("re-read CRD %s: %w", crdName, err)
	}
	fresh.Status.StoredVersions = []string{storageVersion}
	if _, err := crds.UpdateStatus(ctx, fresh, metav1.UpdateOptions{}); err != nil {
		return res, fmt.Errorf("update storedVersions on %s: %w", crdName, err)
	}
	return res, nil
}

func listAll(ctx context.Context, dyn dynamic.Interface, gvr schema.GroupVersionResource, scope apiextensionsv1.ResourceScope) ([]unstructured.Unstructured, error) {
	var out []unstructured.Unstructured
	cont := ""
	for {
		opts := metav1.ListOptions{Limit: 200, Continue: cont}
		var (
			list *unstructured.UnstructuredList
			err  error
		)
		if scope == apiextensionsv1.NamespaceScoped {
			list, err = dyn.Resource(gvr).Namespace(metav1.NamespaceAll).List(ctx, opts)
		} else {
			list, err = dyn.Resource(gvr).List(ctx, opts)
		}
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", gvr.Resource, err)
		}
		out = append(out, list.Items...)
		cont = list.GetContinue()
		if cont == "" {
			return out, nil
		}
	}
}

// rewriteOutcome is what became of one object's rewrite.
type rewriteOutcome int

const (
	rewritten rewriteOutcome = iota
	deleted
	conflicted
)

// maxRewriteAttempts bounds how often an object that keeps changing between
// read and write is re-read and written again.
const maxRewriteAttempts = 3

// rewrite writes obj back unchanged so the API server stores it in the
// current storage version.
func rewrite(ctx context.Context, dyn dynamic.Interface, gvr schema.GroupVersionResource, scope apiextensionsv1.ResourceScope, obj *unstructured.Unstructured) (rewriteOutcome, error) {
	client := resourceClient(dyn, gvr, scope, obj.GetNamespace())
	current := obj
	for attempt := 1; ; attempt++ {
		_, err := client.Update(ctx, current, metav1.UpdateOptions{})
		switch {
		case err == nil:
			return rewritten, nil
		case apierrors.IsNotFound(err):
			return deleted, nil
		case !apierrors.IsConflict(err):
			return conflicted, fmt.Errorf("rewrite %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
		case attempt >= maxRewriteAttempts:
			return conflicted, nil
		}
		current, err = client.Get(ctx, obj.GetName(), metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			return deleted, nil
		case err != nil:
			return conflicted, fmt.Errorf("re-read %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
		}
	}
}

func resourceClient(dyn dynamic.Interface, gvr schema.GroupVersionResource, scope apiextensionsv1.ResourceScope, namespace string) dynamic.ResourceInterface {
	if scope == apiextensionsv1.NamespaceScoped {
		return dyn.Resource(gvr).Namespace(namespace)
	}
	return dyn.Resource(gvr)
}
