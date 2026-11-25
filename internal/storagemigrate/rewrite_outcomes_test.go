package storagemigrate

import (
	"context"
	"errors"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

var widgetResource = schema.GroupResource{Group: "podtrace.io", Resource: "widgets"}

func failUpdates(dyn *dynamicfake.FakeDynamicClient, errs ...error) *int {
	calls := 0
	dyn.PrependReactor("update", "widgets", func(clienttesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls <= len(errs) {
			return true, nil, errs[calls-1]
		}
		return false, nil, nil
	})
	return &calls
}

func conflict() error {
	return apierrors.NewConflict(widgetResource, "a", errors.New("changed"))
}

func migrateOneWidget(t *testing.T, dyn *dynamicfake.FakeDynamicClient) (Result, *fakeCRDClient, error) {
	t.Helper()
	crds := &fakeCRDClient{crd: testCRD("v1beta1", []string{"v1alpha1", "v1beta1"}, []string{"v1alpha1", "v1beta1"})}
	res, err := Migrate(context.Background(), crds, dyn, "widgets.podtrace.io", false)
	return res, crds, err
}

func TestMigrateCountsAnObjectDeletedBeforeItsRewriteAsDeletedAndStillUnpins(t *testing.T) {
	dyn := fakeDynamic(widget("ns", "a", "v1beta1"))
	failUpdates(dyn, apierrors.NewNotFound(widgetResource, "a"))

	res, crds, err := migrateOneWidget(t, dyn)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.Deleted != 1 || res.Conflicts != 0 || res.Rewritten != 0 {
		t.Fatalf("result = %+v, want one deleted object and no conflicts", res)
	}
	if crds.updates != 1 || len(crds.crd.Status.StoredVersions) != 1 {
		t.Fatalf("storedVersions = %v after %d updates, want only the storage version", crds.crd.Status.StoredVersions, crds.updates)
	}
}

func TestMigrateRereadsAndRewritesAnObjectThatChangedUnderIt(t *testing.T) {
	dyn := fakeDynamic(widget("ns", "a", "v1beta1"))
	calls := failUpdates(dyn, conflict())

	res, crds, err := migrateOneWidget(t, dyn)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.Rewritten != 1 || res.Conflicts != 0 || *calls != 2 {
		t.Fatalf("result = %+v after %d updates, want one rewrite on the second attempt", res, *calls)
	}
	if crds.updates != 1 {
		t.Fatalf("storedVersions not unpinned after a retried rewrite")
	}
}

func TestMigrateGivesUpOnAnObjectThatKeepsChangingAndRefusesToUnpin(t *testing.T) {
	dyn := fakeDynamic(widget("ns", "a", "v1beta1"))
	calls := failUpdates(dyn, conflict(), conflict(), conflict(), conflict())

	res, crds, err := migrateOneWidget(t, dyn)
	if err == nil || !strings.Contains(err.Error(), "could not be rewritten") {
		t.Fatalf("Migrate error = %v, want a refusal to unpin", err)
	}
	if res.Conflicts != 1 || *calls != maxRewriteAttempts {
		t.Fatalf("result = %+v after %d updates, want one conflict after %d attempts", res, *calls, maxRewriteAttempts)
	}
	if crds.updates != 0 {
		t.Fatal("storedVersions must stay pinned while an object is unconverted")
	}
}

func TestMigrateCountsAnObjectDeletedBetweenConflictAndRereadAsDeleted(t *testing.T) {
	dyn := fakeDynamic(widget("ns", "a", "v1beta1"))
	failUpdates(dyn, conflict())
	dyn.PrependReactor("get", "widgets", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(widgetResource, "a")
	})

	res, _, err := migrateOneWidget(t, dyn)
	if err != nil || res.Deleted != 1 || res.Conflicts != 0 {
		t.Fatalf("result = %+v, %v; want one deleted object", res, err)
	}
}

func TestMigrateFailsWhenTheRereadAfterAConflictFails(t *testing.T) {
	dyn := fakeDynamic(widget("ns", "a", "v1beta1"))
	failUpdates(dyn, conflict())
	dyn.PrependReactor("get", "widgets", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewServiceUnavailable("etcd down")
	})

	_, crds, err := migrateOneWidget(t, dyn)
	if err == nil || !strings.Contains(err.Error(), "re-read ns/a") {
		t.Fatalf("Migrate error = %v, want the re-read failure", err)
	}
	if crds.updates != 0 {
		t.Fatal("storedVersions must stay pinned after a failed re-read")
	}
}

func TestMigrateFailsOnARewriteErrorThatIsNeitherConflictNorNotFound(t *testing.T) {
	dyn := fakeDynamic(widget("ns", "a", "v1beta1"))
	failUpdates(dyn, apierrors.NewForbidden(widgetResource, "a", errors.New("no")))

	_, _, err := migrateOneWidget(t, dyn)
	if err == nil || !strings.Contains(err.Error(), "rewrite ns/a") {
		t.Fatalf("Migrate error = %v, want the rewrite failure", err)
	}
}
