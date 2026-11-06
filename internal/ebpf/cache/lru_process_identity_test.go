package cache

import (
	"testing"
	"time"
)

func TestGetProcessMatchesOnlyTheProcessInstanceThatStoredTheName(t *testing.T) {
	c := NewLRUCache(8, time.Hour)
	t.Cleanup(c.Close)
	c.SetProcess(4242, 100, "worker")

	if name, ok := c.GetProcess(4242, 100); !ok || name != "worker" {
		t.Fatalf("GetProcess(same process) = %q, %v", name, ok)
	}
	if _, ok := c.GetProcess(4242, 900); ok {
		t.Fatal("a later holder of the pid was served its predecessor's name")
	}
}

func TestGetProcessIgnoresNamesStoredWithoutAnIdentity(t *testing.T) {
	c := NewLRUCache(8, time.Hour)
	t.Cleanup(c.Close)
	c.Set(4242, "anonymous")

	if _, ok := c.GetProcess(4242, 0); ok {
		t.Fatal("a name stored without a process identity matched one")
	}
	if name, ok := c.Get(4242); !ok || name != "anonymous" {
		t.Fatalf("Get = %q, %v", name, ok)
	}
}

func TestGetRecentServesOnlyFreshEntries(t *testing.T) {
	c := NewLRUCache(8, time.Hour)
	t.Cleanup(c.Close)
	c.SetProcess(4242, 100, "short-lived")

	if name, ok := c.GetRecent(4242, time.Minute); !ok || name != "short-lived" {
		t.Fatalf("GetRecent = %q, %v", name, ok)
	}
	if _, ok := c.GetRecent(4242, 0); ok {
		t.Fatal("an entry older than the allowed age was served")
	}
}

func TestSetProcessReplacesTheIdentityOfAnExistingEntry(t *testing.T) {
	c := NewLRUCache(8, time.Hour)
	t.Cleanup(c.Close)
	c.SetProcess(4242, 100, "old")
	c.SetProcess(4242, 900, "new")

	if _, ok := c.GetProcess(4242, 100); ok {
		t.Fatal("the replaced process instance still matched")
	}
	if name, ok := c.GetProcess(4242, 900); !ok || name != "new" {
		t.Fatalf("GetProcess = %q, %v", name, ok)
	}
}
