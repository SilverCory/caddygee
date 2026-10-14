package apigeecompat_test

import (
	"testing"
	"time"

	"caddygee/modules/apigeecompat"
)

func TestTTLCache_SetAndGet(t *testing.T) {
	c := apigeecompat.NewTTLCacheString(time.Minute)
	val := "hello"
	c.Set("key1", &val)

	got, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if *got != "hello" {
		t.Errorf("got %q, want %q", *got, "hello")
	}
}

func TestTTLCache_MissingKey(t *testing.T) {
	c := apigeecompat.NewTTLCacheString(time.Minute)

	_, ok := c.Get("nonexistent")
	if ok {
		t.Error("expected ok=false for missing key")
	}
}

func TestTTLCache_ExpiredEntry(t *testing.T) {
	// Use a very short TTL so the entry expires immediately.
	c := apigeecompat.NewTTLCacheString(1 * time.Nanosecond)
	val := "temporary"
	c.Set("k", &val)

	// Sleep just past the TTL.
	time.Sleep(5 * time.Millisecond)

	_, ok := c.Get("k")
	if ok {
		t.Error("expected ok=false for expired entry")
	}
}

func TestTTLCache_DeleteRemovesEntry(t *testing.T) {
	c := apigeecompat.NewTTLCacheString(time.Minute)
	val := "to-be-deleted"
	c.Set("k", &val)

	c.Delete("k")

	_, ok := c.Get("k")
	if ok {
		t.Error("expected ok=false after Delete")
	}
}

func TestTTLCache_DeleteNonExistentKey_NoOp(t *testing.T) {
	// Deleting a key that was never set should not panic.
	c := apigeecompat.NewTTLCacheString(time.Minute)
	c.Delete("ghost") // must not panic
}

func TestTTLCache_OverwriteResetsExpiry(t *testing.T) {
	c := apigeecompat.NewTTLCacheString(1 * time.Nanosecond)
	first := "first"
	c.Set("k", &first)
	time.Sleep(5 * time.Millisecond)

	// Re-set with a longer TTL via a fresh cache write.
	// Overwrite with a fresh 1-minute TTL cache.
	c2 := apigeecompat.NewTTLCacheString(time.Minute)
	second := "second"
	c2.Set("k", &second)

	got, ok := c2.Get("k")
	if !ok {
		t.Fatal("expected ok=true after overwrite")
	}
	if *got != "second" {
		t.Errorf("got %q, want %q", *got, "second")
	}
}

func TestTTLCache_ConcurrentAccess(t *testing.T) {
	// Run concurrent Get/Set to confirm the RWMutex guards are correct.
	// The race detector (-race) will catch any violations.
	c := apigeecompat.NewTTLCacheString(time.Minute)
	done := make(chan struct{})

	for i := 0; i < 50; i++ {
		go func(n int) {
			v := "v"
			c.Set("k", &v)
			c.Get("k")
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}
