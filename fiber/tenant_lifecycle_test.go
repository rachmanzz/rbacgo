package fiberadapter

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/rachmanzz/rbacgo"
)

type lifecycleInvalidator struct{ messages chan rbacgo.InvalidationEvent }

func (i *lifecycleInvalidator) Publish(context.Context, rbacgo.InvalidationEvent) error { return nil }
func (i *lifecycleInvalidator) Messages() <-chan rbacgo.InvalidationEvent               { return i.messages }
func (i *lifecycleInvalidator) Close() error                                            { return nil }

func assertLifecycleSubscriberStopped(t *testing.T, i *lifecycleInvalidator) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		quiet := time.NewTimer(20 * time.Millisecond)
		select {
		case i.messages <- rbacgo.InvalidationEvent{Kind: rbacgo.InvalidateFlush}:
			quiet.Stop() // Close may race with one final event; retry until stopped.
		case <-quiet.C:
			return
		case <-deadline.C:
			quiet.Stop()
			t.Fatal("removed Enforcer still consumes invalidation events")
		}
	}
}

func TestTenantRegistryResourceCleanup(t *testing.T) {
	invalidators := make(map[*rbacgo.Enforcer]*lifecycleInvalidator)
	reg := NewTenantRegistry(func(tenant string) (*rbacgo.Enforcer, error) {
		inv := &lifecycleInvalidator{messages: make(chan rbacgo.InvalidationEvent)}
		e, err := rbacgo.New(rbacgo.WithTenant(tenant), rbacgo.WithMemoryStore(), rbacgo.WithCacheInvalidator(inv))
		if err == nil {
			invalidators[e] = inv
		}
		return e, err
	})
	defer reg.ClearAndClose()
	a, err := reg.Get("a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.Get("b")
	if err != nil {
		t.Fatal(err)
	}
	if reg.Evict("missing") {
		t.Fatal("evicted absent tenant")
	}
	if !reg.Evict("a") {
		t.Fatal("failed to evict cached tenant")
	}
	assertLifecycleSubscriberStopped(t, invalidators[a])
	again, err := reg.Get("b")
	if err != nil || again != b {
		t.Fatal("eviction affected another tenant")
	}
	fresh, err := reg.Get("a")
	if err != nil || fresh == a {
		t.Fatal("tenant was not reprovisioned")
	}
	reg.ClearAndClose()
	assertLifecycleSubscriberStopped(t, invalidators[b])
	assertLifecycleSubscriberStopped(t, invalidators[fresh])
	reg.ClearAndClose() // Empty cleanup remains safe.
	after, err := reg.Get("a")
	if err != nil || after == fresh {
		t.Fatal("registry must remain reusable")
	}
}

func TestTenantRegistryEvictsFactoryFailure(t *testing.T) {
	calls := 0
	reg := NewTenantRegistry(func(tenant string) (*rbacgo.Enforcer, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("temporary provisioning failure")
		}
		return rbacgo.New(rbacgo.WithTenant(tenant), rbacgo.WithMemoryStore())
	})
	defer reg.ClearAndClose()
	for range 2 {
		if _, err := reg.Get("a"); err == nil {
			t.Fatal("factory failure should be cached")
		}
	}
	if calls != 1 {
		t.Fatal("failed factory ran repeatedly")
	}
	if !reg.Evict("a") {
		t.Fatal("failed entry not evicted")
	}
	if _, err := reg.Get("a"); err != nil || calls != 2 {
		t.Fatalf("retry failed: calls=%d, err=%v", calls, err)
	}
}

func TestTenantRegistryCleanupDuringProvisioning(t *testing.T) {
	for _, all := range []bool{false, true} {
		name := "Evict"
		if all {
			name = "ClearAndClose"
		}
		t.Run(name, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			inv := &lifecycleInvalidator{messages: make(chan rbacgo.InvalidationEvent)}
			reg := NewTenantRegistry(func(tenant string) (*rbacgo.Enforcer, error) {
				if tenant == "slow" {
					close(started)
					<-release
					return rbacgo.New(rbacgo.WithTenant(tenant), rbacgo.WithMemoryStore(), rbacgo.WithCacheInvalidator(inv))
				}
				return rbacgo.New(rbacgo.WithTenant(tenant), rbacgo.WithMemoryStore())
			})
			got := make(chan error, 1)
			go func() { _, err := reg.Get("slow"); got <- err }()
			<-started
			done := make(chan struct{})
			go func() {
				if all {
					reg.ClearAndClose()
				} else {
					reg.Evict("slow")
				}
				close(done)
			}()
			// Wait until cleanup has detached the entry, while its factory is blocked.
			deadline := time.Now().Add(time.Second)
			for {
				present := reg.Len() != 0
				if !present {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("cleanup did not detach pending entry")
				}
				runtime.Gosched()
			}
			select {
			case <-done:
				t.Fatal("cleanup returned before factory finished")
			default:
			}
			// Cleanup must not hold the global registry lock while waiting.
			fast := make(chan error, 1)
			go func() { _, err := reg.Get("fast"); fast <- err }()
			select {
			case err := <-fast:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cleanup blocked another tenant")
			}
			unblock()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cleanup did not finish")
			}
			if err := <-got; err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			assertLifecycleSubscriberStopped(t, inv)
			reg.ClearAndClose()
		})
	}
}
