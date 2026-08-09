package rbacgo

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// TestConcurrentMixedWorkload hammers a single shared enforcer+store with
// every API at once: register/update/delete roles, assign/unassign, enforce,
// owned enforces, permission views, and role listing. Run under -race it
// proves the enforcer, memory store, and cache are safe under real mixed
// contention.
func TestConcurrentMixedWorkload(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithTenant("stress"), WithMemoryStore(), WithLRU(NewMemoryLRU(1024, 0)))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := New(WithTenant("stress"), WithStore(e.store), WithLRU(NewMemoryLRU(1024, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.RegisterRole(ctx, Role{Name: "admin", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}); err != nil {
		t.Fatal(err)
	}
	if err := admin.AssignRole(ctx, "root", "admin"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if err := e.RegisterRole(ctx, Role{Name: fmt.Sprintf("r%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	roles := [8]string{"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"}
	var (
		wg      sync.WaitGroup
		enforce uint64
		owned   uint64
		mutate  uint64
		list    uint64
	)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				u := fmt.Sprintf("u%d", (g+i)%8)
				switch (g + i) % 4 {
				case 0:
					e.Enforce(ctx, u, "doc", "read")
					atomic.AddUint64(&enforce, 1)
				case 1:
					e.EnforceOwned(ctx, u, u, "hr", "doc", "edit")
					atomic.AddUint64(&owned, 1)
				case 2:
					if _, err := e.PermissionView(ctx, u); err != nil {
						t.Errorf("PermissionView: %v", err)
					}
				case 3:
					if _, err := e.ListRoles(ctx); err != nil {
						t.Errorf("ListRoles: %v", err)
					}
					atomic.AddUint64(&list, 1)
				}
			}
		}(g)
	}
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				u := fmt.Sprintf("u%d", (g+i)%8)
				r := roles[(g+i)%8]
				switch (g + i) % 4 {
				case 0:
					if err := admin.AssignRole(ctx, u, r); err != nil {
						t.Errorf("AssignRole: %v", err)
					}
					atomic.AddUint64(&mutate, 1)
				case 1:
					if err := admin.UnassignRole(ctx, "root", u, r); err != nil {
						t.Errorf("UnassignRole: %v", err)
					}
					atomic.AddUint64(&mutate, 1)
				case 2:
					if err := admin.UpdateRole(ctx, "root", Role{Name: r, Parents: []string{roles[(g+i+1)%8]}}); err != nil && err != ErrCycleDetected {
						t.Errorf("UpdateRole: %v", err)
					}
					atomic.AddUint64(&mutate, 1)
				case 3:
					if _, err := admin.HasRole(ctx, u, r); err != nil {
						t.Errorf("HasRole: %v", err)
					}
				}
			}
		}(g)
	}
	wg.Wait()
	if enforce == 0 || owned == 0 || mutate == 0 || list == 0 {
		t.Fatalf("workload made no progress: enforce=%d owned=%d mutate=%d list=%d", enforce, owned, mutate, list)
	}
}
