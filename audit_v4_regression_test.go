package rbacgo

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestPresenceRulesRejectInvalidFacts(t *testing.T) {
	cases := []struct {
		name    string
		attrs   Attributes
		present bool
		valid   bool
	}{
		{"missing", Attributes{}, false, true},
		{"null", Attributes{"approval": nil}, true, true},
		{"false", Attributes{"approval": false}, true, true},
		{"value", Attributes{"approval": "approved"}, true, true},
		{"nan", Attributes{"approval": math.NaN()}, true, false},
		{"positive_infinity", Attributes{"approval": math.Inf(1)}, true, false},
		{"negative_infinity", Attributes{"approval": math.Inf(-1)}, true, false},
		{"function", Attributes{"approval": func() {}}, true, false},
		{"nested_nan", Attributes{"approval": map[string]any{"amount": math.NaN()}}, true, false},
		{"nested_function", Attributes{"approval": []any{func() {}}}, true, false},
	}
	for backend, factory := range extensionStores() {
		t.Run(backend, func(t *testing.T) {
			e := extensionEnforcer(t, factory(t))
			ctx := context.Background()
			mustFeature(t, e.RegisterRoleAs(ctx, "admin", Role{Name: "worker"}))
			mustFeature(t, e.AssignRoleAs(ctx, "admin", "alice", "worker"))
			for _, effect := range []string{EffectAllow, EffectDeny} {
				t.Run(effect, func(t *testing.T) {
					role := Role{Name: "worker"}
					if effect == EffectDeny {
						role.Permissions = []Permission{{Resource: "document", Action: "read"}}
					}
					mustFeature(t, e.UpdateRole(ctx, "admin", role))
					for _, operator := range []string{"exists", "not_exists"} {
						t.Run(operator, func(t *testing.T) {
							mustFeature(t, e.SetRoleRules(ctx, "admin", "worker", []PolicyRule{{Effect: effect, Resource: "document", Action: "read", Conditions: []Condition{{Attribute: "approval", Operator: operator}}}}))
							for _, test := range cases {
								t.Run(test.name, func(t *testing.T) {
									matches := test.present
									if operator == "not_exists" {
										matches = !matches
									}
									expected := test.valid && matches
									if effect == EffectDeny {
										expected = test.valid && !matches
									}
									allowed, err := e.EnforceAttributesCtx(ctx, "alice", "document", "read", test.attrs)
									mustFeature(t, err)
									if allowed != expected {
										t.Fatalf("allowed=%t, want %t", allowed, expected)
									}
								})
							}
						})
					}
				})
			}
		})
	}
}

func TestAuditInitializationSyncOrderAndFailures(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, failure := range []string{"none", "file", "parent"} {
			name := failure
			if existing {
				name += "_existing"
			} else {
				name += "_new"
			}
			t.Run(name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "audit.jsonl")
				var original []byte
				if existing {
					original = []byte("{\"Operation\":\"original\"}\n")
					mustFeature(t, os.WriteFile(path, original, 0600))
				}
				injected := errors.New("injected synchronization failure")
				var calls []string
				var opened *os.File
				sink, err := newFileAuditSink(path, func(file *os.File) error {
					opened = file
					calls = append(calls, "file")
					if failure == "file" {
						return injected
					}
					return file.Sync()
				}, func(got string) error {
					calls = append(calls, "parent")
					if got != path {
						t.Fatalf("parent sync path=%q, want %q", got, path)
					}
					if failure == "parent" {
						return injected
					}
					return syncAuditParents(got)
				})
				expectedCalls := []string{"file", "parent"}
				if failure == "file" {
					expectedCalls = []string{"file"}
				}
				if !reflect.DeepEqual(calls, expectedCalls) {
					t.Fatalf("sync order=%v, want %v", calls, expectedCalls)
				}
				if failure != "none" {
					if sink != nil || !errors.Is(err, injected) {
						t.Fatalf("failed initialization returned %v, %v", sink, err)
					}
					if _, err := opened.Write([]byte("must not write")); !errors.Is(err, os.ErrClosed) {
						t.Fatalf("failed constructor leaked file: %v", err)
					}
					raw, readErr := os.ReadFile(path)
					mustFeature(t, readErr)
					if !bytes.Equal(raw, original) {
						t.Fatal("failed synchronization modified audit evidence")
					}
					// A previous creation failure leaves a file behind. Reopening must still
					// perform the full initialization and allow a safe retry.
					sink, err = NewFileAuditSink(path)
				}
				mustFeature(t, err)
				defer sink.Close()
				mustFeature(t, sink.Emit(context.Background(), AuditEvent{Operation: "after_init"}))
				raw, err := os.ReadFile(path)
				mustFeature(t, err)
				if !bytes.HasPrefix(raw, original) || !bytes.Contains(raw, []byte("after_init")) {
					t.Fatalf("audit content not preserved: %s", raw)
				}
			})
		}
	}
}

func TestAuditInitializationRejectsIncompleteTailBeforeSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	original := []byte("incomplete evidence")
	mustFeature(t, os.WriteFile(path, original, 0600))
	unexpected := func(*os.File) error { t.Error("incomplete file was synchronized"); return nil }
	sink, err := newFileAuditSink(path, unexpected, func(string) error { t.Error("incomplete parent was synchronized"); return nil })
	if err == nil || sink != nil {
		t.Fatalf("incomplete tail accepted: %v, %v", sink, err)
	}
	raw, err := os.ReadFile(path)
	mustFeature(t, err)
	if !bytes.Equal(raw, original) {
		t.Fatal("incomplete evidence changed")
	}
}

func TestAuditInitializationThroughDanglingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires Windows-specific privileges")
	}
	base := t.TempDir()
	targetDir := filepath.Join(base, "target")
	linkDir := filepath.Join(base, "link")
	mustFeature(t, os.Mkdir(targetDir, 0700))
	mustFeature(t, os.Mkdir(linkDir, 0700))
	target := filepath.Join(targetDir, "audit.jsonl")
	link := filepath.Join(linkDir, "audit.jsonl")
	mustFeature(t, os.Symlink(target, link))
	sink, err := NewFileAuditSink(link)
	mustFeature(t, err)
	defer sink.Close()
	mustFeature(t, sink.Emit(context.Background(), AuditEvent{Operation: "symlink"}))
	raw, err := os.ReadFile(target)
	mustFeature(t, err)
	if !bytes.Contains(raw, []byte("symlink")) {
		t.Fatal("audit symlink target was not written")
	}
}
