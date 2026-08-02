// Command http demonstrates the standard-library net/http adapter.
// It also serves Chi users, since Chi is built on net/http.
//
// Run: go run ./http
//
// Try:
//
//	curl -i -H "X-User-ID: alice" http://localhost:8080/articles          # 200
//	curl -i -H "X-User-ID: alice" -X POST http://localhost:8080/articles   # 200 (editor)
//	curl -i -H "X-User-ID: bob"   http://localhost:8080/articles           # 403
//	curl -i http://localhost:8080/articles                                  # 401
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/rachmanzz/rbacgo"
	httpadapter "github.com/rachmanzz/rbacgo/http"
)

func seed(enforcer *rbacgo.Enforcer) {
	ctx := context.Background()
	if err := enforcer.RegisterRole(ctx, rbacgo.Role{
		Name:        "viewer",
		Permissions: []rbacgo.Permission{{Resource: "/articles", Action: "GET"}},
	}); err != nil {
		log.Fatal(err)
	}
	if err := enforcer.RegisterRole(ctx, rbacgo.Role{
		Name:        "editor",
		Permissions: []rbacgo.Permission{{Resource: "/articles", Action: "POST"}},
		Parents:     []string{"viewer"},
	}); err != nil {
		log.Fatal(err)
	}
	if err := enforcer.AssignRole(ctx, "alice", "editor"); err != nil {
		log.Fatal(err)
	}
}

func main() {
	enforcer, err := rbacgo.New()
	if err != nil {
		log.Fatal(err)
	}
	seed(enforcer)

	guard := httpadapter.New(enforcer)

	mux := http.NewServeMux()
	mux.Handle("GET /articles", guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("list articles"))
	})))
	mux.Handle("POST /articles", guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("create article"))
	})))

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
