// Command echo demonstrates the Echo v5 adapter.
//
// Run: go run ./echo
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

	"github.com/labstack/echo/v5"
	"github.com/rachmanzz/rbacgo"
	echoadapter "github.com/rachmanzz/rbacgo/echo"
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
	enforcer, err := rbacgo.New(
		rbacgo.WithTenant("demo"),
	)
	if err != nil {
		log.Fatal(err)
	}
	seed(enforcer)

	e := echo.New()
	// In your real application the user ID comes from your auth layer
	// (session, JWT claims, auth middleware context), never from a raw header.
	// This example reads a demo header so you can try it with curl.
	e.Use(echoadapter.Middleware(enforcer, echoadapter.WithUserID(func(c *echo.Context) (string, bool) {
		id := c.Request().Header.Get("X-User-ID")
		return id, id != ""
	})))
	e.GET("/articles", func(c *echo.Context) error {
		return c.String(http.StatusOK, "list articles")
	})
	e.POST("/articles", func(c *echo.Context) error {
		return c.String(http.StatusOK, "create article")
	})

	log.Fatal(e.Start(":8080"))
}
