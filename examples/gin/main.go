// Command gin demonstrates the Gin v1 adapter.
//
// Run: go run ./gin
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

	"github.com/gin-gonic/gin"
	"github.com/rachmanzz/rbacgo"
	ginadapter "github.com/rachmanzz/rbacgo/gin"
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

	r := gin.Default()
	// In your real application the user ID comes from your auth layer
	// (session, JWT claims, auth middleware context), never from a raw header.
	// This example reads a demo header so you can try it with curl.
	r.Use(ginadapter.Middleware(enforcer, ginadapter.WithUserID(func(c *gin.Context) (string, bool) {
		id := c.GetHeader("X-User-ID")
		return id, id != ""
	})))
	r.GET("/articles", func(c *gin.Context) {
		c.String(http.StatusOK, "list articles")
	})
	r.POST("/articles", func(c *gin.Context) {
		c.String(http.StatusOK, "create article")
	})

	log.Fatal(r.Run(":8080"))
}
