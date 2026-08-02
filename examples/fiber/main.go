// Command fiber demonstrates the Fiber v3 adapter.
//
// Run: go run ./fiber
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

	"github.com/gofiber/fiber/v3"
	"github.com/rachmanzz/rbacgo"
	fiberadapter "github.com/rachmanzz/rbacgo/fiber"
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

	app := fiber.New()
	app.Use(fiberadapter.Middleware(enforcer))
	app.Get("/articles", func(c fiber.Ctx) error {
		return c.SendString("list articles")
	})
	app.Post("/articles", func(c fiber.Ctx) error {
		return c.SendString("create article")
	})

	log.Fatal(app.Listen(":8080"))
}
