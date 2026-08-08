module github.com/rachmanzz/rbacgo/echo

go 1.25.7

toolchain go1.25.12

require github.com/rachmanzz/rbacgo v0.1.0-1

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/labstack/echo/v5 v5.3.1
	github.com/mattn/go-sqlite3 v1.14.49 // indirect
	github.com/redis/go-redis/v9 v9.21.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
)

replace github.com/rachmanzz/rbacgo => ../
