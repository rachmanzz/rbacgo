module github.com/rachmanzz/rbacgo/echo

go 1.26.0

toolchain go1.27.2

require github.com/rachmanzz/rbacgo v0.2.0-4

require golang.org/x/sys v0.48.0 // indirect

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/labstack/echo/v5 v5.4.2
	github.com/mattn/go-sqlite3 v1.14.52 // indirect
	github.com/redis/go-redis/v9 v9.23.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
)

replace github.com/rachmanzz/rbacgo => ../
