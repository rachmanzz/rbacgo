package rbacgo

import (
	"context"
	"fmt"
	"log/slog"
)

// WithLogger enables warning logs for permission lookup failures, failed
// invalidation publishes, and shared policy-version fallbacks. No logging is
// enabled by default. The handler must support concurrent use and should not
// block; calls are synchronous. This is operational logging, not a durable
// audit trail. The logger and handler remain owned by the caller.
func WithLogger(logger *slog.Logger) Option {
	return func(e *Enforcer) error {
		if logger == nil {
			return fmt.Errorf("rbacgo: nil logger")
		}
		e.logger = logger
		return nil
	}
}

func (e *Enforcer) logError(ctx context.Context, message string, err error) {
	if e.logger != nil {
		e.logger.WarnContext(ctx, message, "tenant", e.tenant, "error", err)
	}
}
