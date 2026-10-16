package rbacgo

import "context"

// Shutdown is terminal: it rejects subsequent permission lookups, stops the
// invalidation subscriber, and closes Redis/SQL resources created by options.
// Caller-owned Store, SQL pools, Redis clients, invalidators, and audit sinks
// are not closed. Drain external users first. Cleanup continues after a deadline.
// Close retains its historical nonterminal behavior.
func (e *Enforcer) Shutdown(ctx context.Context) error {
	e.shutdownOnce.Do(func() {
		e.shutdown.Store(true)
		go func() {
			defer close(e.shutdownDone)
			_ = e.Close()
			for _, db := range e.ownedDBs {
				_ = db.Close()
			}
		}()
	})
	select {
	case <-e.shutdownDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
