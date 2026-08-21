package smtp

import (
	"context"
	"net"
	"testing"
	"time"

	"migadu/mizu/pkg/logging"
)

// newBudgetTestSession builds a session carrying only what the budget helpers
// touch, with its deadline placed relative to now.
func newBudgetTestSession(remaining time.Duration) *Session {
	s := &Session{Logger: logging.NewTestLogger()}
	s.sessionDeadline.Store(time.Now().Add(remaining).UnixNano())
	return s
}

// TestExtendSessionDeadline_RestartsOnProgress covers what the budget is for: a
// sender working through a queue on one connection is measured on progress, not
// on how long it has been connected. Without the restart, message N of a long
// run is refused even though every message before it was delivered — and each
// refusal is a redelivery the sender's MTA has to make.
func TestExtendSessionDeadline_RestartsOnProgress(t *testing.T) {
	s := newBudgetTestSession(time.Second) // nearly spent

	s.extendSessionDeadline()

	if remaining := time.Until(s.sessionDeadlineTime()); remaining < SessionDeadline-time.Minute {
		t.Errorf("remaining budget %v; want a fresh ~%v", remaining, SessionDeadline)
	}
}

// TestExtendSessionDeadline_IgnoresUnbudgetedSession keeps bare test sessions
// (no deadline set) unbudgeted rather than granting them one.
func TestExtendSessionDeadline_IgnoresUnbudgetedSession(t *testing.T) {
	s := &Session{Logger: logging.NewTestLogger()}

	s.extendSessionDeadline()
	s.ensureSessionBudget(time.Hour)

	if !s.sessionDeadlineTime().IsZero() {
		t.Errorf("deadline = %v; want zero", s.sessionDeadlineTime())
	}
}

func TestEnsureSessionBudget(t *testing.T) {
	t.Run("extends a budget too small for the work", func(t *testing.T) {
		s := newBudgetTestSession(5 * time.Second)

		s.ensureSessionBudget(DataPhaseBudget)

		if remaining := time.Until(s.sessionDeadlineTime()); remaining < DataPhaseBudget-time.Minute {
			t.Errorf("remaining budget %v; want at least ~%v", remaining, DataPhaseBudget)
		}
	})

	t.Run("leaves a sufficient budget alone", func(t *testing.T) {
		s := newBudgetTestSession(SessionDeadline)
		before := s.sessionDeadlineTime()

		s.ensureSessionBudget(DataPhaseBudget)

		if got := s.sessionDeadlineTime(); !got.Equal(before) {
			t.Errorf("deadline moved from %v to %v; want unchanged", before, got)
		}
	})
}

// TestCommandContext_CarriesSessionBudget is the property that made DATA worth
// reserving a budget for: outbound work (validators, delivery) inherits the
// session deadline, so a transaction handed a nearly-spent budget would fail a
// healthy backend call.
func TestCommandContext_CarriesSessionBudget(t *testing.T) {
	s := newBudgetTestSession(2 * time.Second)

	ctx, cancel := s.commandContext(context.Background())
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("command context has no deadline; want the session deadline")
	}
	if !deadline.Equal(s.sessionDeadlineTime()) {
		t.Errorf("deadline = %v; want session deadline %v", deadline, s.sessionDeadlineTime())
	}

	// After reserving the data budget, the same derivation must yield room for
	// the body plus its synchronous delivery.
	s.ensureSessionBudget(DataPhaseBudget)
	ctx2, cancel2 := s.commandContext(context.Background())
	defer cancel2()
	deadline2, _ := ctx2.Deadline()
	if remaining := time.Until(deadline2); remaining < DataPhaseBudget-time.Minute {
		t.Errorf("command context leaves %v for the data phase; want ~%v", remaining, DataPhaseBudget)
	}
}

// TestSetCommandTimeout_RejectsExpiredSession keeps the budget enforceable:
// once it is spent, the next command must be refused.
func TestSetCommandTimeout_RejectsExpiredSession(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &Session{Logger: logging.NewTestLogger(), netConn: server}
	s.sessionDeadline.Store(time.Now().Add(-time.Second).UnixNano())

	if err := s.setCommandTimeout(IdleTimeout); err != ErrSessionTimeout {
		t.Errorf("err = %v; want %v", err, ErrSessionTimeout)
	}

	s.extendSessionDeadline()
	if err := s.setCommandTimeout(IdleTimeout); err != nil {
		t.Errorf("err = %v after restarting the budget; want nil", err)
	}
}
