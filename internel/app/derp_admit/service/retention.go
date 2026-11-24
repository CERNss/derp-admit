package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"derp-admit/internel/app/derp_admit/metrics"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	defaultPruneFirstDelay = 30 * time.Second
	defaultPruneInterval   = time.Hour
	defaultPruneBatchSize  = 1000
	// maxRetentionDays keeps the cutoff arithmetic far from overflow; a cutoff
	// this far in the past deletes nothing anyway.
	maxRetentionDays = 100000
)

// pruneTable describes one audit table the pruner manages.
type pruneTable struct {
	name  string // SQL table name
	label string // metrics/log label
	days  int
}

// AuditPruner deletes audit rows older than a retention period. Every replica
// runs its own pruner; concurrent pruners are harmless (see pruneTableOnce).
// It never touches policy state, the verify cache, or the admin audit trail
// of its own actions.
type AuditPruner struct {
	db        *gorm.DB
	logger    *zap.Logger
	metrics   metrics.Recorder
	dbTimeout time.Duration
	tables    []pruneTable

	// Unexported, test-injectable timing and sizing.
	firstDelay time.Duration
	interval   time.Duration
	batchSize  int
	now        func() time.Time

	startOnce sync.Once
	done      chan struct{}
}

// PrunerOption adjusts an AuditPruner. There is no public setting behind it;
// it exists so tests can shorten the schedule.
type PrunerOption func(*AuditPruner)

// WithPruneSchedule overrides the delay before the first pass and the
// interval between passes. Non-positive values keep the defaults (30 s and
// one hour). Intended for tests.
func WithPruneSchedule(firstDelay, interval time.Duration) PrunerOption {
	return func(p *AuditPruner) {
		if firstDelay > 0 {
			p.firstDelay = firstDelay
		}
		if interval > 0 {
			p.interval = interval
		}
	}
}

// NewAuditPruner returns a pruner for audit_logs (verifyDays) and
// admin_audit_logs (adminDays). A retention of 0 disables pruning for that
// table. metrics may be nil.
func NewAuditPruner(db *gorm.DB, verifyDays, adminDays int, dbTimeout time.Duration, logger *zap.Logger, rec metrics.Recorder, opts ...PrunerOption) *AuditPruner {
	if logger == nil {
		logger = zap.NewNop()
	}
	if rec == nil {
		rec = metrics.Nop
	}
	if dbTimeout <= 0 {
		dbTimeout = 2 * time.Second
	}
	p := &AuditPruner{
		db:         db,
		logger:     logger,
		metrics:    rec,
		dbTimeout:  dbTimeout,
		firstDelay: defaultPruneFirstDelay,
		interval:   defaultPruneInterval,
		batchSize:  defaultPruneBatchSize,
		now:        time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	if verifyDays > 0 {
		p.tables = append(p.tables, pruneTable{name: "audit_logs", label: metrics.AuditTableVerify, days: verifyDays})
	}
	if adminDays > 0 {
		p.tables = append(p.tables, pruneTable{name: "admin_audit_logs", label: metrics.AuditTableAdmin, days: adminDays})
	}
	return p
}

// Enabled reports whether any table has a retention period.
func (p *AuditPruner) Enabled() bool {
	return p != nil && len(p.tables) > 0
}

// Start runs the pruner in the background until ctx is cancelled: a first
// pass after a short delay, then one pass per interval. It does nothing when
// no table has a retention period. Calling Start more than once has no effect.
func (p *AuditPruner) Start(ctx context.Context) {
	if !p.Enabled() {
		return
	}
	p.startOnce.Do(func() {
		p.done = make(chan struct{})
		go p.run(ctx)
	})
}

// Wait blocks until a started pruner has stopped. It returns at once if the
// pruner was never started.
func (p *AuditPruner) Wait() {
	if p == nil || p.done == nil {
		return
	}
	<-p.done
}

func (p *AuditPruner) run(ctx context.Context) {
	defer close(p.done)

	timer := time.NewTimer(p.firstDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	p.passLogged(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.passLogged(ctx)
		}
	}
}

// passLogged runs one pass; failures are logged by PruneOnce and retried at
// the next tick.
func (p *AuditPruner) passLogged(ctx context.Context) {
	_, _ = p.PruneOnce(ctx)
}

// PruneOnce runs one pruning pass over every table with a retention period
// and returns the number of rows deleted per metrics label. A table that
// fails is logged at error level; the other tables are still pruned and the
// first error is returned.
func (p *AuditPruner) PruneOnce(ctx context.Context) (map[string]int64, error) {
	deleted := make(map[string]int64, len(p.tables))
	var firstErr error
	for _, tbl := range p.tables {
		if ctx.Err() != nil {
			break
		}
		cutoff := retentionCutoff(p.now(), tbl.days)
		n, err := p.pruneTableOnce(ctx, tbl.name, cutoff)
		deleted[tbl.label] = n
		if n > 0 {
			p.metrics.AuditPruned(tbl.label, n)
			p.logger.Info("audit retention pruned rows",
				zap.String("table", tbl.label),
				zap.Int64("deleted", n),
				zap.Time("cutoff", cutoff),
			)
		}
		if err != nil {
			if ctx.Err() != nil {
				// Shutdown, not a failure.
				break
			}
			p.logger.Error("audit retention prune failed",
				zap.String("table", tbl.label),
				zap.Time("cutoff", cutoff),
				zap.Int64("deleted_before_failure", n),
				zap.Error(err),
			)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return deleted, firstErr
}

func retentionCutoff(now time.Time, days int) time.Time {
	if days > maxRetentionDays {
		days = maxRetentionDays
	}
	return now.UTC().AddDate(0, 0, -days)
}

// pruneStatement returns the batched delete for table with two placeholders
// (cutoff, batch size). The inner SELECT has no ORDER BY: any rows older than
// the cutoff may go first. With ORDER BY id, SQLite walked the primary key and
// the final, empty statement of every pass scanned all retained rows; without
// it SQLite searches the ts index (idx_audit_logs_ts,
// idx_admin_audit_logs_ts_id), which TestPruneStatementPlanUsesTSIndex pins.
// PostgreSQL 16 uses the same ts index when the cutoff is selective, including
// the final empty statement and its generic prepared plan; when most rows are
// older it may scan the table instead and stop once the batch is full.
//
// On PostgreSQL, id = ANY(ARRAY(...)) runs the subquery once and deletes
// through the primary key (IN (subquery) planned a hash join over the whole
// table), and FOR UPDATE SKIP LOCKED lets pruners on several replicas skip
// each other's rows instead of waiting on them.
func pruneStatement(dialect, table string) string {
	if dialect == "postgres" {
		return fmt.Sprintf(`DELETE FROM %s WHERE id = ANY(ARRAY(SELECT id FROM %s WHERE ts < ? LIMIT ? FOR UPDATE SKIP LOCKED))`, table, table)
	}
	return fmt.Sprintf(`DELETE FROM %s WHERE id IN (SELECT id FROM %s WHERE ts < ? LIMIT ?)`, table, table)
}

// pruneTableOnce deletes rows of table with ts < cutoff in batches of at most
// batchSize, one statement per batch with its own DB timeout, until a
// statement deletes nothing. It stops early when ctx is cancelled.
//
// On PostgreSQL the inner SELECT takes FOR UPDATE SKIP LOCKED, so pruners on
// several replicas never wait on each other's row locks (no deadlock) and
// simply split the old rows between them. SQLite serialises writers. The loop
// ends on zero rows rather than on a short batch, because a concurrent pruner
// can take part of a batch while older rows remain.
func (p *AuditPruner) pruneTableOnce(ctx context.Context, table string, cutoff time.Time) (int64, error) {
	stmt := pruneStatement(p.db.Dialector.Name(), table)
	cutoff = cutoff.UTC()

	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		stmtCtx, cancel := context.WithTimeout(ctx, p.dbTimeout)
		res := p.db.WithContext(stmtCtx).Exec(stmt, cutoff, p.batchSize)
		cancel()
		if res.Error != nil {
			return total, fmt.Errorf("prune %s: %w", table, res.Error)
		}
		total += res.RowsAffected
		if res.RowsAffected == 0 {
			return total, nil
		}
	}
}
