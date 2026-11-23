package service

import (
	"context"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"tailscale.com/types/key"
)

// TestRegisterConcurrentSameUser pins two invariants under concurrency on the
// sqlite backend: the MaxDevices cap holds (exactly one registration wins),
// and the losers get a clean 403 rather than SQLITE_BUSY surfacing as a 500.
func TestRegisterConcurrentSameUser(t *testing.T) {
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "race.db")
	gormDB, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.ApplyMigrations(context.Background(), gormDB, dbURL); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	engine, err := policy.NewEngine(gormDB)
	if err != nil {
		t.Fatalf("new policy: %v", err)
	}

	svc := New(gormDB, engine, "test-pepper", 10*time.Second, NewVerifyCache(0), zap.NewNop())

	user := model.User{ID: uuid.New(), Username: "race-user"}
	if err := gormDB.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	token := model.EnrollToken{
		ID:         uuid.New(),
		UserID:     user.ID,
		TokenHash:  svc.hashToken("race-token"),
		MaxDevices: 1,
	}
	if err := gormDB.Create(&token).Error; err != nil {
		t.Fatalf("create token: %v", err)
	}

	const workers = 8
	statuses := make([]int, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i], errs[i] = svc.Register(context.Background(), RegisterInput{
				Token:   "race-token",
				NodeKey: key.NewNode().Public().String(),
			})
		}(i)
	}
	wg.Wait()

	okCount := 0
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Errorf("worker %d: unexpected error (status=%d): %v", i, statuses[i], errs[i])
			continue
		}
		switch statuses[i] {
		case http.StatusOK:
			okCount++
		case http.StatusForbidden:
			// lost the MaxDevices race cleanly
		default:
			t.Errorf("worker %d: status=%d want %d or %d", i, statuses[i], http.StatusOK, http.StatusForbidden)
		}
	}
	if okCount != 1 {
		t.Errorf("successful registrations=%d want=1", okCount)
	}

	var count int64
	if err := gormDB.Model(&model.Device{}).Count(&count).Error; err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if count != 1 {
		t.Errorf("device rows=%d want=1 (MaxDevices exceeded)", count)
	}
}
