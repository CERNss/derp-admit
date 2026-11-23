package page_test

import (
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"derp-admit/internel/app/derp_admit/db"
	"derp-admit/internel/app/derp_admit/page"
)

func TestPageCursorRoundTripAndForeignList(t *testing.T) {
	ts := time.Date(2026, 11, 23, 14, 30, 15, 123456789, time.FixedZone("CST", 8*3600))
	cur := page.Cursor{
		L: "users",
		T: ts,
		K: "550e8400-e29b-41d4-a716-446655440000",
	}

	encoded := cur.Encode()
	req, err := page.Parse("users", "25", encoded)
	if err != nil {
		t.Fatalf("Parse valid cursor: %v", err)
	}
	if req.Limit != 25 {
		t.Fatalf("limit=%d want=25", req.Limit)
	}
	if req.After == nil {
		t.Fatalf("expected non-nil After cursor")
	}
	if req.After.L != "users" || req.After.K != cur.K || !req.After.T.Equal(ts.UTC()) {
		t.Fatalf("round-trip mismatch: got=%+v want=%+v", *req.After, cur)
	}
	if req.After.T.Location() != time.UTC {
		t.Fatalf("expected UTC time location, got %v", req.After.T.Location())
	}

	// A cursor minted for one list must be rejected on another list.
	if _, err := page.Parse("devices", "", encoded); !errors.Is(err, page.ErrInvalid) {
		t.Fatalf("foreign list err=%v want ErrInvalid", err)
	}

	// Default limit when omitted.
	defReq, err := page.Parse("users", "", "")
	if err != nil {
		t.Fatalf("Parse default: %v", err)
	}
	if defReq.Limit != page.DefaultLimit || defReq.After != nil {
		t.Fatalf("default req=%+v want limit=%d after=nil", defReq, page.DefaultLimit)
	}

	// Invalid limits and malformed cursors.
	for _, badLimit := range []string{"0", "-1", "201", "abc"} {
		if _, err := page.Parse("users", badLimit, ""); !errors.Is(err, page.ErrInvalid) {
			t.Fatalf("limit %q: err=%v want ErrInvalid", badLimit, err)
		}
	}
	for _, badCur := range []string{"not-base64!!!", "e30"} {
		if _, err := page.Parse("users", "", badCur); !errors.Is(err, page.ErrInvalid) {
			t.Fatalf("cursor %q: err=%v want ErrInvalid", badCur, err)
		}
	}

	// Cut trims Limit+1 rows and emits nextCursor; <= Limit returns nil nextCursor.
	type item struct {
		t time.Time
		k string
	}
	rows := []item{
		{t: ts, k: "a"},
		{t: ts.Add(time.Second), k: "b"},
		{t: ts.Add(2 * time.Second), k: "c"},
	}
	page1, next := page.Cut(rows, page.Request{List: "users", Limit: 2}, func(i item) (time.Time, string) {
		return i.t, i.k
	})
	if len(page1) != 2 || next == nil {
		t.Fatalf("page1 len=%d next=%v want len=2 non-nil next", len(page1), next)
	}
	parsedNext, err := page.Parse("users", "2", *next)
	if err != nil {
		t.Fatalf("parse nextCursor: %v", err)
	}
	if parsedNext.After.K != "b" {
		t.Fatalf("nextCursor key=%q want=b", parsedNext.After.K)
	}

	lastPage, lastNext := page.Cut(rows[:2], page.Request{List: "users", Limit: 2}, func(i item) (time.Time, string) {
		return i.t, i.k
	})
	if len(lastPage) != 2 || lastNext != nil {
		t.Fatalf("lastPage len=%d next=%v want len=2 nil next", len(lastPage), lastNext)
	}
}

func TestPageKeysetAscAndDescSQLite(t *testing.T) {
	dbURL := "sqlite://" + filepath.Join(t.TempDir(), "page.db")
	conn, err := db.OpenDatabase(dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	type row struct {
		ID        int64     `gorm:"primaryKey"`
		CreatedAt time.Time `gorm:"not null"`
	}
	if err := conn.AutoMigrate(&row{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	base := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	// Include tied timestamps to exercise the tie-breaker.
	seed := []row{
		{ID: 1, CreatedAt: base},
		{ID: 2, CreatedAt: base},
		{ID: 3, CreatedAt: base.Add(time.Second)},
		{ID: 4, CreatedAt: base.Add(time.Second)},
		{ID: 5, CreatedAt: base.Add(2 * time.Second)},
	}
	if err := conn.Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Ascending walk, 2 at a time.
	var ascIDs []int64
	cursor := ""
	for {
		req, err := page.Parse("rows", "2", cursor)
		if err != nil {
			t.Fatalf("parse asc: %v", err)
		}
		var batch []row
		if err := page.Asc(conn.Model(&row{}), req, "created_at", "id", page.KeyInt).Find(&batch).Error; err != nil {
			t.Fatalf("query asc: %v", err)
		}
		cut, next := page.Cut(batch, req, func(r row) (time.Time, string) {
			return r.CreatedAt, strconv.FormatInt(r.ID, 10)
		})
		for _, r := range cut {
			ascIDs = append(ascIDs, r.ID)
		}
		if next == nil {
			break
		}
		cursor = *next
	}
	wantAsc := []int64{1, 2, 3, 4, 5}
	if len(ascIDs) != len(wantAsc) {
		t.Fatalf("ascIDs=%v want=%v", ascIDs, wantAsc)
	}
	for i := range wantAsc {
		if ascIDs[i] != wantAsc[i] {
			t.Fatalf("ascIDs=%v want=%v", ascIDs, wantAsc)
		}
	}

	// Descending walk, 2 at a time.
	var descIDs []int64
	cursor = ""
	for {
		req, err := page.Parse("rows", "2", cursor)
		if err != nil {
			t.Fatalf("parse desc: %v", err)
		}
		var batch []row
		if err := page.Desc(conn.Model(&row{}), req, "created_at", "id", page.KeyInt).Find(&batch).Error; err != nil {
			t.Fatalf("query desc: %v", err)
		}
		cut, next := page.Cut(batch, req, func(r row) (time.Time, string) {
			return r.CreatedAt, strconv.FormatInt(r.ID, 10)
		})
		for _, r := range cut {
			descIDs = append(descIDs, r.ID)
		}
		if next == nil {
			break
		}
		cursor = *next
	}
	wantDesc := []int64{5, 4, 3, 2, 1}
	if len(descIDs) != len(wantDesc) {
		t.Fatalf("descIDs=%v want=%v", descIDs, wantDesc)
	}
	for i := range wantDesc {
		if descIDs[i] != wantDesc[i] {
			t.Fatalf("descIDs=%v want=%v", descIDs, wantDesc)
		}
	}
}
