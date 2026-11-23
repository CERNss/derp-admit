package page

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	DefaultLimit = 50
	MaxLimit     = 200
)

var ErrInvalid = errors.New("invalid pagination")

type KeyKind uint8

const (
	KeyString KeyKind = iota
	KeyInt
)

type Cursor struct {
	L string    `json:"l"`
	T time.Time `json:"t"`
	K string    `json:"k"`
}

type Request struct {
	List  string
	Limit int
	After *Cursor
}

func Parse(list, limitRaw, cursorRaw string) (Request, error) {
	limit := DefaultLimit
	if raw := strings.TrimSpace(limitRaw); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > MaxLimit {
			return Request{}, fmt.Errorf("%w: limit must be an integer between 1 and %d", ErrInvalid, MaxLimit)
		}
		limit = n
	}

	var after *Cursor
	if raw := strings.TrimSpace(cursorRaw); raw != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return Request{}, fmt.Errorf("%w: invalid cursor", ErrInvalid)
		}
		var c Cursor
		if err := json.Unmarshal(decoded, &c); err != nil {
			return Request{}, fmt.Errorf("%w: invalid cursor", ErrInvalid)
		}
		if c.L != list || c.T.IsZero() || c.K == "" {
			return Request{}, fmt.Errorf("%w: invalid cursor", ErrInvalid)
		}
		c.T = c.T.UTC()
		after = &c
	}

	return Request{
		List:  list,
		Limit: limit,
		After: after,
	}, nil
}

func (c Cursor) Encode() string {
	c.T = c.T.UTC()
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func Asc(q *gorm.DB, r Request, tCol, kCol string, k KeyKind) *gorm.DB {
	if r.After != nil {
		keyVal, err := cursorKeyValue(r.After.K, k)
		if err != nil {
			_ = q.AddError(err)
			return q
		}
		ts := r.After.T.UTC()
		q = q.Where(fmt.Sprintf("(%s > ? OR (%s = ? AND %s > ?))", tCol, tCol, kCol), ts, ts, keyVal)
	}
	return q.Order(fmt.Sprintf("%s ASC, %s ASC", tCol, kCol)).Limit(r.Limit + 1)
}

func Desc(q *gorm.DB, r Request, tCol, kCol string, k KeyKind) *gorm.DB {
	if r.After != nil {
		keyVal, err := cursorKeyValue(r.After.K, k)
		if err != nil {
			_ = q.AddError(err)
			return q
		}
		ts := r.After.T.UTC()
		q = q.Where(fmt.Sprintf("(%s < ? OR (%s = ? AND %s < ?))", tCol, tCol, kCol), ts, ts, keyVal)
	}
	return q.Order(fmt.Sprintf("%s DESC, %s DESC", tCol, kCol)).Limit(r.Limit + 1)
}

func Cut[T any](rows []T, r Request, key func(T) (time.Time, string)) ([]T, *string) {
	if len(rows) <= r.Limit {
		return rows, nil
	}
	trimmed := rows[:r.Limit]
	t, k := key(trimmed[len(trimmed)-1])
	next := Cursor{L: r.List, T: t.UTC(), K: k}.Encode()
	return trimmed, &next
}

func cursorKeyValue(raw string, k KeyKind) (any, error) {
	if k == KeyInt {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid cursor key", ErrInvalid)
		}
		return v, nil
	}
	return raw, nil
}
