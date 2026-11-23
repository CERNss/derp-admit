package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/model"
	"derp-admit/internel/app/derp_admit/page"
	"derp-admit/internel/app/derp_admit/policy"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type CreateRelayInput struct {
	Name        string
	Description string
}

type CreateRoleInput struct {
	Name        string
	Description string
	Relays      []string
}

type RoleWithGrants struct {
	Role   model.Role
	Relays []string
}

func (s *Service) CreateRelay(ctx context.Context, in CreateRelayInput) (model.Relay, error) {
	if !policy.NamePattern.MatchString(in.Name) {
		return model.Relay{}, fmt.Errorf("%w: invalid relay name", ErrAdminInvalid)
	}
	description := strings.TrimSpace(in.Description)

	var created model.Relay
	err := s.Mutate(ctx, EffectPolicy, http.StatusCreated, func(tx *gorm.DB, ch *Change) error {
		relay := model.Relay{
			Name:        in.Name,
			Description: description,
		}
		res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&relay)
		if res.Error != nil {
			return fmt.Errorf("create relay: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("%w: relay already exists", ErrAdminConflict)
		}

		purged, err := policy.PurgeRelayRules(tx, relay.Name)
		if err != nil {
			return fmt.Errorf("purge stale relay rules: %w", err)
		}

		created = relay
		ch.Changed = true
		ch.TargetID = relay.Name
		ch.Summary = map[string]any{
			"relay":            relay.Name,
			"description":      relay.Description,
			"purgedStaleRules": purged,
		}
		return nil
	})
	if err != nil {
		return model.Relay{}, err
	}
	return created, nil
}

func (s *Service) ListRelays(ctx context.Context, p page.Request) ([]model.Relay, *string, error) {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var rows []model.Relay
	q := page.Asc(s.db.WithContext(dbCtx).Model(&model.Relay{}), p, "created_at", "name", page.KeyString)
	if err := q.Find(&rows).Error; err != nil {
		if errors.Is(err, page.ErrInvalid) {
			return nil, nil, fmt.Errorf("%w: %w", ErrAdminInvalid, err)
		}
		return nil, nil, fmt.Errorf("list relays: %w", err)
	}

	items, nextCursor := page.Cut(rows, p, func(r model.Relay) (time.Time, string) {
		return r.CreatedAt, r.Name
	})
	if items == nil {
		items = []model.Relay{}
	}
	return items, nextCursor, nil
}

func (s *Service) DeleteRelay(ctx context.Context, name string) error {
	return s.Mutate(ctx, EffectPolicy, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		if name == policy.BuiltinRelay {
			return fmt.Errorf("%w: %w", ErrAdminConflict, policy.ErrBuiltin)
		}

		var relay model.Relay
		q := tx
		if tx.Dialector.Name() == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := q.First(&relay, "name = ?", name).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup relay: %w", err)
		}

		if err := policy.DeleteRelayGrants(tx, name); err != nil {
			if errors.Is(err, policy.ErrBuiltin) {
				return fmt.Errorf("%w: %w", ErrAdminConflict, err)
			}
			return fmt.Errorf("delete relay grants: %w", err)
		}

		if err := tx.Delete(&model.Relay{}, "name = ?", name).Error; err != nil {
			return fmt.Errorf("delete relay: %w", err)
		}

		ch.Changed = true
		ch.TargetID = name
		ch.Summary = map[string]any{
			"relay": name,
		}
		return nil
	})
}

func (s *Service) CreateRole(ctx context.Context, in CreateRoleInput) (RoleWithGrants, error) {
	if !policy.NamePattern.MatchString(in.Name) {
		return RoleWithGrants{}, fmt.Errorf("%w: invalid role name", ErrAdminInvalid)
	}
	normalizedRelays, err := normalizeRelaysInput(in.Relays)
	if err != nil {
		return RoleWithGrants{}, fmt.Errorf("%w: %w", ErrAdminInvalid, err)
	}
	description := strings.TrimSpace(in.Description)

	var out RoleWithGrants
	err = s.Mutate(ctx, EffectPolicy, http.StatusCreated, func(tx *gorm.DB, ch *Change) error {
		role := model.Role{
			Name:        in.Name,
			Description: description,
		}
		res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&role)
		if res.Error != nil {
			return fmt.Errorf("create role: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("%w: role already exists", ErrAdminConflict)
		}

		purged, err := policy.PurgeRoleRules(tx, role.Name)
		if err != nil {
			return fmt.Errorf("purge stale role rules: %w", err)
		}

		if err := policy.SetRoleGrants(tx, role.Name, normalizedRelays); err != nil {
			if errors.Is(err, policy.ErrUnknownRelay) || errors.Is(err, policy.ErrInvalidGrant) {
				return fmt.Errorf("%w: %w", ErrAdminInvalid, err)
			}
			return fmt.Errorf("set role grants: %w", err)
		}
		if len(normalizedRelays) == 1 && normalizedRelays[0] == "*" {
			role.AllRelays = true
		}

		out = RoleWithGrants{
			Role:   role,
			Relays: normalizedRelays,
		}
		ch.Changed = true
		ch.TargetID = role.Name
		ch.Summary = map[string]any{
			"role":             role.Name,
			"description":      role.Description,
			"relays":           normalizedRelays,
			"purgedStaleRules": purged,
		}
		return nil
	})
	if err != nil {
		return RoleWithGrants{}, err
	}
	return out, nil
}

func (s *Service) ListRoles(ctx context.Context, p page.Request) ([]RoleWithGrants, *string, error) {
	dbCtx, cancel := context.WithTimeout(ctx, s.dbTimeout)
	defer cancel()

	var rows []model.Role
	q := page.Asc(s.db.WithContext(dbCtx).Model(&model.Role{}), p, "created_at", "name", page.KeyString)
	if err := q.Find(&rows).Error; err != nil {
		if errors.Is(err, page.ErrInvalid) {
			return nil, nil, fmt.Errorf("%w: %w", ErrAdminInvalid, err)
		}
		return nil, nil, fmt.Errorf("list roles: %w", err)
	}

	pageRoles, nextCursor := page.Cut(rows, p, func(r model.Role) (time.Time, string) {
		return r.CreatedAt, r.Name
	})

	names := make([]string, len(pageRoles))
	for i, r := range pageRoles {
		names[i] = r.Name
	}

	grants, err := policy.RoleGrants(dbCtx, s.db, names)
	if err != nil {
		return nil, nil, fmt.Errorf("load role grants: %w", err)
	}

	out := make([]RoleWithGrants, 0, len(pageRoles))
	for _, r := range pageRoles {
		relays := grants[r.Name]
		if relays == nil {
			relays = []string{}
		}
		out = append(out, RoleWithGrants{
			Role:   r,
			Relays: relays,
		})
	}
	return out, nextCursor, nil
}

func (s *Service) SetRoleRelays(ctx context.Context, roleName string, relays []string) ([]string, error) {
	var result []string
	err := s.Mutate(ctx, EffectPolicy, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		if !policy.NamePattern.MatchString(roleName) {
			return ErrAdminNotFound
		}
		var role model.Role
		q := tx
		if tx.Dialector.Name() == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := q.First(&role, "name = ?", roleName).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup role: %w", err)
		}

		normalized, err := normalizeRelaysInput(relays)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrAdminInvalid, err)
		}

		currentMap, err := policy.RoleGrants(txContext(ctx, tx), tx, []string{roleName})
		if err != nil {
			return fmt.Errorf("load current role grants: %w", err)
		}
		current := currentMap[roleName]

		ch.TargetID = roleName
		ch.Summary = map[string]any{
			"role":   roleName,
			"relays": normalized,
		}
		result = normalized

		if slices.Equal(current, normalized) {
			ch.Changed = false
			return nil
		}

		if err := policy.SetRoleGrants(tx, roleName, normalized); err != nil {
			switch {
			case errors.Is(err, policy.ErrUnknownRole):
				return ErrAdminNotFound
			case errors.Is(err, policy.ErrUnknownRelay), errors.Is(err, policy.ErrInvalidGrant):
				return fmt.Errorf("%w: %w", ErrAdminInvalid, err)
			default:
				return fmt.Errorf("set role grants: %w", err)
			}
		}

		ch.Changed = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) DeleteRole(ctx context.Context, name string) (int64, error) {
	var removedBindings int64
	err := s.Mutate(ctx, EffectPolicy, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		if name == policy.BuiltinRole {
			return fmt.Errorf("%w: %w", ErrAdminConflict, policy.ErrBuiltin)
		}

		var role model.Role
		q := tx
		if tx.Dialector.Name() == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := q.First(&role, "name = ?", name).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup role: %w", err)
		}

		bindings, err := policy.DeleteRoleRules(tx, name)
		if err != nil {
			if errors.Is(err, policy.ErrBuiltin) {
				return fmt.Errorf("%w: %w", ErrAdminConflict, err)
			}
			return fmt.Errorf("delete role rules: %w", err)
		}

		if err := tx.Delete(&model.Role{}, "name = ?", name).Error; err != nil {
			return fmt.Errorf("delete role: %w", err)
		}

		removedBindings = bindings
		ch.Changed = true
		ch.TargetID = name
		ch.Summary = map[string]any{
			"role":            name,
			"removedBindings": bindings,
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removedBindings, nil
}

func (s *Service) SetUserRoles(ctx context.Context, userID uuid.UUID, roles []string) ([]string, error) {
	var result []string
	err := s.Mutate(ctx, EffectPolicy, http.StatusOK, func(tx *gorm.DB, ch *Change) error {
		var user model.User
		if err := tx.First(&user, "id = ?", userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrAdminNotFound
			}
			return fmt.Errorf("lookup user: %w", err)
		}

		normalized := dedupeSortedStrings(roles)
		for _, roleName := range normalized {
			if !policy.NamePattern.MatchString(roleName) {
				return fmt.Errorf("%w: %w: %s", ErrAdminInvalid, policy.ErrUnknownRole, roleName)
			}
		}

		currentMap, err := policy.UserRoles(txContext(ctx, tx), tx, []uuid.UUID{userID})
		if err != nil {
			return fmt.Errorf("load current user roles: %w", err)
		}
		current := currentMap[userID]

		ch.TargetID = userID.String()
		ch.Summary = map[string]any{
			"userId": userID.String(),
			"roles":  normalized,
		}
		result = normalized

		if slices.Equal(current, normalized) {
			ch.Changed = false
			return nil
		}

		if err := policy.SetUserRoles(tx, userID, normalized); err != nil {
			if errors.Is(err, policy.ErrUnknownRole) {
				return fmt.Errorf("%w: %w", ErrAdminInvalid, err)
			}
			return fmt.Errorf("set user roles: %w", err)
		}

		ch.Changed = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func normalizeRelaysInput(relays []string) ([]string, error) {
	normalized := dedupeSortedStrings(relays)
	if slices.Contains(normalized, "*") {
		if len(normalized) > 1 {
			return nil, fmt.Errorf("%w: wildcard '*' must be the only relay entry", policy.ErrInvalidGrant)
		}
		return []string{"*"}, nil
	}
	for _, r := range normalized {
		if !policy.NamePattern.MatchString(r) {
			return nil, fmt.Errorf("%w: %s", policy.ErrUnknownRelay, r)
		}
	}
	return normalized, nil
}

func dedupeSortedStrings(items []string) []string {
	if len(items) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, dup := seen[item]; dup {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func txContext(fallback context.Context, tx *gorm.DB) context.Context {
	if tx != nil && tx.Statement != nil && tx.Statement.Context != nil {
		return tx.Statement.Context
	}
	return fallback
}
