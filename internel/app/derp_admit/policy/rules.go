package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"derp-admit/internel/app/derp_admit/model"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	BuiltinRelay = "default"
	BuiltinRole  = "standard"
)

var NamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var (
	ErrUnknownRole  = errors.New("unknown role")
	ErrUnknownRelay = errors.New("unknown relay")
	ErrInvalidGrant = errors.New("invalid grant")
	ErrBuiltin      = errors.New("built-in resource cannot be deleted")
)

// SeedBuiltins idempotently ensures relay "default" and role "standard" exist.
// It grants "standard" connect on "default" only when it creates "standard",
// preserving any operator edits to "standard"'s grants across restarts.
func SeedBuiltins(tx *gorm.DB) (created bool, err error) {
	relayRes := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.Relay{
		Name: BuiltinRelay,
	})
	if relayRes.Error != nil {
		return false, fmt.Errorf("seed default relay: %w", relayRes.Error)
	}
	if relayRes.RowsAffected > 0 {
		created = true
	}

	roleRes := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.Role{
		Name: BuiltinRole,
	})
	if roleRes.Error != nil {
		return false, fmt.Errorf("seed standard role: %w", roleRes.Error)
	}
	if roleRes.RowsAffected > 0 {
		created = true
		var existing int64
		if err := tx.Model(&model.CasbinRule{}).
			Where("ptype = ? AND v0 = ? AND v1 = ? AND v2 = ?", "p", roleSubject(BuiltinRole), relayObject(BuiltinRelay), connectAct).
			Count(&existing).Error; err != nil {
			return false, fmt.Errorf("check standard default grant: %w", err)
		}
		if existing == 0 {
			if err := tx.Create(&model.CasbinRule{
				Ptype: "p",
				V0:    roleSubject(BuiltinRole),
				V1:    relayObject(BuiltinRelay),
				V2:    connectAct,
			}).Error; err != nil {
				return false, fmt.Errorf("grant standard on default: %w", err)
			}
		}
	}

	return created, nil
}

// SetUserRoles replaces a user's managed role bindings inside tx. Every role
// in roles must exist in the roles registry or ErrUnknownRole is returned.
func SetUserRoles(tx *gorm.DB, userID uuid.UUID, roles []string) error {
	unique := dedupeSorted(roles)
	if len(unique) > 0 {
		var existing []string
		if err := tx.Model(&model.Role{}).Where("name IN ?", unique).Pluck("name", &existing).Error; err != nil {
			return fmt.Errorf("lookup roles: %w", err)
		}
		found := make(map[string]struct{}, len(existing))
		for _, name := range existing {
			found[name] = struct{}{}
		}
		for _, name := range unique {
			if _, ok := found[name]; !ok {
				return fmt.Errorf("%w: %s", ErrUnknownRole, name)
			}
		}
	}

	userSub := UserSubject(userID)
	if err := tx.Where("ptype = ? AND v0 = ?", "g", userSub).Delete(&model.CasbinRule{}).Error; err != nil {
		return fmt.Errorf("delete existing user role bindings: %w", err)
	}

	for _, name := range unique {
		if err := tx.Create(&model.CasbinRule{
			Ptype: "g",
			V0:    userSub,
			V1:    roleSubject(name),
		}).Error; err != nil {
			return fmt.Errorf("insert user role binding %s: %w", name, err)
		}
	}
	return nil
}

// UserRoles returns the sorted registered role names bound to each requested user id.
func UserRoles(ctx context.Context, db *gorm.DB, ids []uuid.UUID) (map[uuid.UUID][]string, error) {
	result := make(map[uuid.UUID][]string, len(ids))
	if len(ids) == 0 {
		return result, nil
	}

	var registered []string
	if err := db.WithContext(ctx).Model(&model.Role{}).Pluck("name", &registered).Error; err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	validRoles := make(map[string]struct{}, len(registered))
	for _, r := range registered {
		validRoles[r] = struct{}{}
	}

	subjects := make([]string, 0, len(ids))
	subToID := make(map[string]uuid.UUID, len(ids))
	for _, id := range ids {
		result[id] = []string{}
		sub := UserSubject(id)
		if _, dup := subToID[sub]; !dup {
			subToID[sub] = id
			subjects = append(subjects, sub)
		}
	}

	var rows []model.CasbinRule
	if err := db.WithContext(ctx).Where("ptype = ? AND v0 IN ?", "g", subjects).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("load user role bindings: %w", err)
	}

	seen := make(map[uuid.UUID]map[string]struct{}, len(ids))
	for _, row := range rows {
		if row.V2 != "" || row.V3 != "" || row.V4 != "" || row.V5 != "" {
			continue
		}
		uid, ok := subToID[row.V0]
		if !ok {
			continue
		}
		roleName, ok := strings.CutPrefix(row.V1, rolePrefix)
		if !ok {
			continue
		}
		if _, exists := validRoles[roleName]; !exists {
			continue
		}
		if seen[uid] == nil {
			seen[uid] = map[string]struct{}{}
		}
		if _, dup := seen[uid][roleName]; dup {
			continue
		}
		seen[uid][roleName] = struct{}{}
		result[uid] = append(result[uid], roleName)
	}
	for id := range result {
		sort.Strings(result[id])
	}
	return result, nil
}

// SetRoleGrants replaces a role's relay grants inside tx (AM2).
// Passing []string{"*"} sets roles.all_relays = true and clears named grants.
// Passing "*" alongside any other entry returns ErrInvalidGrant.
// Otherwise roles.all_relays is set to false and named grants are replaced
// after verifying every relay is registered.
func SetRoleGrants(tx *gorm.DB, role string, relays []string) error {
	var roleRow model.Role
	if err := tx.First(&roleRow, "name = ?", role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: %s", ErrUnknownRole, role)
		}
		return fmt.Errorf("lookup role %s: %w", role, err)
	}

	hasWildcard := false
	for _, r := range relays {
		if r == "*" {
			hasWildcard = true
			break
		}
	}
	if hasWildcard {
		if len(relays) > 1 {
			return fmt.Errorf("%w: wildcard '*' must be the only relay entry", ErrInvalidGrant)
		}
		if err := tx.Model(&model.Role{}).Where("name = ?", role).Update("all_relays", true).Error; err != nil {
			return fmt.Errorf("set role all_relays: %w", err)
		}
		if err := tx.Where("ptype = ? AND v0 = ? AND v2 = ?", "p", roleSubject(role), connectAct).
			Delete(&model.CasbinRule{}).Error; err != nil {
			return fmt.Errorf("clear named role grants: %w", err)
		}
		return nil
	}

	unique := dedupeSorted(relays)
	if len(unique) > 0 {
		var existing []string
		if err := tx.Model(&model.Relay{}).Where("name IN ?", unique).Pluck("name", &existing).Error; err != nil {
			return fmt.Errorf("lookup relays: %w", err)
		}
		found := make(map[string]struct{}, len(existing))
		for _, name := range existing {
			found[name] = struct{}{}
		}
		for _, name := range unique {
			if _, ok := found[name]; !ok {
				return fmt.Errorf("%w: %s", ErrUnknownRelay, name)
			}
		}
	}

	if err := tx.Model(&model.Role{}).Where("name = ?", role).Update("all_relays", false).Error; err != nil {
		return fmt.Errorf("clear role all_relays: %w", err)
	}
	if err := tx.Where("ptype = ? AND v0 = ? AND v2 = ?", "p", roleSubject(role), connectAct).
		Delete(&model.CasbinRule{}).Error; err != nil {
		return fmt.Errorf("delete existing role grants: %w", err)
	}
	for _, relayName := range unique {
		if err := tx.Create(&model.CasbinRule{
			Ptype: "p",
			V0:    roleSubject(role),
			V1:    relayObject(relayName),
			V2:    connectAct,
		}).Error; err != nil {
			return fmt.Errorf("insert role grant %s -> %s: %w", role, relayName, err)
		}
	}
	return nil
}

// RoleGrants returns each requested role's effective grant list: ["*"] when
// roles.all_relays is true, or the sorted list of registered relays granted
// connect on that role.
func RoleGrants(ctx context.Context, db *gorm.DB, roles []string) (map[string][]string, error) {
	result := make(map[string][]string, len(roles))
	if len(roles) == 0 {
		return result, nil
	}

	uniqueRoles := dedupeSorted(roles)
	for _, r := range uniqueRoles {
		result[r] = []string{}
	}

	var roleRows []model.Role
	if err := db.WithContext(ctx).Where("name IN ?", uniqueRoles).Find(&roleRows).Error; err != nil {
		return nil, fmt.Errorf("load roles: %w", err)
	}

	namedSubjects := make([]string, 0, len(roleRows))
	subToRole := make(map[string]string, len(roleRows))
	for _, r := range roleRows {
		if r.AllRelays {
			result[r.Name] = []string{"*"}
			continue
		}
		sub := roleSubject(r.Name)
		subToRole[sub] = r.Name
		namedSubjects = append(namedSubjects, sub)
	}

	if len(namedSubjects) == 0 {
		return result, nil
	}

	var registeredRelays []string
	if err := db.WithContext(ctx).Model(&model.Relay{}).Pluck("name", &registeredRelays).Error; err != nil {
		return nil, fmt.Errorf("list relays: %w", err)
	}
	validRelays := make(map[string]struct{}, len(registeredRelays))
	for _, r := range registeredRelays {
		validRelays[r] = struct{}{}
	}

	var rows []model.CasbinRule
	if err := db.WithContext(ctx).
		Where("ptype = ? AND v0 IN ? AND v2 = ?", "p", namedSubjects, connectAct).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("load role grants: %w", err)
	}

	seen := make(map[string]map[string]struct{}, len(namedSubjects))
	for _, row := range rows {
		if row.V3 != "" || row.V4 != "" || row.V5 != "" {
			continue
		}
		roleName, ok := subToRole[row.V0]
		if !ok {
			continue
		}
		relayName, ok := strings.CutPrefix(row.V1, relayPrefix)
		if !ok {
			continue
		}
		if _, exists := validRelays[relayName]; !exists {
			continue
		}
		if seen[roleName] == nil {
			seen[roleName] = map[string]struct{}{}
		}
		if _, dup := seen[roleName][relayName]; dup {
			continue
		}
		seen[roleName][relayName] = struct{}{}
		result[roleName] = append(result[roleName], relayName)
	}
	for _, roleName := range subToRole {
		sort.Strings(result[roleName])
	}
	return result, nil
}

// DeleteRoleRules removes all grants of role and all user bindings to role,
// returning the number of user bindings removed.
func DeleteRoleRules(tx *gorm.DB, role string) (bindings int64, err error) {
	if role == BuiltinRole {
		return 0, ErrBuiltin
	}
	sub := roleSubject(role)
	if err := tx.Where("ptype = ? AND v0 = ?", "p", sub).Delete(&model.CasbinRule{}).Error; err != nil {
		return 0, fmt.Errorf("delete role grants for %s: %w", role, err)
	}
	res := tx.Where("ptype = ? AND v0 LIKE ? AND v1 = ?", "g", userPrefix+"%", sub).Delete(&model.CasbinRule{})
	if res.Error != nil {
		return 0, fmt.Errorf("delete user bindings for role %s: %w", role, res.Error)
	}
	return res.RowsAffected, nil
}

// DeleteRelayGrants removes all managed connect grants naming relay.
func DeleteRelayGrants(tx *gorm.DB, relay string) error {
	if relay == BuiltinRelay {
		return ErrBuiltin
	}
	if err := tx.Where("ptype = ? AND v1 = ? AND v2 = ?", "p", relayObject(relay), connectAct).
		Delete(&model.CasbinRule{}).Error; err != nil {
		return fmt.Errorf("delete relay grants for %s: %w", relay, err)
	}
	return nil
}

// DeleteUserRules removes all role bindings for userID and all legacy
// g, device:<node_key>, user:<userID> rules for the user's nodeKeys.
func DeleteUserRules(tx *gorm.DB, userID uuid.UUID, nodeKeys []string) error {
	userSub := UserSubject(userID)
	if err := tx.Where("ptype = ? AND v0 = ?", "g", userSub).Delete(&model.CasbinRule{}).Error; err != nil {
		return fmt.Errorf("delete user role bindings: %w", err)
	}
	if len(nodeKeys) > 0 {
		deviceSubs := make([]string, 0, len(nodeKeys))
		for _, nk := range nodeKeys {
			deviceSubs = append(deviceSubs, devicePrefix+nk)
		}
		if err := tx.Where("ptype = ? AND v0 IN ? AND v1 = ?", "g", deviceSubs, userSub).
			Delete(&model.CasbinRule{}).Error; err != nil {
			return fmt.Errorf("delete legacy device rules for user: %w", err)
		}
	}
	return nil
}

// DeleteLegacyDeviceRule removes the legacy g, device:<nodeKey>, user:<userID> rule.
func DeleteLegacyDeviceRule(tx *gorm.DB, nodeKey string, userID uuid.UUID) error {
	if err := tx.Where("ptype = ? AND v0 = ? AND v1 = ?", "g", devicePrefix+nodeKey, UserSubject(userID)).
		Delete(&model.CasbinRule{}).Error; err != nil {
		return fmt.Errorf("delete legacy device rule: %w", err)
	}
	return nil
}

func dedupeSorted(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, s := range items {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
