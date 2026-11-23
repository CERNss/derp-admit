package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"derp-admit/internel/app/derp_admit/actor"
	"derp-admit/internel/app/derp_admit/model"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	upgradeAuditActionDeviceRevoke = "device.revoke"
	upgradeAuditTargetDevice       = "device"
	upgradeAuditOutcomeSuccess     = "success"
)

// RunUpgrade executes the one-time policy data upgrade in a single database
// transaction on both SQLite and PostgreSQL. It is guarded by
// policy_state.upgraded_at so it executes at most once per database.
//
// The upgrade never deletes any casbin_rule row and never loosens access
// compared to the previous model on relay "default" (design A7, R1, R2, R4, S1, S2).
func RunUpgrade(ctx context.Context, db *gorm.DB, casbinWasDisabled bool, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}

	var (
		ran                bool
		uncoveredUserIDs   []string
		revokedDeviceIDs   []string
		unmanagedRuleCount int
	)

	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		state, err := loadOrCreatePolicyStateForUpgrade(tx)
		if err != nil {
			return err
		}
		if state.UpgradedAt != nil {
			return nil
		}

		var rules []model.CasbinRule
		if err := tx.Find(&rules).Error; err != nil {
			return fmt.Errorf("load casbin rules for upgrade: %w", err)
		}

		var existingRoles []model.Role
		if err := tx.Find(&existingRoles).Error; err != nil {
			return fmt.Errorf("load roles for upgrade: %w", err)
		}

		var existingRelays []model.Relay
		if err := tx.Find(&existingRelays).Error; err != nil {
			return fmt.Errorf("load relays for upgrade: %w", err)
		}

		var users []model.User
		if err := tx.Order("id asc").Find(&users).Error; err != nil {
			return fmt.Errorf("load users for upgrade: %w", err)
		}

		var devices []model.Device
		if err := tx.Order("id asc").Find(&devices).Error; err != nil {
			return fmt.Errorf("load devices for upgrade: %w", err)
		}

		importRoles := make(map[string]struct{})
		importRelays := make(map[string]struct{})
		userManagedRoles := make(map[uuid.UUID]map[string]struct{})
		userHasAnyGRule := make(map[uuid.UUID]bool)
		roleGrantsDefault := make(map[string]bool)
		roleGrantsAny := make(map[string]bool)
		legacyDeviceRules := make(map[[2]string]struct{})
		unmanagedCount := 0

		for _, rule := range rules {
			if rule.Ptype == "g" {
				if uidRaw, ok := strings.CutPrefix(rule.V0, userPrefix); ok {
					if uid, err := uuid.Parse(uidRaw); err == nil && uidRaw == uid.String() {
						userHasAnyGRule[uid] = true
					}
				}
			}

			switch rule.Ptype {
			case "g":
				if rule.V2 == "" && rule.V3 == "" && rule.V4 == "" && rule.V5 == "" {
					if uid, roleName, ok := parseManagedUserRoleRule(rule); ok {
						importRoles[roleName] = struct{}{}
						if userManagedRoles[uid] == nil {
							userManagedRoles[uid] = make(map[string]struct{})
						}
						userManagedRoles[uid][roleName] = struct{}{}
						continue
					}
					if nodeKey, ownerID, ok := parseLegacyDeviceRule(rule); ok {
						legacyDeviceRules[[2]string{nodeKey, ownerID.String()}] = struct{}{}
					}
				}
				unmanagedCount++

			case "p":
				if roleName, relayName, ok := parseManagedGrantRule(rule); ok {
					importRoles[roleName] = struct{}{}
					importRelays[relayName] = struct{}{}
					roleGrantsAny[roleName] = true
					if relayName == BuiltinRelay {
						roleGrantsDefault[roleName] = true
					}
					continue
				}
				unmanagedCount++

			default:
				unmanagedCount++
			}
		}

		knownRoles := make(map[string]model.Role, len(existingRoles)+len(importRoles))
		for _, r := range existingRoles {
			if NamePattern.MatchString(r.Name) {
				knownRoles[r.Name] = r
			}
		}
		knownRelays := make(map[string]struct{}, len(existingRelays)+len(importRelays))
		for _, r := range existingRelays {
			if NamePattern.MatchString(r.Name) {
				knownRelays[r.Name] = struct{}{}
			}
		}

		changed := false

		for _, roleName := range sortedStringSet(importRoles) {
			res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.Role{Name: roleName})
			if res.Error != nil {
				return fmt.Errorf("import role %s: %w", roleName, res.Error)
			}
			if res.RowsAffected > 0 {
				changed = true
			}
			if _, exists := knownRoles[roleName]; !exists {
				knownRoles[roleName] = model.Role{Name: roleName}
			}
		}

		for _, relayName := range sortedStringSet(importRelays) {
			res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.Relay{Name: relayName})
			if res.Error != nil {
				return fmt.Errorf("import relay %s: %w", relayName, res.Error)
			}
			if res.RowsAffected > 0 {
				changed = true
			}
			knownRelays[relayName] = struct{}{}
		}

		_, hasDefaultRelay := knownRelays[BuiltinRelay]
		hasAnyRelay := len(knownRelays) > 0
		roleCoversDefault := func(roleName string) bool {
			if !hasDefaultRelay {
				return false
			}
			r, exists := knownRoles[roleName]
			if !exists {
				return false
			}
			return r.AllRelays || roleGrantsDefault[roleName]
		}
		roleCoversAnyRelay := func(roleName string) bool {
			r, exists := knownRoles[roleName]
			if !exists {
				return false
			}
			if r.AllRelays && hasAnyRelay {
				return true
			}
			return roleGrantsAny[roleName]
		}

		devicesByUser := make(map[uuid.UUID][]model.Device, len(users))
		for _, d := range devices {
			devicesByUser[d.UserID] = append(devicesByUser[d.UserID], d)
		}

		now := time.Now().UTC()

		for _, u := range users {
			coveredDefault := false
			coveredAny := false
			for roleName := range userManagedRoles[u.ID] {
				if roleCoversDefault(roleName) {
					coveredDefault = true
				}
				if roleCoversAnyRelay(roleName) {
					coveredAny = true
				}
			}

			if !coveredDefault {
				if casbinWasDisabled || len(devicesByUser[u.ID]) == 0 {
					bound, err := bindUserToStandardWithoutDeleting(tx, u.ID, userManagedRoles[u.ID], userHasAnyGRule[u.ID], knownRoles)
					if err != nil {
						return err
					}
					if bound {
						changed = true
					}
				} else {
					uncoveredUserIDs = append(uncoveredUserIDs, u.ID.String())
				}
			}

			if casbinWasDisabled || !coveredAny {
				continue
			}

			for _, d := range devicesByUser[u.ID] {
				if d.RevokedAt != nil {
					continue
				}
				if _, hasLegacy := legacyDeviceRules[[2]string{d.NodeKey, u.ID.String()}]; hasLegacy {
					continue
				}
				if err := tx.Model(&model.Device{}).
					Where("id = ?", d.ID).
					Update("revoked_at", &now).Error; err != nil {
					return fmt.Errorf("revoke device %s during upgrade: %w", d.ID, err)
				}
				if err := insertUpgradeRevokeAudit(tx, d.ID, now); err != nil {
					return err
				}
				revokedDeviceIDs = append(revokedDeviceIDs, d.ID.String())
				changed = true
			}
		}

		if err := tx.Model(&model.PolicyState{}).
			Where("id = ?", model.PolicyStateRowID).
			Update("upgraded_at", &now).Error; err != nil {
			return fmt.Errorf("record upgrade marker: %w", err)
		}

		if changed {
			if _, err := BumpVersion(tx); err != nil {
				return fmt.Errorf("bump policy version after upgrade: %w", err)
			}
		}

		ran = true
		unmanagedRuleCount = unmanagedCount
		return nil
	}); err != nil {
		return err
	}

	if ran && (len(uncoveredUserIDs) > 0 || len(revokedDeviceIDs) > 0 || unmanagedRuleCount > 0) {
		sort.Strings(uncoveredUserIDs)
		sort.Strings(revokedDeviceIDs)
		logger.Warn("one-time policy upgrade completed with restrictions or unmanaged rules",
			zap.Int("uncovered_user_count", len(uncoveredUserIDs)),
			zap.Strings("uncovered_user_ids", uncoveredUserIDs),
			zap.Int("revoked_device_count", len(revokedDeviceIDs)),
			zap.Strings("revoked_device_ids", revokedDeviceIDs),
			zap.Int("unmanaged_rule_count", unmanagedRuleCount),
		)
	}

	return nil
}

func loadOrCreatePolicyStateForUpgrade(tx *gorm.DB) (model.PolicyState, error) {
	var state model.PolicyState
	query := func() error {
		q := tx
		if tx.Dialector.Name() != "sqlite" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		return q.First(&state, "id = ?", model.PolicyStateRowID).Error
	}

	err := query()
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.PolicyState{
			ID: model.PolicyStateRowID,
		}).Error; err != nil {
			return model.PolicyState{}, fmt.Errorf("create policy_state row: %w", err)
		}
		if err := query(); err != nil {
			return model.PolicyState{}, fmt.Errorf("reload policy_state row: %w", err)
		}
		return state, nil
	}
	if err != nil {
		return model.PolicyState{}, fmt.Errorf("load policy_state: %w", err)
	}
	return state, nil
}

func parseManagedUserRoleRule(rule model.CasbinRule) (uuid.UUID, string, bool) {
	if rule.Ptype != "g" || rule.V2 != "" || rule.V3 != "" || rule.V4 != "" || rule.V5 != "" {
		return uuid.Nil, "", false
	}
	uidRaw, ok := strings.CutPrefix(rule.V0, userPrefix)
	if !ok {
		return uuid.Nil, "", false
	}
	uid, err := uuid.Parse(uidRaw)
	if err != nil || uidRaw != uid.String() {
		return uuid.Nil, "", false
	}
	roleName, ok := strings.CutPrefix(rule.V1, rolePrefix)
	if !ok || !NamePattern.MatchString(roleName) {
		return uuid.Nil, "", false
	}
	return uid, roleName, true
}

func parseManagedGrantRule(rule model.CasbinRule) (string, string, bool) {
	if rule.Ptype != "p" || rule.V3 != "" || rule.V4 != "" || rule.V5 != "" || rule.V2 != connectAct {
		return "", "", false
	}
	roleName, ok := strings.CutPrefix(rule.V0, rolePrefix)
	if !ok || !NamePattern.MatchString(roleName) {
		return "", "", false
	}
	relayName, ok := strings.CutPrefix(rule.V1, relayPrefix)
	if !ok || !NamePattern.MatchString(relayName) {
		return "", "", false
	}
	return roleName, relayName, true
}

func parseLegacyDeviceRule(rule model.CasbinRule) (string, uuid.UUID, bool) {
	if rule.Ptype != "g" || rule.V2 != "" || rule.V3 != "" || rule.V4 != "" || rule.V5 != "" {
		return "", uuid.Nil, false
	}
	nodeKey, ok := strings.CutPrefix(rule.V0, devicePrefix)
	if !ok || nodeKey == "" {
		return "", uuid.Nil, false
	}
	uidRaw, ok := strings.CutPrefix(rule.V1, userPrefix)
	if !ok {
		return "", uuid.Nil, false
	}
	uid, err := uuid.Parse(uidRaw)
	if err != nil || uidRaw != uid.String() {
		return "", uuid.Nil, false
	}
	return nodeKey, uid, true
}

// bindUserToStandardWithoutDeleting adds role:standard for userID without
// deleting any existing casbin_rule row. When the user has no existing g rules
// at all it delegates to SetUserRoles; when the user already has g rules (valid
// or unmanaged), it inserts only the missing standard binding so no rule row is
// deleted.
func bindUserToStandardWithoutDeleting(
	tx *gorm.DB,
	userID uuid.UUID,
	existingManaged map[string]struct{},
	hasAnyGRule bool,
	knownRoles map[string]model.Role,
) (bool, error) {
	if _, already := existingManaged[BuiltinRole]; already {
		return false, nil
	}
	if !hasAnyGRule {
		if err := SetUserRoles(tx, userID, []string{BuiltinRole}); err != nil {
			return false, fmt.Errorf("bind user %s to %s: %w", userID, BuiltinRole, err)
		}
		return true, nil
	}
	if _, ok := knownRoles[BuiltinRole]; !ok {
		return false, fmt.Errorf("%w: %s", ErrUnknownRole, BuiltinRole)
	}
	if err := tx.Create(&model.CasbinRule{
		Ptype: "g",
		V0:    UserSubject(userID),
		V1:    roleSubject(BuiltinRole),
	}).Error; err != nil {
		return false, fmt.Errorf("insert standard binding for user %s: %w", userID, err)
	}
	return true, nil
}

// insertUpgradeRevokeAudit writes a system admin audit row matching
// service.InsertSystemAudit's column conventions (service cannot be imported
// here without creating a package cycle).
func insertUpgradeRevokeAudit(tx *gorm.DB, deviceID uuid.UUID, ts time.Time) error {
	raw, err := json.Marshal(map[string]any{
		"revoked": true,
		"source":  "policy_upgrade",
		"reason":  "revoked by one-time policy upgrade: missing legacy device rule",
	})
	if err != nil {
		return fmt.Errorf("encode upgrade audit summary: %w", err)
	}

	entry := model.AdminAuditLog{
		TS:         ts,
		ActorKeyID: nil,
		ActorName:  actor.System.Name,
		ActorTier:  actor.System.Tier.String(),
		Action:     upgradeAuditActionDeviceRevoke,
		TargetType: upgradeAuditTargetDevice,
		TargetID:   deviceID.String(),
		Outcome:    upgradeAuditOutcomeSuccess,
		HTTPStatus: nil,
		ClientIP:   "",
		Summary:    string(raw),
	}
	if err := tx.Create(&entry).Error; err != nil {
		return fmt.Errorf("insert upgrade revoke audit log: %w", err)
	}
	return nil
}

func sortedStringSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
