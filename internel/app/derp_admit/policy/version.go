package policy

import (
	"context"
	"fmt"

	"derp-admit/internel/app/derp_admit/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// BumpVersion atomically increments the singleton policy_state version row
// inside tx, creating it with version 1 if it does not yet exist.
func BumpVersion(tx *gorm.DB) (int64, error) {
	if err := tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "id"}},
		DoUpdates: clause.Assignments(map[string]any{
			"version": gorm.Expr("policy_state.version + 1"),
		}),
	}).Create(&model.PolicyState{
		ID:      model.PolicyStateRowID,
		Version: 1,
	}).Error; err != nil {
		return 0, fmt.Errorf("bump policy version: %w", err)
	}

	var state model.PolicyState
	if err := tx.Select("version").First(&state, "id = ?", model.PolicyStateRowID).Error; err != nil {
		return 0, fmt.Errorf("read bumped policy version: %w", err)
	}
	return state.Version, nil
}

// ReadVersion returns the current stored policy version from policy_state.
func ReadVersion(ctx context.Context, db *gorm.DB) (int64, error) {
	var state model.PolicyState
	if err := db.WithContext(ctx).Select("version").First(&state, "id = ?", model.PolicyStateRowID).Error; err != nil {
		return 0, fmt.Errorf("read policy version: %w", err)
	}
	return state.Version, nil
}
