package store

import (
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/discovery"
)

// TargetAdapter adapts the DB store to satisfy discovery.TargetProvider.
type TargetAdapter struct {
	DB *DB
}

func (a *TargetAdapter) GetEnabledScanTargets() ([]discovery.ScanTarget, error) {
	dbTargets, err := a.DB.GetEnabledScanTargets()
	if err != nil {
		return nil, err
	}

	targets := make([]discovery.ScanTarget, len(dbTargets))
	for i, t := range dbTargets {
		targets[i] = discovery.ScanTarget{
			ID:        t.TargetID,
			Name:      t.Name,
			CIDR:      t.CIDR,
			Segment:   t.Segment,
			ScanPorts: t.ScanPorts,
		}
	}
	return targets, nil
}

func (a *TargetAdapter) UpdateScanTargetLastScan(targetID string, t time.Time) error {
	return a.DB.UpdateScanTargetLastScan(targetID, t)
}
