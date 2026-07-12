package dnsintel

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/models"
)

type detectorStateSnapshot struct {
	beacon         *BeaconDetector
	beaconKey      beaconKey
	beaconValue    *beaconEntry
	beaconExisted  bool
	rebinding      *RebindingDetector
	rebindingKey   string
	rebindingValue *domainHistory
	rebindingFound bool
	firewall       *FirewallFirstSeen
	firewallKey    string
	firewallValue  time.Time
	firewallFound  bool
}

// BeginEventState holds the Enricher-wide state guard until commit or rollback.
// This prevents a failed event's rollback from overwriting another event that
// committed between checkpoint and persistence.
func (e *Enricher) BeginEventState(event models.Event) (func(*models.Event), func(), func()) {
	e.stateMu.Lock()
	snapshot := snapshotDetectorState(e, event)
	finished := false
	finish := func(restore bool) {
		if finished {
			return
		}
		if restore {
			snapshot.restore()
		}
		finished = true
		e.stateMu.Unlock()
	}
	return e.enrichEvent, func() { finish(false) }, func() { finish(true) }
}

func snapshotDetectorState(e *Enricher, event models.Event) detectorStateSnapshot {
	snapshot := detectorStateSnapshot{}
	if e.Beacon != nil && event.SourceHash != "" && event.Domain != "" {
		snapshot.beacon = e.Beacon
		snapshot.beaconKey = beaconKey{SourceHash: event.SourceHash, Domain: event.Domain}
		e.Beacon.mu.Lock()
		if value, ok := e.Beacon.entries[snapshot.beaconKey]; ok {
			snapshot.beaconExisted = true
			snapshot.beaconValue = &beaconEntry{
				timestamps: append([]time.Time(nil), value.timestamps...),
				lastSeen:   value.lastSeen,
			}
		}
		e.Beacon.mu.Unlock()
	}
	if e.Rebinding != nil && event.Domain != "" {
		snapshot.rebinding = e.Rebinding
		snapshot.rebindingKey = event.Domain
		e.Rebinding.mu.Lock()
		if value, ok := e.Rebinding.history[event.Domain]; ok {
			copyValue := *value
			snapshot.rebindingFound = true
			snapshot.rebindingValue = &copyValue
		}
		e.Rebinding.mu.Unlock()
	}
	if e.FirewallSeen != nil && event.EventType == "firewall_log" {
		var metadata firewallMeta
		_ = json.Unmarshal([]byte(event.Metadata), &metadata)
		sourceIP := strings.TrimSpace(event.SourceIP)
		if sourceIP == "" {
			sourceIP = strings.TrimSpace(metadata.SrcIP)
		}
		if sourceIP != "" {
			snapshot.firewall = e.FirewallSeen
			snapshot.firewallKey = firewallSeenKey(sourceIP, metadata.DstIP, metadata.Rule)
			e.FirewallSeen.mu.Lock()
			if value, ok := e.FirewallSeen.seen[snapshot.firewallKey]; ok {
				snapshot.firewallFound = true
				snapshot.firewallValue = value
			}
			e.FirewallSeen.mu.Unlock()
		}
	}
	return snapshot
}

func (snapshot detectorStateSnapshot) restore() {
	if snapshot.beacon != nil {
		snapshot.beacon.mu.Lock()
		if snapshot.beaconExisted {
			snapshot.beacon.entries[snapshot.beaconKey] = snapshot.beaconValue
		} else {
			delete(snapshot.beacon.entries, snapshot.beaconKey)
		}
		snapshot.beacon.mu.Unlock()
	}
	if snapshot.rebinding != nil {
		snapshot.rebinding.mu.Lock()
		if snapshot.rebindingFound {
			snapshot.rebinding.history[snapshot.rebindingKey] = snapshot.rebindingValue
		} else {
			delete(snapshot.rebinding.history, snapshot.rebindingKey)
		}
		snapshot.rebinding.mu.Unlock()
	}
	if snapshot.firewall != nil {
		snapshot.firewall.mu.Lock()
		if snapshot.firewallFound {
			snapshot.firewall.seen[snapshot.firewallKey] = snapshot.firewallValue
		} else {
			delete(snapshot.firewall.seen, snapshot.firewallKey)
		}
		snapshot.firewall.mu.Unlock()
	}
}
