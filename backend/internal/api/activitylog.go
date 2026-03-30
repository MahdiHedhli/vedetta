package api

import (
	"sync"
	"time"
)

// LogEntry represents a structured activity log entry.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`     // info, warn, error
	Category  string    `json:"category"`  // sensor, scan, device, system, ingest
	Message   string    `json:"message"`
}

// ActivityLog is a thread-safe ring buffer of recent log entries.
type ActivityLog struct {
	mu      sync.Mutex
	entries []LogEntry
	maxSize int
}

// NewActivityLog creates a log buffer with the given capacity.
func NewActivityLog(maxSize int) *ActivityLog {
	return &ActivityLog{
		entries: make([]LogEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

// Add appends a log entry, evicting the oldest if at capacity.
func (al *ActivityLog) Add(level, category, message string) {
	al.mu.Lock()
	defer al.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Category:  category,
		Message:   message,
	}

	if len(al.entries) >= al.maxSize {
		al.entries = al.entries[1:]
	}
	al.entries = append(al.entries, entry)
}

// Info adds an info-level entry.
func (al *ActivityLog) Info(category, message string) {
	al.Add("info", category, message)
}

// Warn adds a warn-level entry.
func (al *ActivityLog) Warn(category, message string) {
	al.Add("warn", category, message)
}

// Error adds an error-level entry.
func (al *ActivityLog) Error(category, message string) {
	al.Add("error", category, message)
}

// Recent returns the last N entries in reverse chronological order.
func (al *ActivityLog) Recent(n int) []LogEntry {
	al.mu.Lock()
	defer al.mu.Unlock()

	if n <= 0 || len(al.entries) == 0 {
		return []LogEntry{}
	}

	start := len(al.entries) - n
	if start < 0 {
		start = 0
	}

	// Return in reverse order (newest first)
	slice := al.entries[start:]
	result := make([]LogEntry, len(slice))
	for i, e := range slice {
		result[len(slice)-1-i] = e
	}
	return result
}
