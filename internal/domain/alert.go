package domain

import (
	"time"

	"github.com/google/uuid"
)

// AlertType represents the type of AML alert
type AlertType string

const (
	AlertTypePattern         AlertType = "PATTERN_DETECTION"
	AlertTypeScreening       AlertType = "SCREENING_HIT"
	AlertTypeVelocity        AlertType = "VELOCITY_SPIKE"
	AlertTypeThreshold       AlertType = "THRESHOLD_BREACH"
	AlertTypeWatchlist       AlertType = "WATCHLIST_HIT"
	AlertTypeSystemGenerated AlertType = "SYSTEM_GENERATED"
)

// AlertStatus represents the status of an alert
type AlertStatus string

const (
	AlertStatusNew       AlertStatus = "NEW"
	AlertStatusReviewing AlertStatus = "REVIEWING"
	AlertStatusEscalated AlertStatus = "ESCALATED"
	AlertStatusDismissed AlertStatus = "DISMISSED"
	AlertStatusResolved  AlertStatus = "RESOLVED"
)

// AMLAlert represents a system-generated AML alert
type AMLAlert struct {
	ID          uuid.UUID `json:"id" db:"id"`
	AlertNumber string    `json:"alert_number" db:"alert_number"`

	// Subject
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	TransactionID *uuid.UUID `json:"transaction_id,omitempty" db:"transaction_id"`

	// Classification
	AlertType AlertType   `json:"alert_type" db:"alert_type"`
	Status    AlertStatus `json:"status" db:"status"`
	Priority  RiskLevel   `json:"priority" db:"priority"`
	RiskScore int         `json:"risk_score" db:"risk_score"`

	// Details
	Title        string       `json:"title" db:"title"`
	Description  string       `json:"description" db:"description"`
	PatternType  *PatternType `json:"pattern_type,omitempty" db:"pattern_type"`
	RelatedTxIDs []uuid.UUID  `json:"related_tx_ids,omitempty" db:"related_tx_ids"`

	// Detection metrics
	Confidence    float64 `json:"confidence" db:"confidence"`
	DetectionRule string  `json:"detection_rule" db:"detection_rule"`

	// Resolution
	InvestigationID *uuid.UUID `json:"investigation_id,omitempty" db:"investigation_id"`
	ReviewedBy      *uuid.UUID `json:"reviewed_by,omitempty" db:"reviewed_by"`
	ReviewedAt      *time.Time `json:"reviewed_at,omitempty" db:"reviewed_at"`
	Resolution      string     `json:"resolution,omitempty" db:"resolution"`

	// Timestamps
	DetectedAt time.Time `json:"detected_at" db:"detected_at"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}

// IsResolved returns true if the alert has been resolved
func (a *AMLAlert) IsResolved() bool {
	return a.Status == AlertStatusDismissed || a.Status == AlertStatusResolved
}

// RequiresEscalation returns true if alert should be escalated
func (a *AMLAlert) RequiresEscalation() bool {
	return a.RiskScore >= 80 || a.Priority == RiskLevelCritical
}

// CreateAlertRequest represents a request to create an alert
type CreateAlertRequest struct {
	UserID        uuid.UUID    `json:"user_id" validate:"required"`
	TransactionID *uuid.UUID   `json:"transaction_id,omitempty"`
	AlertType     AlertType    `json:"alert_type" validate:"required"`
	Title         string       `json:"title" validate:"required,min=5,max=200"`
	Description   string       `json:"description" validate:"required,min=10"`
	PatternType   *PatternType `json:"pattern_type,omitempty"`
	Confidence    float64      `json:"confidence" validate:"min=0,max=1"`
	RiskScore     int          `json:"risk_score" validate:"min=0,max=100"`
	DetectionRule string       `json:"detection_rule" validate:"required"`
	RelatedTxIDs  []uuid.UUID  `json:"related_tx_ids,omitempty"`
}

// AlertSummary is a lean DTO for list views
type AlertSummary struct {
	ID          uuid.UUID   `json:"id"`
	AlertNumber string      `json:"alert_number"`
	UserID      uuid.UUID   `json:"user_id"`
	AlertType   AlertType   `json:"alert_type"`
	Status      AlertStatus `json:"status"`
	Priority    RiskLevel   `json:"priority"`
	Title       string      `json:"title"`
	Confidence  float64     `json:"confidence"`
	DetectedAt  time.Time   `json:"detected_at"`
}

// ToSummary converts AMLAlert to AlertSummary
func (a *AMLAlert) ToSummary() *AlertSummary {
	return &AlertSummary{
		ID:          a.ID,
		AlertNumber: a.AlertNumber,
		UserID:      a.UserID,
		AlertType:   a.AlertType,
		Status:      a.Status,
		Priority:    a.Priority,
		Title:       a.Title,
		Confidence:  a.Confidence,
		DetectedAt:  a.DetectedAt,
	}
}
