package domain

import (
	"time"

	"github.com/google/uuid"
)

// InvestigationStatus represents the status of an investigation
type InvestigationStatus string

const (
	InvestigationStatusOpen       InvestigationStatus = "OPEN"
	InvestigationStatusAssigned   InvestigationStatus = "ASSIGNED"
	InvestigationStatusInProgress InvestigationStatus = "IN_PROGRESS"
	InvestigationStatusEscalated  InvestigationStatus = "ESCALATED"
	InvestigationStatusPending    InvestigationStatus = "PENDING_REVIEW"
	InvestigationStatusClosed     InvestigationStatus = "CLOSED"
)

// InvestigationDecision represents the final decision of an investigation
type InvestigationDecision string

const (
	DecisionFalsePositive    InvestigationDecision = "FALSE_POSITIVE"
	DecisionSARFiled         InvestigationDecision = "SAR_FILED"
	DecisionNoActionRequired InvestigationDecision = "NO_ACTION_REQUIRED"
	DecisionAccountBlocked   InvestigationDecision = "ACCOUNT_BLOCKED"
	DecisionReferred         InvestigationDecision = "REFERRED_EXTERNAL"
)

// InvestigationPriority represents the urgency of investigation
type InvestigationPriority string

const (
	PriorityLow      InvestigationPriority = "LOW"
	PriorityMedium   InvestigationPriority = "MEDIUM"
	PriorityHigh     InvestigationPriority = "HIGH"
	PriorityCritical InvestigationPriority = "CRITICAL"
)

// Investigation represents an AML investigation
type Investigation struct {
	ID         uuid.UUID `json:"id" db:"id"`
	CaseNumber string    `json:"case_number" db:"case_number"`

	// Subject
	UserID            uuid.UUID  `json:"user_id" db:"user_id"`
	TransactionID     *uuid.UUID `json:"transaction_id,omitempty" db:"transaction_id"`
	ScreeningResultID *uuid.UUID `json:"screening_result_id,omitempty" db:"screening_result_id"`
	AlertID           *uuid.UUID `json:"alert_id,omitempty" db:"alert_id"`

	// Classification
	Status            InvestigationStatus   `json:"status" db:"status"`
	Priority          InvestigationPriority `json:"priority" db:"priority"`
	RiskScore         int                   `json:"risk_score" db:"risk_score"`
	InvestigationType string                `json:"investigation_type" db:"investigation_type"`

	// Assignment
	AssignedTo *uuid.UUID `json:"assigned_to,omitempty" db:"assigned_to"`
	AssignedAt *time.Time `json:"assigned_at,omitempty" db:"assigned_at"`
	AssignedBy *uuid.UUID `json:"assigned_by,omitempty" db:"assigned_by"`

	// Investigation details
	Title       string     `json:"title" db:"title"`
	Description string     `json:"description" db:"description"`
	Findings    string     `json:"findings,omitempty" db:"findings"`
	Evidence    []Evidence `json:"evidence,omitempty" db:"evidence"`

	// Decision
	Decision       *InvestigationDecision `json:"decision,omitempty" db:"decision"`
	DecisionReason string                 `json:"decision_reason,omitempty" db:"decision_reason"`
	DecisionBy     *uuid.UUID             `json:"decision_by,omitempty" db:"decision_by"`
	DecisionAt     *time.Time             `json:"decision_at,omitempty" db:"decision_at"`

	// Compliance
	SARFilingID *uuid.UUID `json:"sar_filing_id,omitempty" db:"sar_filing_id"`
	CTRFilingID *uuid.UUID `json:"ctr_filing_id,omitempty" db:"ctr_filing_id"`

	// SLA
	DueDate     time.Time `json:"due_date" db:"due_date"`
	SLABreached bool      `json:"sla_breached" db:"sla_breached"`

	// Timestamps
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	ClosedAt  *time.Time `json:"closed_at,omitempty" db:"closed_at"`
}

// Evidence represents supporting evidence for an investigation
type Evidence struct {
	ID          uuid.UUID `json:"id"`
	Type        string    `json:"type"` // transaction, document, note, screenshot
	Description string    `json:"description"`
	Reference   string    `json:"reference"` // URL or ID reference
	AddedBy     uuid.UUID `json:"added_by"`
	AddedAt     time.Time `json:"added_at"`
}

// InvestigationNote represents a note/comment on an investigation
type InvestigationNote struct {
	ID              uuid.UUID `json:"id" db:"id"`
	InvestigationID uuid.UUID `json:"investigation_id" db:"investigation_id"`
	AuthorID        uuid.UUID `json:"author_id" db:"author_id"`
	Content         string    `json:"content" db:"content"`
	IsInternal      bool      `json:"is_internal" db:"is_internal"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// InvestigationTimeline represents an event in investigation history
type InvestigationTimeline struct {
	ID              uuid.UUID `json:"id" db:"id"`
	InvestigationID uuid.UUID `json:"investigation_id" db:"investigation_id"`
	EventType       string    `json:"event_type" db:"event_type"`
	Description     string    `json:"description" db:"description"`
	OldValue        string    `json:"old_value,omitempty" db:"old_value"`
	NewValue        string    `json:"new_value,omitempty" db:"new_value"`
	ActorID         uuid.UUID `json:"actor_id" db:"actor_id"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

// IsClosed returns true if investigation is in a closed state
func (i *Investigation) IsClosed() bool {
	return i.Status == InvestigationStatusClosed
}

// IsOverdue returns true if the investigation has breached SLA
func (i *Investigation) IsOverdue() bool {
	return !i.IsClosed() && time.Now().After(i.DueDate)
}

// CanAssign returns true if the investigation can be assigned
func (i *Investigation) CanAssign() bool {
	return i.Status == InvestigationStatusOpen || i.Status == InvestigationStatusAssigned
}

// CanClose returns true if the investigation can be closed
func (i *Investigation) CanClose() bool {
	return i.Status != InvestigationStatusClosed && i.Decision != nil
}

// CreateInvestigationRequest represents a request to create an investigation
type CreateInvestigationRequest struct {
	UserID            uuid.UUID             `json:"user_id" validate:"required"`
	TransactionID     *uuid.UUID            `json:"transaction_id,omitempty"`
	ScreeningResultID *uuid.UUID            `json:"screening_result_id,omitempty"`
	AlertID           *uuid.UUID            `json:"alert_id,omitempty"`
	InvestigationType string                `json:"investigation_type" validate:"required"`
	Title             string                `json:"title" validate:"required,min=5,max=200"`
	Description       string                `json:"description" validate:"required,min=10"`
	Priority          InvestigationPriority `json:"priority" validate:"required,oneof=LOW MEDIUM HIGH CRITICAL"`
	RiskScore         int                   `json:"risk_score" validate:"min=0,max=100"`
}

// AssignInvestigationRequest represents a request to assign an investigation
type AssignInvestigationRequest struct {
	AssigneeID uuid.UUID `json:"assignee_id" validate:"required"`
	Note       string    `json:"note,omitempty"`
}

// InvestigationDecisionRequest represents a request to make a decision
type InvestigationDecisionRequest struct {
	Decision     InvestigationDecision `json:"decision" validate:"required"`
	Reason       string                `json:"reason" validate:"required,min=10"`
	FileSAR      bool                  `json:"file_sar,omitempty"`
	BlockAccount bool                  `json:"block_account,omitempty"`
}

// UpdateInvestigationRequest represents a request to update an investigation
type UpdateInvestigationRequest struct {
	Status      *InvestigationStatus   `json:"status,omitempty"`
	Priority    *InvestigationPriority `json:"priority,omitempty"`
	Findings    *string                `json:"findings,omitempty"`
	Description *string                `json:"description,omitempty"`
}

// InvestigationSummary is a lean DTO for list views
type InvestigationSummary struct {
	ID          uuid.UUID             `json:"id"`
	CaseNumber  string                `json:"case_number"`
	UserID      uuid.UUID             `json:"user_id"`
	Status      InvestigationStatus   `json:"status"`
	Priority    InvestigationPriority `json:"priority"`
	RiskScore   int                   `json:"risk_score"`
	Title       string                `json:"title"`
	AssignedTo  *uuid.UUID            `json:"assigned_to,omitempty"`
	DueDate     time.Time             `json:"due_date"`
	SLABreached bool                  `json:"sla_breached"`
	CreatedAt   time.Time             `json:"created_at"`
}

// ToSummary converts Investigation to InvestigationSummary
func (i *Investigation) ToSummary() *InvestigationSummary {
	return &InvestigationSummary{
		ID:          i.ID,
		CaseNumber:  i.CaseNumber,
		UserID:      i.UserID,
		Status:      i.Status,
		Priority:    i.Priority,
		RiskScore:   i.RiskScore,
		Title:       i.Title,
		AssignedTo:  i.AssignedTo,
		DueDate:     i.DueDate,
		SLABreached: i.SLABreached || i.IsOverdue(),
		CreatedAt:   i.CreatedAt,
	}
}
