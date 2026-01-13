package domain

import (
	"time"

	"github.com/google/uuid"
)

// FilingType represents the type of regulatory filing
type FilingType string

const (
	FilingTypeSAR FilingType = "SAR" // Suspicious Activity Report
	FilingTypeCTR FilingType = "CTR" // Currency Transaction Report
)

// FilingStatus represents the status of a filing
type FilingStatus string

const (
	FilingStatusDraft     FilingStatus = "DRAFT"
	FilingStatusReview    FilingStatus = "PENDING_REVIEW"
	FilingStatusApproved  FilingStatus = "APPROVED"
	FilingStatusSubmitted FilingStatus = "SUBMITTED"
	FilingStatusAccepted  FilingStatus = "ACCEPTED"
	FilingStatusRejected  FilingStatus = "REJECTED"
	FilingStatusAmended   FilingStatus = "AMENDED"
)

// RegulatoryFiling represents a SAR or CTR filing
type RegulatoryFiling struct {
	ID           uuid.UUID `json:"id" db:"id"`
	FilingNumber string    `json:"filing_number" db:"filing_number"`
	BSAFilingID  string    `json:"bsa_filing_id,omitempty" db:"bsa_filing_id"` // FinCEN BSA ID

	// Type
	FilingType FilingType   `json:"filing_type" db:"filing_type"`
	Status     FilingStatus `json:"status" db:"status"`

	// Subject
	UserID          uuid.UUID   `json:"user_id" db:"user_id"`
	InvestigationID *uuid.UUID  `json:"investigation_id,omitempty" db:"investigation_id"`
	TransactionIDs  []uuid.UUID `json:"transaction_ids" db:"transaction_ids"`

	// Filing content (encrypted)
	SubjectInfo        *SARSubject  `json:"subject_info" db:"subject_info"`
	SuspiciousActivity *SARActivity `json:"suspicious_activity,omitempty" db:"suspicious_activity"`
	CTRDetails         *CTRDetails  `json:"ctr_details,omitempty" db:"ctr_details"`

	// Amounts
	TotalAmount float64 `json:"total_amount" db:"total_amount"`
	Currency    string  `json:"currency" db:"currency"`

	// Narrative (for SAR)
	Narrative          string `json:"narrative,omitempty" db:"narrative"`
	NarrativeEncrypted string `json:"-" db:"narrative_encrypted"`

	// Workflow
	PreparedBy uuid.UUID  `json:"prepared_by" db:"prepared_by"`
	ReviewedBy *uuid.UUID `json:"reviewed_by,omitempty" db:"reviewed_by"`
	ApprovedBy *uuid.UUID `json:"approved_by,omitempty" db:"approved_by"`

	// Dates
	ActivityStartDate time.Time `json:"activity_start_date" db:"activity_start_date"`
	ActivityEndDate   time.Time `json:"activity_end_date" db:"activity_end_date"`
	FilingDueDate     time.Time `json:"filing_due_date" db:"filing_due_date"`

	// Submission
	SubmittedAt        *time.Time `json:"submitted_at,omitempty" db:"submitted_at"`
	ConfirmationNumber string     `json:"confirmation_number,omitempty" db:"confirmation_number"`
	RejectionReason    string     `json:"rejection_reason,omitempty" db:"rejection_reason"`

	// Amendments
	AmendedFromID   *uuid.UUID `json:"amended_from_id,omitempty" db:"amended_from_id"`
	AmendmentReason string     `json:"amendment_reason,omitempty" db:"amendment_reason"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// SARSubject represents the subject of a SAR
type SARSubject struct {
	// Individual
	FirstName  string `json:"first_name"`
	MiddleName string `json:"middle_name,omitempty"`
	LastName   string `json:"last_name"`
	Suffix     string `json:"suffix,omitempty"`
	DOB        string `json:"dob,omitempty"` // YYYY-MM-DD
	SSN        string `json:"ssn,omitempty"` // Encrypted

	// Address
	Address string `json:"address"`
	City    string `json:"city"`
	State   string `json:"state"`
	ZipCode string `json:"zip_code"`
	Country string `json:"country"`

	// Identification
	IDType    string `json:"id_type,omitempty"`
	IDNumber  string `json:"id_number,omitempty"`
	IDState   string `json:"id_state,omitempty"`
	IDCountry string `json:"id_country,omitempty"`

	// Account
	AccountNumber    string `json:"account_number"`
	AccountOpenDate  string `json:"account_open_date,omitempty"`
	AccountCloseDate string `json:"account_close_date,omitempty"`

	// Relationship
	Occupation   string `json:"occupation,omitempty"`
	Employer     string `json:"employer,omitempty"`
	Relationship string `json:"relationship"` // Customer, Former Customer, etc.
}

// SARActivity represents suspicious activity details
type SARActivity struct {
	// Activity categories
	Categories []string `json:"categories"` // Structuring, Money Laundering, etc.

	// Instruments
	Instruments []string `json:"instruments"` // Cash, Wire Transfer, etc.

	// Products/Services
	Products []string `json:"products"` // Checking, Savings, etc.

	// Amount breakdown
	CashIn          float64 `json:"cash_in,omitempty"`
	CashOut         float64 `json:"cash_out,omitempty"`
	WireTransferIn  float64 `json:"wire_transfer_in,omitempty"`
	WireTransferOut float64 `json:"wire_transfer_out,omitempty"`
	OtherIn         float64 `json:"other_in,omitempty"`
	OtherOut        float64 `json:"other_out,omitempty"`

	// Law enforcement
	LEContactName  string `json:"le_contact_name,omitempty"`
	LEContactPhone string `json:"le_contact_phone,omitempty"`
}

// CTRDetails represents CTR-specific details
type CTRDetails struct {
	// Transaction info
	TransactionDate string `json:"transaction_date"`
	TransactionType string `json:"transaction_type"` // Deposit, Withdrawal, etc.

	// Amounts
	CashIn  float64 `json:"cash_in"`
	CashOut float64 `json:"cash_out"`

	// Conductor (if different from account holder)
	ConductedByOther  bool   `json:"conducted_by_other"`
	ConductorName     string `json:"conductor_name,omitempty"`
	ConductorDOB      string `json:"conductor_dob,omitempty"`
	ConductorSSN      string `json:"conductor_ssn,omitempty"`
	ConductorAddress  string `json:"conductor_address,omitempty"`
	ConductorIDType   string `json:"conductor_id_type,omitempty"`
	ConductorIDNumber string `json:"conductor_id_number,omitempty"`

	// Multiple transactions
	MultipleTransactions bool    `json:"multiple_transactions"`
	AggregatedAmount     float64 `json:"aggregated_amount,omitempty"`
}

// IsDraft returns true if filing is still in draft
func (f *RegulatoryFiling) IsDraft() bool {
	return f.Status == FilingStatusDraft
}

// CanSubmit returns true if filing can be submitted
func (f *RegulatoryFiling) CanSubmit() bool {
	return f.Status == FilingStatusApproved
}

// IsOverdue returns true if filing is past due date
func (f *RegulatoryFiling) IsOverdue() bool {
	return f.Status != FilingStatusSubmitted &&
		f.Status != FilingStatusAccepted &&
		time.Now().After(f.FilingDueDate)
}

// CreateSARRequest represents a request to create a SAR
type CreateSARRequest struct {
	UserID             uuid.UUID   `json:"user_id" validate:"required"`
	InvestigationID    *uuid.UUID  `json:"investigation_id,omitempty"`
	TransactionIDs     []uuid.UUID `json:"transaction_ids" validate:"required,min=1"`
	SubjectInfo        SARSubject  `json:"subject_info" validate:"required"`
	SuspiciousActivity SARActivity `json:"suspicious_activity" validate:"required"`
	Narrative          string      `json:"narrative" validate:"required,min=100"`
	TotalAmount        float64     `json:"total_amount" validate:"required,gt=0"`
	ActivityStartDate  time.Time   `json:"activity_start_date" validate:"required"`
	ActivityEndDate    time.Time   `json:"activity_end_date" validate:"required"`
}

// CreateCTRRequest represents a request to create a CTR
type CreateCTRRequest struct {
	UserID         uuid.UUID   `json:"user_id" validate:"required"`
	TransactionIDs []uuid.UUID `json:"transaction_ids" validate:"required,min=1"`
	SubjectInfo    SARSubject  `json:"subject_info" validate:"required"`
	CTRDetails     CTRDetails  `json:"ctr_details" validate:"required"`
	TotalAmount    float64     `json:"total_amount" validate:"required,gt=10000"`
}

// FilingSummary is a lean DTO for list views
type FilingSummary struct {
	ID            uuid.UUID    `json:"id"`
	FilingNumber  string       `json:"filing_number"`
	FilingType    FilingType   `json:"filing_type"`
	Status        FilingStatus `json:"status"`
	UserID        uuid.UUID    `json:"user_id"`
	TotalAmount   float64      `json:"total_amount"`
	FilingDueDate time.Time    `json:"filing_due_date"`
	IsOverdue     bool         `json:"is_overdue"`
	CreatedAt     time.Time    `json:"created_at"`
}

// ToSummary converts RegulatoryFiling to FilingSummary
func (f *RegulatoryFiling) ToSummary() *FilingSummary {
	return &FilingSummary{
		ID:            f.ID,
		FilingNumber:  f.FilingNumber,
		FilingType:    f.FilingType,
		Status:        f.Status,
		UserID:        f.UserID,
		TotalAmount:   f.TotalAmount,
		FilingDueDate: f.FilingDueDate,
		IsOverdue:     f.IsOverdue(),
		CreatedAt:     f.CreatedAt,
	}
}
