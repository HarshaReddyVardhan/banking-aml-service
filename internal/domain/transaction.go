package domain

import (
	"time"

	"github.com/google/uuid"
)

// Transaction represents a transaction to be screened
// This is the event received from the transaction service
type Transaction struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	AccountID uuid.UUID `json:"account_id"`

	// Transaction details
	Type      string  `json:"type"`      // TRANSFER, DEPOSIT, WITHDRAWAL, PAYMENT
	Direction string  `json:"direction"` // INBOUND, OUTBOUND
	Amount    float64 `json:"amount"`
	Currency  string  `json:"currency"`

	// Parties
	SenderName      string `json:"sender_name,omitempty"`
	SenderAccount   string `json:"sender_account,omitempty"`
	SenderCountry   string `json:"sender_country,omitempty"`
	SenderBank      string `json:"sender_bank,omitempty"`
	ReceiverName    string `json:"receiver_name,omitempty"`
	ReceiverAccount string `json:"receiver_account,omitempty"`
	ReceiverCountry string `json:"receiver_country,omitempty"`
	ReceiverBank    string `json:"receiver_bank,omitempty"`

	// Context
	Description string `json:"description,omitempty"`
	Reference   string `json:"reference,omitempty"`
	Channel     string `json:"channel"` // MOBILE, WEB, BRANCH, API

	// Device/Session
	IPAddress   string `json:"ip_address,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
	GeoLocation string `json:"geo_location,omitempty"`

	// Timestamps
	InitiatedAt time.Time `json:"initiated_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// TransactionCreatedEvent is the Kafka event received from transaction service
type TransactionCreatedEvent struct {
	EventID     uuid.UUID    `json:"event_id"`
	EventType   string       `json:"event_type"`
	Timestamp   time.Time    `json:"timestamp"`
	Transaction *Transaction `json:"payload"`
}

// ScreeningRequest represents a request to screen a transaction
type ScreeningRequest struct {
	Transaction *Transaction `json:"transaction" validate:"required"`
	RequesterID uuid.UUID    `json:"requester_id"`
	Priority    string       `json:"priority,omitempty"` // NORMAL, HIGH, URGENT
	BypassCache bool         `json:"bypass_cache,omitempty"`
}

// ScreeningResponse represents the response from transaction screening
type ScreeningResponse struct {
	ScreeningID      uuid.UUID         `json:"screening_id"`
	TransactionID    uuid.UUID         `json:"transaction_id"`
	Decision         ScreeningDecision `json:"decision"`
	RiskScore        int               `json:"risk_score"`
	RiskLevel        RiskLevel         `json:"risk_level"`
	ProcessingTimeMs int64             `json:"processing_time_ms"`

	// Match details
	OFACMatch       bool     `json:"ofac_match"`
	PEPMatch        bool     `json:"pep_match"`
	PatternDetected bool     `json:"pattern_detected"`
	RiskFactors     []string `json:"risk_factors,omitempty"`

	// Actions
	InvestigationCreated bool       `json:"investigation_created"`
	InvestigationID      *uuid.UUID `json:"investigation_id,omitempty"`

	// Errors
	Errors []string `json:"errors,omitempty"`
}

// IsApproved returns true if the transaction was approved
func (r *ScreeningResponse) IsApproved() bool {
	return r.Decision == DecisionApproved
}

// IsBlocked returns true if the transaction was blocked
func (r *ScreeningResponse) IsBlocked() bool {
	return r.Decision == DecisionBlocked
}

// NeedsReview returns true if manual review is required
func (r *ScreeningResponse) NeedsReview() bool {
	return r.Decision == DecisionSuspicious
}

// GetCounterpartyName returns the name of the counterparty
func (t *Transaction) GetCounterpartyName() string {
	if t.Direction == "OUTBOUND" {
		return t.ReceiverName
	}
	return t.SenderName
}

// GetCounterpartyCountry returns the country of the counterparty
func (t *Transaction) GetCounterpartyCountry() string {
	if t.Direction == "OUTBOUND" {
		return t.ReceiverCountry
	}
	return t.SenderCountry
}

// IsCrossBorder returns true if the transaction crosses borders
func (t *Transaction) IsCrossBorder() bool {
	return t.SenderCountry != "" && t.ReceiverCountry != "" &&
		t.SenderCountry != t.ReceiverCountry
}

// IsHighValue returns true if transaction amount exceeds threshold
func (t *Transaction) IsHighValue(threshold float64) bool {
	return t.Amount >= threshold
}
