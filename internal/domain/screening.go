package domain

import (
	"time"

	"github.com/google/uuid"
)

// ScreeningDecision represents the outcome of transaction screening
type ScreeningDecision string

const (
	DecisionApproved   ScreeningDecision = "APPROVED"
	DecisionSuspicious ScreeningDecision = "SUSPICIOUS"
	DecisionBlocked    ScreeningDecision = "BLOCKED"
	DecisionPending    ScreeningDecision = "PENDING"
)

// RiskLevel represents the risk severity
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "LOW"
	RiskLevelMedium   RiskLevel = "MEDIUM"
	RiskLevelHigh     RiskLevel = "HIGH"
	RiskLevelCritical RiskLevel = "CRITICAL"
)

// MatchType represents the type of sanctions match
type MatchType string

const (
	MatchTypeExact MatchType = "EXACT"
	MatchTypeFuzzy MatchType = "FUZZY"
	MatchTypeAlias MatchType = "ALIAS"
)

// ScreeningResult represents the result of a transaction screening
type ScreeningResult struct {
	ID            uuid.UUID `json:"id" db:"id"`
	TransactionID uuid.UUID `json:"transaction_id" db:"transaction_id"`
	UserID        uuid.UUID `json:"user_id" db:"user_id"`

	// Screening details
	RiskScore int               `json:"risk_score" db:"risk_score"` // 0-100
	Decision  ScreeningDecision `json:"decision" db:"decision"`
	RiskLevel RiskLevel         `json:"risk_level" db:"risk_level"`

	// Check results (stored as JSONB)
	OFACMatch      *OFACMatch     `json:"ofac_match,omitempty" db:"ofac_match"`
	PEPMatch       *PEPMatch      `json:"pep_match,omitempty" db:"pep_match"`
	RiskFactors    []RiskFactor   `json:"risk_factors" db:"risk_factors"`
	PatternMatches []PatternMatch `json:"pattern_matches,omitempty" db:"pattern_matches"`

	// Performance metrics
	ScreeningDurationMs int64 `json:"screening_duration_ms" db:"screening_duration_ms"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// OFACMatch represents a match against the OFAC sanctions list
type OFACMatch struct {
	Matched         bool      `json:"matched"`
	MatchScore      float64   `json:"match_score,omitempty"`
	MatchType       MatchType `json:"match_type,omitempty"`
	SDNName         string    `json:"sdn_name,omitempty"`
	SDNType         string    `json:"sdn_type,omitempty"`
	Program         string    `json:"program,omitempty"`
	MatchedField    string    `json:"matched_field,omitempty"`
	CheckDurationMs int64     `json:"check_duration_ms"`
}

// PEPMatch represents a match against the PEP database
type PEPMatch struct {
	Matched         bool      `json:"matched"`
	MatchScore      float64   `json:"match_score,omitempty"`
	MatchType       MatchType `json:"match_type,omitempty"`
	PEPName         string    `json:"pep_name,omitempty"`
	PEPPosition     string    `json:"pep_position,omitempty"`
	PEPCountry      string    `json:"pep_country,omitempty"`
	RiskCategory    string    `json:"risk_category,omitempty"`
	CheckDurationMs int64     `json:"check_duration_ms"`
}

// RiskFactor represents a factor contributing to the risk score
type RiskFactor struct {
	Factor      string `json:"factor"`
	Weight      int    `json:"weight"` // Points added to risk score
	Description string `json:"description"`
	Details     string `json:"details,omitempty"`
}

// PatternMatch represents a detected money laundering pattern
type PatternMatch struct {
	PatternType  PatternType `json:"pattern_type"`
	Confidence   float64     `json:"confidence"` // 0.0 - 1.0
	Description  string      `json:"description"`
	RelatedTxIDs []uuid.UUID `json:"related_tx_ids,omitempty"`
	DetectedAt   time.Time   `json:"detected_at"`
}

// PatternType represents types of suspicious patterns
type PatternType string

const (
	PatternStructuring      PatternType = "STRUCTURING"
	PatternRapidCycling     PatternType = "RAPID_CYCLING"
	PatternGeoConcentration PatternType = "GEO_CONCENTRATION"
	PatternVelocitySpike    PatternType = "VELOCITY_SPIKE"
	PatternMixingLayering   PatternType = "MIXING_LAYERING"
	PatternSmurfing         PatternType = "SMURFING"
	PatternRoundTripping    PatternType = "ROUND_TRIPPING"
	PatternUnusualTime      PatternType = "UNUSUAL_TIME"
)

// CalculateRiskLevel returns the risk level based on score
func CalculateRiskLevel(score int) RiskLevel {
	switch {
	case score >= 80:
		return RiskLevelCritical
	case score >= 60:
		return RiskLevelHigh
	case score >= 30:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}

// CalculateDecision returns the screening decision based on score
func CalculateDecision(score int) ScreeningDecision {
	switch {
	case score >= 80:
		return DecisionBlocked
	case score >= 50:
		return DecisionSuspicious
	default:
		return DecisionApproved
	}
}

// IsHighRisk returns true if the result warrants investigation
func (s *ScreeningResult) IsHighRisk() bool {
	return s.RiskScore >= 60 || s.Decision == DecisionBlocked || s.Decision == DecisionSuspicious
}

// RequiresInvestigation returns true if an investigation should be opened
func (s *ScreeningResult) RequiresInvestigation() bool {
	return s.Decision == DecisionSuspicious || s.Decision == DecisionBlocked
}

// HasOFACMatch returns true if there was an OFAC match
func (s *ScreeningResult) HasOFACMatch() bool {
	return s.OFACMatch != nil && s.OFACMatch.Matched
}

// HasPEPMatch returns true if there was a PEP match
func (s *ScreeningResult) HasPEPMatch() bool {
	return s.PEPMatch != nil && s.PEPMatch.Matched
}
