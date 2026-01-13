package domain

import (
	"time"

	"github.com/google/uuid"
)

// UserRiskProfile represents a user's AML risk assessment
type UserRiskProfile struct {
	ID     uuid.UUID `json:"id" db:"id"`
	UserID uuid.UUID `json:"user_id" db:"user_id"`

	// Overall risk assessment
	RiskScore      int       `json:"risk_score" db:"risk_score"` // 0-100
	RiskLevel      RiskLevel `json:"risk_level" db:"risk_level"`
	LastAssessment time.Time `json:"last_assessment" db:"last_assessment"`
	NextReviewDate time.Time `json:"next_review_date" db:"next_review_date"`

	// Risk factors
	CountryRisk      int `json:"country_risk" db:"country_risk"`       // Based on residence
	OccupationRisk   int `json:"occupation_risk" db:"occupation_risk"` // Based on profession
	TransactionRisk  int `json:"transaction_risk" db:"transaction_risk"`
	BehavioralRisk   int `json:"behavioral_risk" db:"behavioral_risk"`
	RelationshipRisk int `json:"relationship_risk" db:"relationship_risk"`

	// Flags and indicators
	IsPEP          bool        `json:"is_pep" db:"is_pep"`
	PEPDetails     *PEPDetails `json:"pep_details,omitempty" db:"pep_details"`
	IsHighNetWorth bool        `json:"is_high_net_worth" db:"is_high_net_worth"`

	// Sanctions
	HasOFACMatch     bool   `json:"has_ofac_match" db:"has_ofac_match"`
	OFACMatchDetails string `json:"ofac_match_details,omitempty" db:"ofac_match_details"`

	// Transaction patterns
	AvgMonthlyVolume  float64 `json:"avg_monthly_volume" db:"avg_monthly_volume"`
	AvgTransactionAmt float64 `json:"avg_transaction_amt" db:"avg_transaction_amt"`
	TxCountLast30Days int     `json:"tx_count_last_30_days" db:"tx_count_last_30_days"`

	// Countries
	PrimaryCountries  []string `json:"primary_countries" db:"primary_countries"`
	HighRiskCountries []string `json:"high_risk_countries,omitempty" db:"high_risk_countries"`

	// History
	SARCount           int `json:"sar_count" db:"sar_count"`
	InvestigationCount int `json:"investigation_count" db:"investigation_count"`
	BlockedTxCount     int `json:"blocked_tx_count" db:"blocked_tx_count"`

	// Watchlist status
	OnWatchlist      bool       `json:"on_watchlist" db:"on_watchlist"`
	WatchlistReason  string     `json:"watchlist_reason,omitempty" db:"watchlist_reason"`
	WatchlistAddedAt *time.Time `json:"watchlist_added_at,omitempty" db:"watchlist_added_at"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// PEPDetails contains detailed PEP information
type PEPDetails struct {
	Category       string     `json:"category"` // domestic, foreign, international_org
	Position       string     `json:"position"`
	Country        string     `json:"country"`
	StartDate      time.Time  `json:"start_date,omitempty"`
	EndDate        *time.Time `json:"end_date,omitempty"`
	IsActive       bool       `json:"is_active"`
	RiskMultiplier float64    `json:"risk_multiplier"`
}

// VelocityData represents transaction velocity metrics
type VelocityData struct {
	UserID uuid.UUID `json:"user_id" db:"user_id"`

	// Hourly
	TxCountHour int     `json:"tx_count_hour"`
	AmountHour  float64 `json:"amount_hour"`

	// Daily
	TxCountDay int     `json:"tx_count_day"`
	AmountDay  float64 `json:"amount_day"`

	// Weekly
	TxCountWeek int     `json:"tx_count_week"`
	AmountWeek  float64 `json:"amount_week"`

	// Monthly
	TxCountMonth int     `json:"tx_count_month"`
	AmountMonth  float64 `json:"amount_month"`

	// Baselines
	AvgDailyTxCount   float64 `json:"avg_daily_tx_count"`
	AvgDailyAmount    float64 `json:"avg_daily_amount"`
	StdDevDailyAmount float64 `json:"std_dev_daily_amount"`

	// Last updated
	UpdatedAt time.Time `json:"updated_at"`
}

// CalculateOverallRisk computes the weighted average risk score
func (r *UserRiskProfile) CalculateOverallRisk() int {
	// Weighted average of risk factors
	weights := map[string]float64{
		"country":      0.20,
		"occupation":   0.15,
		"transaction":  0.25,
		"behavioral":   0.25,
		"relationship": 0.15,
	}

	score := float64(r.CountryRisk)*weights["country"] +
		float64(r.OccupationRisk)*weights["occupation"] +
		float64(r.TransactionRisk)*weights["transaction"] +
		float64(r.BehavioralRisk)*weights["behavioral"] +
		float64(r.RelationshipRisk)*weights["relationship"]

	// Apply PEP multiplier if applicable
	if r.IsPEP && r.PEPDetails != nil {
		score *= r.PEPDetails.RiskMultiplier
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return int(score)
}

// IsHighRisk returns true if user is considered high risk
func (r *UserRiskProfile) IsHighRisk() bool {
	return r.RiskLevel == RiskLevelHigh || r.RiskLevel == RiskLevelCritical
}

// RequiresEnhancedDueDiligence returns true if EDD is required
func (r *UserRiskProfile) RequiresEnhancedDueDiligence() bool {
	return r.IsPEP || r.HasOFACMatch || r.IsHighRisk() || r.OnWatchlist
}

// NeedsReview returns true if the risk profile needs manual review
func (r *UserRiskProfile) NeedsReview() bool {
	return time.Now().After(r.NextReviewDate) || r.HasOFACMatch
}

// UpdateRiskProfileRequest represents a request to update a risk profile
type UpdateRiskProfileRequest struct {
	CountryRisk      *int    `json:"country_risk,omitempty" validate:"omitempty,min=0,max=100"`
	OccupationRisk   *int    `json:"occupation_risk,omitempty" validate:"omitempty,min=0,max=100"`
	TransactionRisk  *int    `json:"transaction_risk,omitempty" validate:"omitempty,min=0,max=100"`
	BehavioralRisk   *int    `json:"behavioral_risk,omitempty" validate:"omitempty,min=0,max=100"`
	RelationshipRisk *int    `json:"relationship_risk,omitempty" validate:"omitempty,min=0,max=100"`
	IsPEP            *bool   `json:"is_pep,omitempty"`
	IsHighNetWorth   *bool   `json:"is_high_net_worth,omitempty"`
	OnWatchlist      *bool   `json:"on_watchlist,omitempty"`
	WatchlistReason  *string `json:"watchlist_reason,omitempty"`
}

// RiskProfileSummary is a lean DTO for internal services
type RiskProfileSummary struct {
	UserID       uuid.UUID `json:"user_id"`
	RiskScore    int       `json:"risk_score"`
	RiskLevel    RiskLevel `json:"risk_level"`
	IsPEP        bool      `json:"is_pep"`
	OnWatchlist  bool      `json:"on_watchlist"`
	HasOFACMatch bool      `json:"has_ofac_match"`
}

// ToSummary converts UserRiskProfile to RiskProfileSummary
func (r *UserRiskProfile) ToSummary() *RiskProfileSummary {
	return &RiskProfileSummary{
		UserID:       r.UserID,
		RiskScore:    r.RiskScore,
		RiskLevel:    r.RiskLevel,
		IsPEP:        r.IsPEP,
		OnWatchlist:  r.OnWatchlist,
		HasOFACMatch: r.HasOFACMatch,
	}
}
