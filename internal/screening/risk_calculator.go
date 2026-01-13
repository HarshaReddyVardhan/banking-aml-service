package screening

import (
	"github.com/banking/aml-service/internal/config"
	"github.com/banking/aml-service/internal/domain"
)

// RiskCalculator calculates risk scores based on multiple factors
type RiskCalculator struct {
	cfg               *config.PatternsConfig
	highRiskCountries map[string]bool
}

// RiskWeight defines weights for different risk factors
type RiskWeight struct {
	Factor   string
	MaxScore int
	Weight   float64
}

// Default risk weights
var defaultRiskWeights = map[string]RiskWeight{
	"OFAC_MATCH":        {Factor: "OFAC_MATCH", MaxScore: 100, Weight: 1.0},
	"PEP_MATCH":         {Factor: "PEP_MATCH", MaxScore: 40, Weight: 0.8},
	"USER_WATCHLIST":    {Factor: "USER_WATCHLIST", MaxScore: 30, Weight: 0.7},
	"USER_PEP":          {Factor: "USER_PEP", MaxScore: 25, Weight: 0.6},
	"PRIOR_SARS":        {Factor: "PRIOR_SARS", MaxScore: 20, Weight: 0.5},
	"HIGH_RISK_COUNTRY": {Factor: "HIGH_RISK_COUNTRY", MaxScore: 20, Weight: 0.5},
	"HIGH_AMOUNT":       {Factor: "HIGH_AMOUNT", MaxScore: 15, Weight: 0.4},
	"VELOCITY_SPIKE":    {Factor: "VELOCITY_SPIKE", MaxScore: 20, Weight: 0.5},
	"STRUCTURING":       {Factor: "STRUCTURING", MaxScore: 35, Weight: 0.8},
	"RAPID_CYCLING":     {Factor: "RAPID_CYCLING", MaxScore: 30, Weight: 0.7},
	"GEO_CONCENTRATION": {Factor: "GEO_CONCENTRATION", MaxScore: 20, Weight: 0.5},
	"MIXING_LAYERING":   {Factor: "MIXING_LAYERING", MaxScore: 35, Weight: 0.8},
	"SMURFING":          {Factor: "SMURFING", MaxScore: 30, Weight: 0.7},
	"UNUSUAL_TIME":      {Factor: "UNUSUAL_TIME", MaxScore: 10, Weight: 0.3},
	"CROSS_BORDER":      {Factor: "CROSS_BORDER", MaxScore: 10, Weight: 0.3},
}

// NewRiskCalculator creates a new risk calculator
func NewRiskCalculator(cfg *config.PatternsConfig) *RiskCalculator {
	highRiskCountries := make(map[string]bool)
	for _, country := range cfg.HighRiskCountries {
		highRiskCountries[country] = true
	}

	return &RiskCalculator{
		cfg:               cfg,
		highRiskCountries: highRiskCountries,
	}
}

// Calculate computes the overall risk score from screening context
func (c *RiskCalculator) Calculate(sctx *ScreeningContext) int {
	totalScore := 0

	// 1. Sum up existing risk factors
	for _, factor := range sctx.RiskFactors {
		totalScore += factor.Weight
	}

	// 2. Add transaction-specific risk factors
	tx := sctx.Transaction

	// High-risk country check
	if c.isHighRiskCountry(tx.GetCounterpartyCountry()) {
		totalScore += 20
	}

	// Cross-border transaction
	if tx.IsCrossBorder() {
		totalScore += 5
	}

	// High value transaction (>$10K)
	if tx.IsHighValue(10000) {
		if tx.Amount >= 50000 {
			totalScore += 15
		} else {
			totalScore += 10
		}
	}

	// 3. Velocity-based risk factors
	if sctx.VelocityData != nil {
		velocityScore := c.calculateVelocityRisk(sctx.VelocityData, tx)
		totalScore += velocityScore
	}

	// 4. Profile-based adjustments
	if sctx.RiskProfile != nil {
		profileScore := c.calculateProfileRisk(sctx.RiskProfile)
		totalScore += profileScore
	}

	// 5. Pattern-based scores (already included via RiskFactors)

	// Cap at 100
	if totalScore > 100 {
		totalScore = 100
	}
	if totalScore < 0 {
		totalScore = 0
	}

	return totalScore
}

// CalculateFromFactors calculates score from a list of risk factors
func (c *RiskCalculator) CalculateFromFactors(factors []domain.RiskFactor) int {
	totalScore := 0
	for _, factor := range factors {
		if weight, ok := defaultRiskWeights[factor.Factor]; ok {
			score := int(float64(factor.Weight) * weight.Weight)
			if score > weight.MaxScore {
				score = weight.MaxScore
			}
			totalScore += score
		} else {
			totalScore += factor.Weight
		}
	}

	if totalScore > 100 {
		totalScore = 100
	}
	return totalScore
}

// isHighRiskCountry checks if a country is considered high-risk
func (c *RiskCalculator) isHighRiskCountry(country string) bool {
	if country == "" {
		return false
	}
	return c.highRiskCountries[country]
}

// calculateVelocityRisk calculates risk based on velocity anomalies
func (c *RiskCalculator) calculateVelocityRisk(velocity *domain.VelocityData, tx *domain.Transaction) int {
	score := 0

	// Check for velocity spike (10x normal)
	if velocity.AvgDailyAmount > 0 {
		ratio := (velocity.AmountDay + tx.Amount) / velocity.AvgDailyAmount
		if ratio >= c.cfg.VelocitySpikeMultiplier {
			score += 20 // Significant velocity spike
		} else if ratio >= 5.0 {
			score += 10 // Moderate velocity spike
		}
	}

	// Check transaction count spike
	if velocity.AvgDailyTxCount > 0 {
		txRatio := float64(velocity.TxCountDay+1) / velocity.AvgDailyTxCount
		if txRatio >= c.cfg.VelocitySpikeMultiplier {
			score += 10
		}
	}

	return score
}

// calculateProfileRisk adds risk based on user profile
func (c *RiskCalculator) calculateProfileRisk(profile *domain.UserRiskProfile) int {
	score := 0

	// Weighted average of profile risks
	baseScore := (profile.CountryRisk + profile.OccupationRisk +
		profile.TransactionRisk + profile.BehavioralRisk +
		profile.RelationshipRisk) / 5

	// Scale to add 0-20 points
	score += baseScore / 5

	// Additional factors
	if profile.BlockedTxCount > 0 {
		score += min(profile.BlockedTxCount*5, 15)
	}

	if profile.InvestigationCount > 0 {
		score += min(profile.InvestigationCount*3, 10)
	}

	return score
}

// GetRiskThresholds returns the thresholds for risk levels
func GetRiskThresholds() map[string]int {
	return map[string]int{
		"LOW":      0,  // 0-29
		"MEDIUM":   30, // 30-59
		"HIGH":     60, // 60-79
		"CRITICAL": 80, // 80-100
	}
}

// GetDecisionThresholds returns the thresholds for decisions
func GetDecisionThresholds() map[string]int {
	return map[string]int{
		"APPROVED":   0,  // 0-49
		"SUSPICIOUS": 50, // 50-79
		"BLOCKED":    80, // 80-100
	}
}
