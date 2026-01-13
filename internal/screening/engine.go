package screening

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/banking/aml-service/internal/config"
	"github.com/banking/aml-service/internal/domain"
	"github.com/banking/aml-service/internal/pkg/logger"
)

// Engine is the core screening engine that performs parallel AML checks
type Engine struct {
	ofacChecker     *OFACChecker
	pepChecker      *PEPChecker
	riskCalculator  *RiskCalculator
	patternEngine   PatternDetector
	velocityCache   VelocityCache
	riskProfileRepo RiskProfileRepository

	cfg *config.ScreeningConfig
	log *logger.Logger

	// Metrics
	screeningCount int64
	avgLatencyMs   float64
	latencyMu      sync.RWMutex
}

// PatternDetector interface for pattern detection
type PatternDetector interface {
	DetectPatterns(ctx context.Context, userID uuid.UUID, tx *domain.Transaction) ([]domain.PatternMatch, error)
}

// VelocityCache interface for velocity data
type VelocityCache interface {
	GetVelocity(ctx context.Context, userID uuid.UUID) (*domain.VelocityData, error)
	IncrementVelocity(ctx context.Context, userID uuid.UUID, amount float64) error
}

// RiskProfileRepository interface for risk profiles
type RiskProfileRepository interface {
	GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.UserRiskProfile, error)
}

// NewEngine creates a new screening engine
func NewEngine(
	ofacChecker *OFACChecker,
	pepChecker *PEPChecker,
	riskCalculator *RiskCalculator,
	patternEngine PatternDetector,
	velocityCache VelocityCache,
	riskProfileRepo RiskProfileRepository,
	cfg *config.ScreeningConfig,
	log *logger.Logger,
) *Engine {
	return &Engine{
		ofacChecker:     ofacChecker,
		pepChecker:      pepChecker,
		riskCalculator:  riskCalculator,
		patternEngine:   patternEngine,
		velocityCache:   velocityCache,
		riskProfileRepo: riskProfileRepo,
		cfg:             cfg,
		log:             log.Named("screening_engine"),
	}
}

// ScreeningContext holds intermediate results during screening
type ScreeningContext struct {
	Transaction *domain.Transaction
	ScreeningID uuid.UUID
	StartTime   time.Time

	// Results from parallel checks
	OFACResult     *domain.OFACMatch
	PEPResult      *domain.PEPMatch
	RiskProfile    *domain.UserRiskProfile
	VelocityData   *domain.VelocityData
	PatternMatches []domain.PatternMatch
	RiskFactors    []domain.RiskFactor

	// Locks for concurrent access
	mu sync.Mutex
}

// Screen performs comprehensive AML screening on a transaction
// Target: <200ms p99 latency
func (e *Engine) Screen(ctx context.Context, tx *domain.Transaction) (*domain.ScreeningResult, error) {
	startTime := time.Now()
	screeningID := uuid.New()

	e.log.ScreeningStarted(tx.ID.String(), tx.UserID.String())

	// Initialize screening context
	sctx := &ScreeningContext{
		Transaction: tx,
		ScreeningID: screeningID,
		StartTime:   startTime,
		RiskFactors: make([]domain.RiskFactor, 0),
	}

	// Create timeout context (200ms budget)
	screenCtx, cancel := context.WithTimeout(ctx, e.cfg.MaxScreeningLatency)
	defer cancel()

	// Run all checks in parallel using errgroup
	g, gctx := errgroup.WithContext(screenCtx)

	// 1. OFAC Screening (<1ms with cache)
	g.Go(func() error {
		return e.runOFACCheck(gctx, sctx)
	})

	// 2. PEP Check (<5ms with cache)
	g.Go(func() error {
		return e.runPEPCheck(gctx, sctx)
	})

	// 3. Get Risk Profile (<50ms)
	g.Go(func() error {
		return e.getRiskProfile(gctx, sctx)
	})

	// 4. Get Velocity Data (<5ms with cache)
	g.Go(func() error {
		return e.getVelocityData(gctx, sctx)
	})

	// 5. Pattern Detection (<100ms)
	g.Go(func() error {
		return e.detectPatterns(gctx, sctx)
	})

	// Wait for all checks to complete
	if err := g.Wait(); err != nil {
		// Log but continue with available results
		e.log.Warn("some screening checks failed", logger.ErrorField(err))
	}

	// 6. Calculate risk score and make decision
	result := e.calculateResult(sctx)

	// Record latency metrics
	durationMs := time.Since(startTime).Milliseconds()
	e.recordLatency(durationMs)

	// Log if we exceeded latency budget
	if durationMs > int64(e.cfg.MaxScreeningLatency.Milliseconds()) {
		e.log.LatencyWarning("full_screening", durationMs, int64(e.cfg.MaxScreeningLatency.Milliseconds()))
	}

	e.log.ScreeningCompleted(
		tx.ID.String(),
		string(result.Decision),
		result.RiskScore,
		durationMs,
	)

	return result, nil
}

// runOFACCheck performs OFAC sanctions check
func (e *Engine) runOFACCheck(ctx context.Context, sctx *ScreeningContext) error {
	start := time.Now()

	// Check counterparty name against OFAC list
	counterpartyName := sctx.Transaction.GetCounterpartyName()
	if counterpartyName == "" {
		return nil
	}

	result, err := e.ofacChecker.Check(ctx, counterpartyName)
	if err != nil {
		e.log.Warn("ofac check failed", logger.ErrorField(err))
		return nil // Don't fail screening if OFAC check fails
	}

	durationMs := time.Since(start).Milliseconds()
	result.CheckDurationMs = durationMs

	sctx.mu.Lock()
	sctx.OFACResult = result
	if result.Matched {
		sctx.RiskFactors = append(sctx.RiskFactors, domain.RiskFactor{
			Factor:      "OFAC_MATCH",
			Weight:      50, // Major risk factor
			Description: "Counterparty matches OFAC sanctions list",
			Details:     result.SDNName,
		})
	}
	sctx.mu.Unlock()

	e.log.OFACCheckCompleted(sctx.Transaction.ID.String(), result.Matched, durationMs)

	// Warn if OFAC check exceeds 1ms
	if durationMs > 1 {
		e.log.LatencyWarning("ofac_check", durationMs, 1)
	}

	return nil
}

// runPEPCheck performs PEP database check
func (e *Engine) runPEPCheck(ctx context.Context, sctx *ScreeningContext) error {
	start := time.Now()

	counterpartyName := sctx.Transaction.GetCounterpartyName()
	if counterpartyName == "" {
		return nil
	}

	result, err := e.pepChecker.Check(ctx, counterpartyName)
	if err != nil {
		e.log.Warn("pep check failed", logger.ErrorField(err))
		return nil
	}

	durationMs := time.Since(start).Milliseconds()
	result.CheckDurationMs = durationMs

	sctx.mu.Lock()
	sctx.PEPResult = result
	if result.Matched {
		sctx.RiskFactors = append(sctx.RiskFactors, domain.RiskFactor{
			Factor:      "PEP_MATCH",
			Weight:      30,
			Description: "Counterparty is a Politically Exposed Person",
			Details:     result.PEPPosition,
		})
	}
	sctx.mu.Unlock()

	e.log.PEPCheckCompleted(sctx.Transaction.ID.String(), result.Matched, durationMs)

	return nil
}

// getRiskProfile fetches user risk profile
func (e *Engine) getRiskProfile(ctx context.Context, sctx *ScreeningContext) error {
	profile, err := e.riskProfileRepo.GetByUserID(ctx, sctx.Transaction.UserID)
	if err != nil {
		e.log.Warn("failed to get risk profile", logger.ErrorField(err))
		return nil
	}

	sctx.mu.Lock()
	sctx.RiskProfile = profile

	// Add risk factors based on profile
	if profile.OnWatchlist {
		sctx.RiskFactors = append(sctx.RiskFactors, domain.RiskFactor{
			Factor:      "USER_WATCHLIST",
			Weight:      25,
			Description: "User is on internal watchlist",
			Details:     profile.WatchlistReason,
		})
	}
	if profile.IsPEP {
		sctx.RiskFactors = append(sctx.RiskFactors, domain.RiskFactor{
			Factor:      "USER_PEP",
			Weight:      20,
			Description: "User is a Politically Exposed Person",
		})
	}
	if profile.SARCount > 0 {
		sctx.RiskFactors = append(sctx.RiskFactors, domain.RiskFactor{
			Factor:      "PRIOR_SARS",
			Weight:      15,
			Description: "User has prior SAR filings",
		})
	}
	sctx.mu.Unlock()

	return nil
}

// getVelocityData fetches velocity data from cache
func (e *Engine) getVelocityData(ctx context.Context, sctx *ScreeningContext) error {
	velocity, err := e.velocityCache.GetVelocity(ctx, sctx.Transaction.UserID)
	if err != nil {
		e.log.Debug("no velocity data available", logger.ErrorField(err))
		return nil
	}

	sctx.mu.Lock()
	sctx.VelocityData = velocity
	sctx.mu.Unlock()

	return nil
}

// detectPatterns runs pattern detection
func (e *Engine) detectPatterns(ctx context.Context, sctx *ScreeningContext) error {
	patterns, err := e.patternEngine.DetectPatterns(ctx, sctx.Transaction.UserID, sctx.Transaction)
	if err != nil {
		e.log.Warn("pattern detection failed", logger.ErrorField(err))
		return nil
	}

	sctx.mu.Lock()
	sctx.PatternMatches = patterns
	for _, p := range patterns {
		weight := int(p.Confidence * 30) // Max 30 points for patterns
		sctx.RiskFactors = append(sctx.RiskFactors, domain.RiskFactor{
			Factor:      string(p.PatternType),
			Weight:      weight,
			Description: p.Description,
		})
		e.log.PatternDetected(sctx.Transaction.UserID.String(), string(p.PatternType), p.Confidence)
	}
	sctx.mu.Unlock()

	return nil
}

// calculateResult calculates final risk score and decision
func (e *Engine) calculateResult(sctx *ScreeningContext) *domain.ScreeningResult {
	sctx.mu.Lock()
	defer sctx.mu.Unlock()

	// Calculate base risk score from factors
	riskScore := e.riskCalculator.Calculate(sctx)

	// Build result
	result := &domain.ScreeningResult{
		ID:                  sctx.ScreeningID,
		TransactionID:       sctx.Transaction.ID,
		UserID:              sctx.Transaction.UserID,
		RiskScore:           riskScore,
		RiskLevel:           domain.CalculateRiskLevel(riskScore),
		Decision:            domain.CalculateDecision(riskScore),
		OFACMatch:           sctx.OFACResult,
		PEPMatch:            sctx.PEPResult,
		RiskFactors:         sctx.RiskFactors,
		PatternMatches:      sctx.PatternMatches,
		ScreeningDurationMs: time.Since(sctx.StartTime).Milliseconds(),
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	// Override decision if OFAC match (always block)
	if sctx.OFACResult != nil && sctx.OFACResult.Matched && sctx.OFACResult.MatchType == domain.MatchTypeExact {
		result.Decision = domain.DecisionBlocked
		result.RiskScore = 100
		result.RiskLevel = domain.RiskLevelCritical
	}

	return result
}

// recordLatency records screening latency for metrics
func (e *Engine) recordLatency(durationMs int64) {
	e.latencyMu.Lock()
	defer e.latencyMu.Unlock()

	e.screeningCount++
	// Exponential moving average
	e.avgLatencyMs = e.avgLatencyMs*0.9 + float64(durationMs)*0.1
}

// GetAverageLatency returns the average screening latency
func (e *Engine) GetAverageLatency() float64 {
	e.latencyMu.RLock()
	defer e.latencyMu.RUnlock()
	return e.avgLatencyMs
}

// GetScreeningCount returns total screenings performed
func (e *Engine) GetScreeningCount() int64 {
	e.latencyMu.RLock()
	defer e.latencyMu.RUnlock()
	return e.screeningCount
}
