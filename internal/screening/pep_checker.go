package screening

import (
	"context"
	"sync"
	"time"

	"github.com/banking/aml-service/internal/domain"
	"github.com/banking/aml-service/internal/pkg/logger"
)

// PEPChecker performs Politically Exposed Persons screening
// Target: <5ms per lookup using Redis cache
type PEPChecker struct {
	cache     PEPCache
	log       *logger.Logger
	threshold float64

	// In-memory index for fast lookups
	pepIndex map[string]PEPEntry
	indexMu  sync.RWMutex
}

// PEPCache interface for PEP data caching
type PEPCache interface {
	GetByName(ctx context.Context, name string) (*PEPEntry, error)
	GetByFuzzyName(ctx context.Context, name string, threshold float64) ([]PEPEntry, error)
	GetAllEntries(ctx context.Context) ([]PEPEntry, error)
	SetEntries(ctx context.Context, entries []PEPEntry, ttl time.Duration) error
	GetLastUpdate(ctx context.Context) (time.Time, error)
}

// PEPEntry represents a Politically Exposed Person entry
type PEPEntry struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	NormalizedName string     `json:"normalized_name"`
	Position       string     `json:"position"`
	Country        string     `json:"country"`
	Category       string     `json:"category"` // domestic, foreign, international_org
	RiskLevel      string     `json:"risk_level"`
	StartDate      time.Time  `json:"start_date,omitempty"`
	EndDate        *time.Time `json:"end_date,omitempty"`
	IsActive       bool       `json:"is_active"`
	Aliases        []string   `json:"aliases,omitempty"`
	Associates     []string   `json:"associates,omitempty"` // Family, close associates
}

// NewPEPChecker creates a new PEP checker
func NewPEPChecker(cache PEPCache, log *logger.Logger, threshold float64) *PEPChecker {
	return &PEPChecker{
		cache:     cache,
		log:       log.Named("pep_checker"),
		threshold: threshold,
		pepIndex:  make(map[string]PEPEntry),
	}
}

// Check performs PEP screening against a name
func (c *PEPChecker) Check(ctx context.Context, name string) (*domain.PEPMatch, error) {
	if name == "" {
		return &domain.PEPMatch{Matched: false}, nil
	}

	normalizedName := normalizeName(name)

	// 1. Check in-memory index first (fastest)
	if match, found := c.exactMatch(normalizedName); found {
		riskCategory := c.determineRiskCategory(match)
		return &domain.PEPMatch{
			Matched:      true,
			MatchScore:   1.0,
			MatchType:    domain.MatchTypeExact,
			PEPName:      match.Name,
			PEPPosition:  match.Position,
			PEPCountry:   match.Country,
			RiskCategory: riskCategory,
		}, nil
	}

	// 2. Try cache lookup
	entry, err := c.cache.GetByName(ctx, normalizedName)
	if err == nil && entry != nil {
		riskCategory := c.determineRiskCategory(*entry)
		return &domain.PEPMatch{
			Matched:      true,
			MatchScore:   1.0,
			MatchType:    domain.MatchTypeExact,
			PEPName:      entry.Name,
			PEPPosition:  entry.Position,
			PEPCountry:   entry.Country,
			RiskCategory: riskCategory,
		}, nil
	}

	// 3. Fuzzy match
	fuzzyMatches, err := c.cache.GetByFuzzyName(ctx, normalizedName, c.threshold)
	if err == nil && len(fuzzyMatches) > 0 {
		bestMatch := fuzzyMatches[0]
		similarity := jaroWinkler(normalizedName, bestMatch.NormalizedName)
		riskCategory := c.determineRiskCategory(bestMatch)

		return &domain.PEPMatch{
			Matched:      true,
			MatchScore:   similarity,
			MatchType:    domain.MatchTypeFuzzy,
			PEPName:      bestMatch.Name,
			PEPPosition:  bestMatch.Position,
			PEPCountry:   bestMatch.Country,
			RiskCategory: riskCategory,
		}, nil
	}

	return &domain.PEPMatch{Matched: false}, nil
}

// CheckWithAssociates also checks against known associates
func (c *PEPChecker) CheckWithAssociates(ctx context.Context, name string) (*domain.PEPMatch, []string, error) {
	result, err := c.Check(ctx, name)
	if err != nil {
		return nil, nil, err
	}

	if result.Matched {
		// Get associates
		entry, _ := c.cache.GetByName(ctx, normalizeName(name))
		if entry != nil {
			return result, entry.Associates, nil
		}
	}

	return result, nil, nil
}

// LoadIndex loads PEP list into in-memory index
func (c *PEPChecker) LoadIndex(ctx context.Context) error {
	entries, err := c.cache.GetAllEntries(ctx)
	if err != nil {
		return err
	}

	c.indexMu.Lock()
	defer c.indexMu.Unlock()

	c.pepIndex = make(map[string]PEPEntry, len(entries))
	for _, entry := range entries {
		c.pepIndex[entry.NormalizedName] = entry
		for _, alias := range entry.Aliases {
			c.pepIndex[normalizeName(alias)] = entry
		}
	}

	c.log.Info("pep index loaded", logger.IntField("entries", len(entries)))
	return nil
}

// exactMatch checks the in-memory index
func (c *PEPChecker) exactMatch(normalizedName string) (PEPEntry, bool) {
	c.indexMu.RLock()
	defer c.indexMu.RUnlock()

	entry, found := c.pepIndex[normalizedName]
	return entry, found
}

// determineRiskCategory determines the PEP risk category
func (c *PEPChecker) determineRiskCategory(entry PEPEntry) string {
	// Higher risk for active PEPs and certain positions
	if !entry.IsActive {
		return "FORMER_PEP"
	}

	highRiskPositions := map[string]bool{
		"head of state":      true,
		"head of government": true,
		"minister":           true,
		"military general":   true,
		"senior judge":       true,
	}

	if highRiskPositions[entry.Position] {
		return "HIGH_RISK_PEP"
	}

	if entry.Category == "foreign" {
		return "FOREIGN_PEP"
	}

	return "DOMESTIC_PEP"
}

// PEPCategories returns the list of PEP categories
func PEPCategories() []string {
	return []string{
		"HIGH_RISK_PEP",
		"FOREIGN_PEP",
		"DOMESTIC_PEP",
		"FORMER_PEP",
		"PEP_ASSOCIATE",
	}
}
