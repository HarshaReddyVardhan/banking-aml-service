package screening

import (
	"context"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/banking/aml-service/internal/domain"
	"github.com/banking/aml-service/internal/pkg/logger"
)

// OFACChecker performs OFAC sanctions list screening
// Target: <1ms per lookup using Redis cache
type OFACChecker struct {
	cache     OFACCache
	log       *logger.Logger
	threshold float64 // Fuzzy match threshold (e.g., 0.85)

	// In-memory index for fast exact match (loaded from Redis)
	exactIndex map[string]OFACEntry
	indexMu    sync.RWMutex
}

// OFACCache interface for OFAC data caching
type OFACCache interface {
	GetByExactName(ctx context.Context, name string) (*OFACEntry, error)
	GetByFuzzyName(ctx context.Context, name string, threshold float64) ([]OFACEntry, error)
	GetAllEntries(ctx context.Context) ([]OFACEntry, error)
	SetEntries(ctx context.Context, entries []OFACEntry, ttl time.Duration) error
	GetLastUpdate(ctx context.Context) (time.Time, error)
	SetLastUpdate(ctx context.Context, t time.Time) error
}

// OFACEntry represents an entry from the OFAC SDN list
type OFACEntry struct {
	EntityID       string   `json:"entity_id"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`    // Individual, Entity, Vessel, Aircraft
	Program        string   `json:"program"` // SDGT, SDNT, etc.
	Aliases        []string `json:"aliases"`
	Addresses      []string `json:"addresses,omitempty"`
	Remarks        string   `json:"remarks,omitempty"`
	NormalizedName string   `json:"normalized_name"`
}

// NewOFACChecker creates a new OFAC checker
func NewOFACChecker(cache OFACCache, log *logger.Logger, threshold float64) *OFACChecker {
	return &OFACChecker{
		cache:      cache,
		log:        log.Named("ofac_checker"),
		threshold:  threshold,
		exactIndex: make(map[string]OFACEntry),
	}
}

// Check performs OFAC screening against a name
func (c *OFACChecker) Check(ctx context.Context, name string) (*domain.OFACMatch, error) {
	if name == "" {
		return &domain.OFACMatch{Matched: false}, nil
	}

	normalizedName := normalizeName(name)

	// 1. Try exact match first (fastest, <0.1ms)
	if match, found := c.exactMatch(normalizedName); found {
		return &domain.OFACMatch{
			Matched:      true,
			MatchScore:   1.0,
			MatchType:    domain.MatchTypeExact,
			SDNName:      match.Name,
			SDNType:      match.Type,
			Program:      match.Program,
			MatchedField: "name",
		}, nil
	}

	// 2. Try cache lookup (should be <1ms)
	entry, err := c.cache.GetByExactName(ctx, normalizedName)
	if err == nil && entry != nil {
		return &domain.OFACMatch{
			Matched:      true,
			MatchScore:   1.0,
			MatchType:    domain.MatchTypeExact,
			SDNName:      entry.Name,
			SDNType:      entry.Type,
			Program:      entry.Program,
			MatchedField: "name",
		}, nil
	}

	// 3. Fuzzy match (slightly slower, but still <5ms)
	fuzzyMatches, err := c.cache.GetByFuzzyName(ctx, normalizedName, c.threshold)
	if err == nil && len(fuzzyMatches) > 0 {
		// Return best match
		bestMatch := fuzzyMatches[0]
		similarity := jaroWinkler(normalizedName, bestMatch.NormalizedName)

		return &domain.OFACMatch{
			Matched:      true,
			MatchScore:   similarity,
			MatchType:    domain.MatchTypeFuzzy,
			SDNName:      bestMatch.Name,
			SDNType:      bestMatch.Type,
			Program:      bestMatch.Program,
			MatchedField: "name",
		}, nil
	}

	// No match found
	return &domain.OFACMatch{Matched: false}, nil
}

// CheckBatch performs OFAC screening on multiple names concurrently
func (c *OFACChecker) CheckBatch(ctx context.Context, names []string) (map[string]*domain.OFACMatch, error) {
	results := make(map[string]*domain.OFACMatch)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, name := range names {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			result, err := c.Check(ctx, n)
			if err != nil {
				c.log.Warn("batch ofac check failed for name", logger.ErrorField(err))
				return
			}
			mu.Lock()
			results[n] = result
			mu.Unlock()
		}(name)
	}

	wg.Wait()
	return results, nil
}

// LoadIndex loads OFAC list into in-memory index for fastest lookups
func (c *OFACChecker) LoadIndex(ctx context.Context) error {
	entries, err := c.cache.GetAllEntries(ctx)
	if err != nil {
		return err
	}

	c.indexMu.Lock()
	defer c.indexMu.Unlock()

	c.exactIndex = make(map[string]OFACEntry, len(entries))
	for _, entry := range entries {
		// Index by normalized name
		c.exactIndex[entry.NormalizedName] = entry
		// Also index by aliases
		for _, alias := range entry.Aliases {
			c.exactIndex[normalizeName(alias)] = entry
		}
	}

	c.log.Info("ofac index loaded", logger.IntField("entries", len(entries)))
	return nil
}

// exactMatch checks the in-memory index
func (c *OFACChecker) exactMatch(normalizedName string) (OFACEntry, bool) {
	c.indexMu.RLock()
	defer c.indexMu.RUnlock()

	entry, found := c.exactIndex[normalizedName]
	return entry, found
}

// normalizeName normalizes a name for comparison
func normalizeName(name string) string {
	// Convert to lowercase
	name = strings.ToLower(name)

	// Remove common prefixes/suffixes
	prefixes := []string{"mr.", "mrs.", "ms.", "dr.", "prof."}
	for _, prefix := range prefixes {
		name = strings.TrimPrefix(name, prefix)
	}

	// Remove non-alphanumeric characters except spaces
	var result strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == ' ' {
			result.WriteRune(r)
		}
	}

	// Normalize whitespace
	return strings.Join(strings.Fields(result.String()), " ")
}

// jaroWinkler calculates Jaro-Winkler similarity between two strings
// Returns value between 0 (no match) and 1 (exact match)
func jaroWinkler(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Calculate Jaro distance
	matchDistance := max(len(s1), len(s2))/2 - 1
	if matchDistance < 0 {
		matchDistance = 0
	}

	s1Matches := make([]bool, len(s1))
	s2Matches := make([]bool, len(s2))

	matches := 0
	transpositions := 0

	for i := 0; i < len(s1); i++ {
		start := max(0, i-matchDistance)
		end := min(i+matchDistance+1, len(s2))

		for j := start; j < end; j++ {
			if s2Matches[j] || s1[i] != s2[j] {
				continue
			}
			s1Matches[i] = true
			s2Matches[j] = true
			matches++
			break
		}
	}

	if matches == 0 {
		return 0.0
	}

	k := 0
	for i := 0; i < len(s1); i++ {
		if !s1Matches[i] {
			continue
		}
		for !s2Matches[k] {
			k++
		}
		if s1[i] != s2[k] {
			transpositions++
		}
		k++
	}

	jaro := (float64(matches)/float64(len(s1)) +
		float64(matches)/float64(len(s2)) +
		float64(matches-transpositions/2)/float64(matches)) / 3.0

	// Calculate Winkler adjustment (prefix bonus)
	prefix := 0
	for i := 0; i < min(4, min(len(s1), len(s2))); i++ {
		if s1[i] == s2[i] {
			prefix++
		} else {
			break
		}
	}

	return jaro + float64(prefix)*0.1*(1.0-jaro)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
