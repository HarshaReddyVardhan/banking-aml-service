package logger

import (
	"context"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger wraps zap.Logger with AML-specific functionality
type Logger struct {
	*zap.Logger
	serviceName string
}

// ContextKey for request context values
type ContextKey string

const (
	RequestIDKey     ContextKey = "request_id"
	UserIDKey        ContextKey = "user_id"
	TraceIDKey       ContextKey = "trace_id"
	SpanIDKey        ContextKey = "span_id"
	InvestigationKey ContextKey = "investigation_id"
)

// New creates a new logger instance
func New(serviceName, environment string, debug bool) (*Logger, error) {
	var config zap.Config

	if environment == "production" {
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	if debug {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	// Add service metadata
	config.InitialFields = map[string]interface{}{
		"service": serviceName,
		"env":     environment,
		"pid":     os.Getpid(),
	}

	zapLogger, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zap.ErrorLevel),
	)
	if err != nil {
		return nil, err
	}

	return &Logger{
		Logger:      zapLogger,
		serviceName: serviceName,
	}, nil
}

// Named returns a named sub-logger
func (l *Logger) Named(name string) *Logger {
	return &Logger{
		Logger:      l.Logger.Named(name),
		serviceName: l.serviceName,
	}
}

// WithContext returns a logger with context values
func (l *Logger) WithContext(ctx context.Context) *Logger {
	fields := []zap.Field{}

	if requestID, ok := ctx.Value(RequestIDKey).(string); ok && requestID != "" {
		fields = append(fields, zap.String("request_id", requestID))
	}
	if userID, ok := ctx.Value(UserIDKey).(string); ok && userID != "" {
		fields = append(fields, zap.String("user_id", userID))
	}
	if traceID, ok := ctx.Value(TraceIDKey).(string); ok && traceID != "" {
		fields = append(fields, zap.String("trace_id", traceID))
	}
	if spanID, ok := ctx.Value(SpanIDKey).(string); ok && spanID != "" {
		fields = append(fields, zap.String("span_id", spanID))
	}
	if investigationID, ok := ctx.Value(InvestigationKey).(string); ok && investigationID != "" {
		fields = append(fields, zap.String("investigation_id", investigationID))
	}

	return &Logger{
		Logger:      l.With(fields...),
		serviceName: l.serviceName,
	}
}

// WithTransaction returns a logger with transaction context
func (l *Logger) WithTransaction(txID, userID string) *Logger {
	return &Logger{
		Logger: l.With(
			zap.String("transaction_id", txID),
			zap.String("user_id", userID),
		),
		serviceName: l.serviceName,
	}
}

// WithScreening returns a logger with screening context
func (l *Logger) WithScreening(screeningID, txID string) *Logger {
	return &Logger{
		Logger: l.With(
			zap.String("screening_id", screeningID),
			zap.String("transaction_id", txID),
		),
		serviceName: l.serviceName,
	}
}

// WithInvestigation returns a logger with investigation context
func (l *Logger) WithInvestigation(investigationID, caseNumber string) *Logger {
	return &Logger{
		Logger: l.With(
			zap.String("investigation_id", investigationID),
			zap.String("case_number", caseNumber),
		),
		serviceName: l.serviceName,
	}
}

// ScreeningStarted logs the start of a screening operation
func (l *Logger) ScreeningStarted(txID, userID string) {
	l.Info("screening started",
		zap.String("transaction_id", txID),
		zap.String("user_id", userID),
	)
}

// ScreeningCompleted logs the completion of a screening operation
func (l *Logger) ScreeningCompleted(txID string, decision string, riskScore int, durationMs int64) {
	l.Info("screening completed",
		zap.String("transaction_id", txID),
		zap.String("decision", decision),
		zap.Int("risk_score", riskScore),
		zap.Int64("duration_ms", durationMs),
	)
}

// OFACCheckCompleted logs OFAC check result
func (l *Logger) OFACCheckCompleted(txID string, matched bool, durationMs int64) {
	l.Info("ofac check completed",
		zap.String("transaction_id", txID),
		zap.Bool("matched", matched),
		zap.Int64("duration_ms", durationMs),
	)
}

// PEPCheckCompleted logs PEP check result
func (l *Logger) PEPCheckCompleted(txID string, matched bool, durationMs int64) {
	l.Info("pep check completed",
		zap.String("transaction_id", txID),
		zap.Bool("matched", matched),
		zap.Int64("duration_ms", durationMs),
	)
}

// PatternDetected logs a detected pattern
func (l *Logger) PatternDetected(userID, patternType string, confidence float64) {
	l.Warn("suspicious pattern detected",
		zap.String("user_id", userID),
		zap.String("pattern_type", patternType),
		zap.Float64("confidence", confidence),
	)
}

// InvestigationCreated logs investigation creation
func (l *Logger) InvestigationCreated(investigationID, caseNumber, userID string) {
	l.Info("investigation created",
		zap.String("investigation_id", investigationID),
		zap.String("case_number", caseNumber),
		zap.String("user_id", userID),
	)
}

// SARFiled logs SAR filing
func (l *Logger) SARFiled(filingID, filingNumber, userID string) {
	l.Info("sar filed",
		zap.String("filing_id", filingID),
		zap.String("filing_number", filingNumber),
		zap.String("user_id", userID),
	)
}

// CTRFiled logs CTR filing
func (l *Logger) CTRFiled(filingID, filingNumber, userID string, amount float64) {
	l.Info("ctr filed",
		zap.String("filing_id", filingID),
		zap.String("filing_number", filingNumber),
		zap.String("user_id", userID),
		zap.Float64("amount", amount),
	)
}

// AlertCreated logs alert creation
func (l *Logger) AlertCreated(alertID, alertType, userID string, riskScore int) {
	l.Warn("alert created",
		zap.String("alert_id", alertID),
		zap.String("alert_type", alertType),
		zap.String("user_id", userID),
		zap.Int("risk_score", riskScore),
	)
}

// LatencyWarning logs when a check exceeds expected latency
func (l *Logger) LatencyWarning(checkType string, durationMs, thresholdMs int64) {
	l.Warn("latency threshold exceeded",
		zap.String("check_type", checkType),
		zap.Int64("duration_ms", durationMs),
		zap.Int64("threshold_ms", thresholdMs),
	)
}

// Helper field functions

// ErrorField creates an error field
func ErrorField(err error) zap.Field {
	return zap.Error(err)
}

// DurationField creates a duration field
func DurationField(name string, d time.Duration) zap.Field {
	return zap.Duration(name, d)
}

// StringField creates a string field
func StringField(key, value string) zap.Field {
	return zap.String(key, value)
}

// IntField creates an int field
func IntField(key string, value int) zap.Field {
	return zap.Int(key, value)
}

// Float64Field creates a float64 field
func Float64Field(key string, value float64) zap.Field {
	return zap.Float64(key, value)
}

// BoolField creates a bool field
func BoolField(key string, value bool) zap.Field {
	return zap.Bool(key, value)
}
