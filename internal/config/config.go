package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the AML service
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	Database   DatabaseConfig   `mapstructure:"database"`
	Redis      RedisConfig      `mapstructure:"redis"`
	Kafka      KafkaConfig      `mapstructure:"kafka"`
	Screening  ScreeningConfig  `mapstructure:"screening"`
	Patterns   PatternsConfig   `mapstructure:"patterns"`
	Compliance ComplianceConfig `mapstructure:"compliance"`
	Telemetry  TelemetryConfig  `mapstructure:"telemetry"`
	Security   SecurityConfig   `mapstructure:"security"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Port            int           `mapstructure:"port"`
	MetricsPort     int           `mapstructure:"metrics_port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	MaxRequestSize  int64         `mapstructure:"max_request_size"`
}

// DatabaseConfig holds PostgreSQL configuration
type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	Database        string        `mapstructure:"database"`
	SSLMode         string        `mapstructure:"ssl_mode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	MaxRetries   int           `mapstructure:"max_retries"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	OFACCacheTTL time.Duration `mapstructure:"ofac_cache_ttl"`
	PEPCacheTTL  time.Duration `mapstructure:"pep_cache_ttl"`
	RiskCacheTTL time.Duration `mapstructure:"risk_cache_ttl"`
}

// KafkaConfig holds Kafka configuration
type KafkaConfig struct {
	Brokers          []string `mapstructure:"brokers"`
	ConsumerGroup    string   `mapstructure:"consumer_group"`
	TransactionTopic string   `mapstructure:"transaction_topic"`
	AMLEventsTopic   string   `mapstructure:"aml_events_topic"`
	AlertsTopic      string   `mapstructure:"alerts_topic"`
	AuditTopic       string   `mapstructure:"audit_topic"`
}

// ScreeningConfig holds screening configuration
type ScreeningConfig struct {
	OFACUpdateInterval  time.Duration `mapstructure:"ofac_update_interval"`
	PEPUpdateInterval   time.Duration `mapstructure:"pep_update_interval"`
	MaxScreeningLatency time.Duration `mapstructure:"max_screening_latency"`
	ParallelChecks      int           `mapstructure:"parallel_checks"`
	FuzzyMatchThreshold float64       `mapstructure:"fuzzy_match_threshold"`
}

// PatternsConfig holds pattern detection configuration
type PatternsConfig struct {
	// Structuring detection
	StructuringWindowHours int     `mapstructure:"structuring_window_hours"`
	StructuringThreshold   float64 `mapstructure:"structuring_threshold"`
	StructuringMinTxCount  int     `mapstructure:"structuring_min_tx_count"`

	// Rapid cycling
	RapidCyclingWindowMins int     `mapstructure:"rapid_cycling_window_mins"`
	RapidCyclingThreshold  float64 `mapstructure:"rapid_cycling_threshold"`

	// Velocity
	VelocityBaselineDays    int     `mapstructure:"velocity_baseline_days"`
	VelocitySpikeMultiplier float64 `mapstructure:"velocity_spike_multiplier"`

	// Geographic
	GeoConcentrationThreshold float64  `mapstructure:"geo_concentration_threshold"`
	HighRiskCountries         []string `mapstructure:"high_risk_countries"`

	// Batch processing
	BatchSize     int           `mapstructure:"batch_size"`
	BatchInterval time.Duration `mapstructure:"batch_interval"`
}

// ComplianceConfig holds compliance reporting configuration
type ComplianceConfig struct {
	SARThreshold          float64       `mapstructure:"sar_threshold"`
	CTRThreshold          float64       `mapstructure:"ctr_threshold"`
	SARDeadlineDays       int           `mapstructure:"sar_deadline_days"`
	InvestigationSLA      time.Duration `mapstructure:"investigation_sla"`
	MaxOpenInvestigations int           `mapstructure:"max_open_investigations"`
}

// TelemetryConfig holds observability configuration
type TelemetryConfig struct {
	ServiceName     string  `mapstructure:"service_name"`
	Environment     string  `mapstructure:"environment"`
	OTLPEndpoint    string  `mapstructure:"otlp_endpoint"`
	SamplingRatio   float64 `mapstructure:"sampling_ratio"`
	EnableProfiling bool    `mapstructure:"enable_profiling"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	EncryptionKeys     []string `mapstructure:"encryption_keys"`
	CurrentKeyVersion  int      `mapstructure:"current_key_version"`
	AuditHMACSecret    string   `mapstructure:"audit_hmac_secret"`
	JWTSecret          string   `mapstructure:"jwt_secret"`
	AllowedOrigins     []string `mapstructure:"allowed_origins"`
	RateLimitPerMinute int      `mapstructure:"rate_limit_per_minute"`
}

// Load loads configuration from environment and config files
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Environment variables
	v.SetEnvPrefix("AML_SERVICE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Config file (optional)
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./configs")
	v.AddConfigPath("/etc/aml-service")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
		// Config file not found, use defaults + env
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.port", 8084)
	v.SetDefault("server.metrics_port", 9094)
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.idle_timeout", "60s")
	v.SetDefault("server.shutdown_timeout", "30s")
	v.SetDefault("server.max_request_size", 1048576) // 1MB

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "postgres")
	v.SetDefault("database.database", "aml_db")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("database.max_open_conns", 50)
	v.SetDefault("database.max_idle_conns", 25)
	v.SetDefault("database.conn_max_lifetime", "30m")
	v.SetDefault("database.conn_max_idle_time", "5m")

	// Redis defaults (optimized for low latency)
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 100)
	v.SetDefault("redis.min_idle_conns", 20)
	v.SetDefault("redis.max_retries", 3)
	v.SetDefault("redis.dial_timeout", "5s")
	v.SetDefault("redis.read_timeout", "1s")
	v.SetDefault("redis.write_timeout", "1s")
	v.SetDefault("redis.ofac_cache_ttl", "24h")
	v.SetDefault("redis.pep_cache_ttl", "168h") // 7 days
	v.SetDefault("redis.risk_cache_ttl", "1h")

	// Kafka defaults
	v.SetDefault("kafka.brokers", []string{"localhost:9092"})
	v.SetDefault("kafka.consumer_group", "aml-service-group")
	v.SetDefault("kafka.transaction_topic", "banking.transactions.created")
	v.SetDefault("kafka.aml_events_topic", "banking.aml.events")
	v.SetDefault("kafka.alerts_topic", "banking.aml.alerts")
	v.SetDefault("kafka.audit_topic", "banking.audit.logs")

	// Screening defaults
	v.SetDefault("screening.ofac_update_interval", "24h")
	v.SetDefault("screening.pep_update_interval", "168h") // 7 days
	v.SetDefault("screening.max_screening_latency", "200ms")
	v.SetDefault("screening.parallel_checks", 6)
	v.SetDefault("screening.fuzzy_match_threshold", 0.85)

	// Pattern detection defaults
	v.SetDefault("patterns.structuring_window_hours", 24)
	v.SetDefault("patterns.structuring_threshold", 10000.0)
	v.SetDefault("patterns.structuring_min_tx_count", 3)
	v.SetDefault("patterns.rapid_cycling_window_mins", 60)
	v.SetDefault("patterns.rapid_cycling_threshold", 0.9)
	v.SetDefault("patterns.velocity_baseline_days", 30)
	v.SetDefault("patterns.velocity_spike_multiplier", 10.0)
	v.SetDefault("patterns.geo_concentration_threshold", 0.8)
	v.SetDefault("patterns.high_risk_countries", []string{
		"IR", "KP", "SY", "CU", "VE", "MM", "BY", "RU",
	})
	v.SetDefault("patterns.batch_size", 1000)
	v.SetDefault("patterns.batch_interval", "5m")

	// Compliance defaults
	v.SetDefault("compliance.sar_threshold", 70.0)
	v.SetDefault("compliance.ctr_threshold", 10000.0)
	v.SetDefault("compliance.sar_deadline_days", 30)
	v.SetDefault("compliance.investigation_sla", "72h")
	v.SetDefault("compliance.max_open_investigations", 100)

	// Telemetry defaults
	v.SetDefault("telemetry.service_name", "aml-service")
	v.SetDefault("telemetry.environment", "development")
	v.SetDefault("telemetry.otlp_endpoint", "localhost:4317")
	v.SetDefault("telemetry.sampling_ratio", 0.1)
	v.SetDefault("telemetry.enable_profiling", false)

	// Security defaults
	v.SetDefault("security.current_key_version", 1)
	v.SetDefault("security.rate_limit_per_minute", 1000)
	v.SetDefault("security.allowed_origins", []string{"*"})
}
