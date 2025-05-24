package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

type Configuration struct {
	Server   ServerConfig   `json:"server"`
	Security SecurityConfig `json:"security"`
	Logging  LoggingConfig  `json:"logging"`
	Key      KeyConfig      `json:"key"`
	Database DatabaseConfig `json:"database"`
}

type ServerConfig struct {
	Port         string        `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

type SecurityConfig struct {
	CookieSecret       string        `json:"cookie_secret"`
	SessionTimeout     time.Duration `json:"session_timeout"`
	PasswordMinLength  int           `json:"password_min_length"`
	PasswordMaxLength  int           `json:"password_max_length"`
	MaxFailedAttempts  int           `json:"max_failed_attempts"`
	LockoutDuration    time.Duration `json:"lockout_duration"`
	CSRFProtection     bool          `json:"csrf_protection"`
	EncryptionEnabled  bool          `json:"encryption_enabled"`
	EncryptionKey      string        `json:"encryption_key"`
	AdminResetInterval time.Duration `json:"admin_reset_interval"`
}

type LoggingConfig struct {
	Level        string `json:"level"`
	FilePath     string `json:"file_path"`
	ConsoleLevel string `json:"console_level"`
	FileLevel    string `json:"file_level"`
	Format       string `json:"format"`
}

type KeyConfig struct {
	TotalShares     int           `json:"total_shares"`
	Threshold       int           `json:"threshold"`
	KeyBits         int           `json:"key_bits"`
	RotationEnabled bool          `json:"rotation_enabled"`
	RotationPeriod  time.Duration `json:"rotation_period"`
}

type DatabaseConfig struct {
	Host            string `json:"host"`
	Port            string `json:"port"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	Name            string `json:"name"`
	SSLMode         string `json:"ssl_mode"`
	MaxIdleConns    int    `json:"max_idle_conns"`
	MaxOpenConns    int    `json:"max_open_conns"`
	ConnMaxLifetime int    `json:"conn_max_lifetime"`
}

var (
	config     *Configuration
	configOnce sync.Once
	configLock sync.RWMutex
)

func LoadConfig(filePath string) (*Configuration, error) {
	var err error
	
	configOnce.Do(func() {
		var file *os.File
		file, err = os.Open(filePath)
		if err != nil {
			err = fmt.Errorf("failed to open config file: %w", err)
			return
		}
		defer file.Close()
		
		decoder := json.NewDecoder(file)
		config = &Configuration{}
		err = decoder.Decode(config)
		if err != nil {
			err = fmt.Errorf("failed to decode config file: %w", err)
			return
		}
		
		if config.Server.Port == "" {
			config.Server.Port = "8000"
		}
		if config.Server.ReadTimeout == 0 {
			config.Server.ReadTimeout = 10 * time.Second
		}
		if config.Server.WriteTimeout == 0 {
			config.Server.WriteTimeout = 30 * time.Second
		}
		if config.Server.IdleTimeout == 0 {
			config.Server.IdleTimeout = 120 * time.Second
		}
		
		if config.Key.TotalShares == 0 {
			config.Key.TotalShares = 7
		}
		if config.Key.Threshold == 0 {
			config.Key.Threshold = 3
		}
		if config.Key.KeyBits == 0 {
			config.Key.KeyBits = 2048
		}
	})
	
	return config, err
}

func GetConfig() *Configuration {
	configLock.RLock()
	defer configLock.RUnlock()
	return config
}

func UpdateConfig(updater func(*Configuration)) {
	configLock.Lock()
	defer configLock.Unlock()
	updater(config)
}

func InitializeDefaultConfig() *Configuration {
	configLock.Lock()
	defer configLock.Unlock()
	
	config = &Configuration{
		Server: ServerConfig{
			Port:         "8000",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
		Security: SecurityConfig{
			CookieSecret:       "atomic-protocol-secret-key",
			SessionTimeout:     24 * time.Hour,
			PasswordMinLength:  8,
			PasswordMaxLength:  64,
			MaxFailedAttempts:  5,
			LockoutDuration:    15 * time.Minute,
			CSRFProtection:     true,
			EncryptionEnabled:  true,
			EncryptionKey:      "default-encryption-key",
			AdminResetInterval: 72 * time.Hour,
		},
		Logging: LoggingConfig{
			Level:        "info",
			FilePath:     "logs/atomic-protocol.log",
			ConsoleLevel: "info",
			FileLevel:    "debug",
			Format:       "json",
		},
		Key: KeyConfig{
			TotalShares:     7,
			Threshold:       3,
			KeyBits:         2048,
			RotationEnabled: false,
			RotationPeriod:  720 * time.Hour,
		},
		Database: DatabaseConfig{
			Host:            "localhost",
			Port:            "5432",
			Username:        "postgres",
			Password:        "password",
			Name:            "atomic_protocol",
			SSLMode:         "disable",
			MaxIdleConns:    10,
			MaxOpenConns:    100,
			ConnMaxLifetime: 300,
		},
	}
	
	return config
}

func LogConfig(logger *zap.Logger) {
	configLock.RLock()
	defer configLock.RUnlock()
	
	redactedConfig := *config
	redactedConfig.Security.CookieSecret = "[REDACTED]"
	redactedConfig.Security.EncryptionKey = "[REDACTED]"
	redactedConfig.Database.Password = "[REDACTED]"
	
	logger.Info("Application configuration",
		zap.String("port", redactedConfig.Server.Port),
		zap.Duration("read_timeout", redactedConfig.Server.ReadTimeout),
		zap.Duration("write_timeout", redactedConfig.Server.WriteTimeout),
		zap.Int("key_shares", redactedConfig.Key.TotalShares),
		zap.Int("threshold", redactedConfig.Key.Threshold),
		zap.Int("key_bits", redactedConfig.Key.KeyBits),
		zap.Bool("rotation_enabled", redactedConfig.Key.RotationEnabled),
		zap.String("database_host", redactedConfig.Database.Host),
		zap.String("database_name", redactedConfig.Database.Name),
	)
}