package db

import (
	"fmt"
	"log"
	"time"

	"github.com/atomic-protocol/internal/config"
	"github.com/atomic-protocol/internal/db/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	DB *gorm.DB
)

func Initialize(cfg *config.Configuration) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		cfg.Database.Host,
		cfg.Database.Username,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.Port,
		cfg.Database.SSLMode,
	)

	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := DB.DB()
	if err != nil {
		return nil, err
	}
	
	sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.Database.ConnMaxLifetime) * time.Second)

	err = runMigrations(DB)
	if err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return DB, nil
}

func runMigrations(db *gorm.DB) error {
	log.Println("Running database migrations...")
	
	return db.AutoMigrate(
		&models.User{},
		&models.KeyShare{},
		&models.Document{},
		&models.Certificate{},
		&models.DocumentSignature{},
	)
}