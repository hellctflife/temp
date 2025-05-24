package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atomic-protocol/internal/api"
	"github.com/atomic-protocol/internal/config"
	"github.com/atomic-protocol/internal/db"
	"github.com/atomic-protocol/internal/db/models"
	"github.com/atomic-protocol/internal/services"
	"github.com/atomic-protocol/pkg/logger"
	"github.com/atomic-protocol/pkg/metrics"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func main() {
	cfg := config.InitializeDefaultConfig()

	zapLogger, err := logger.NewLogger(cfg.Logging.Level)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer zapLogger.Sync()
	zap.ReplaceGlobals(zapLogger)

	config.LogConfig(zapLogger)

	database, err := db.Initialize(cfg)
	if err != nil {
		zapLogger.Fatal("Failed to initialize database", zap.Error(err))
	}

	metricsCollector := metrics.NewMetricsCollector()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := seedDatabase(ctx, database, zapLogger); err != nil {
		zapLogger.Fatal("Failed to seed database", zap.Error(err))
	}

	keyService := services.NewKeyService(database, zapLogger, metricsCollector)
	documentService := services.NewDocumentService(database, keyService, zapLogger, metricsCollector)
	certificateService := services.NewCertificateService(keyService, database, zapLogger)

	router := api.NewRouter(zapLogger, metricsCollector, keyService, documentService, certificateService, database)
	router.SetupRoutes()

	port := os.Getenv("PORT")
	if port == "" {
		port = cfg.Server.Port
	}
	go func() {
		if err := router.Run(":" + port); err != nil {
			zapLogger.Fatal("Failed to start server", zap.Error(err))
		}
	}()
	zapLogger.Info("Server started", zap.String("port", port))

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	zapLogger.Info("Shutting down server...")

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ctxShutdown

	sqlDB, err := db.DB.DB()
	if err == nil {
		sqlDB.Close()
	}
	zapLogger.Info("Server gracefully stopped")
}

func seedDatabase(ctx context.Context, database *gorm.DB, logger *zap.Logger) error {
	var count int64
	database.Model(&models.User{}).Count(&count)
	if count > 0 {
		logger.Info("Database already seeded, skipping")
		return nil
	}
	logger.Info("Seeding database with initial data")

	users := []models.User{
		{Username: "agent1", Email: "agent1@volnaya.gov", PasswordHash: "$2y$10$DY3nZ5wOLS8zpEMigxr9d.SLJH7pmt/3eirjo76V.U6Aw4rppb8dq", Role: models.RoleAgent, FirstName: "Agent", LastName: "A", Department: "Operations", ActiveStatus: true},
		{Username: "agent2", Email: "agent2@volnaya.gov", PasswordHash: "$2y$10$DY3nZ5wOLS8zpEMigxr9d.SLJH7pmt/3eirjo76V.U6Aw4rppb8dq", Role: models.RoleAgent, FirstName: "Agent", LastName: "B", Department: "Operations", ActiveStatus: true},
		{Username: "agent3", Email: "agent3@volnaya.gov", PasswordHash: "$2y$10$DY3nZ5wOLS8zpEMigxr9d.SLJH7pmt/3eirjo76V.U6Aw4rppb8dq", Role: models.RoleAgent, FirstName: "Agent", LastName: "C", Department: "Operations", ActiveStatus: true},
		{Username: "director", Email: "director@volnaya.gov", PasswordHash: "$2y$10$55xxmTYXn7.5ya6YYz6RAesK6kCL3lZK0BaUuMjcNH9ViXZ9/6IwK", Role: models.RoleAdmin, FirstName: "Director", LastName: "G", Department: "Command", ActiveStatus: true},
		{Username: "agent4", Email: "agent4@volnaya.gov", PasswordHash: "$2y$10$DY3nZ5wOLS8zpEMigxr9d.SLJH7pmt/3eirjo76V.U6Aw4rppb8dq", Role: models.RoleAgent, FirstName: "Agent", LastName: "D", Department: "Operations", ActiveStatus: true},
		{Username: "agent5", Email: "agent5@volnaya.gov", PasswordHash: "$2y$10$DY3nZ5wOLS8zpEMigxr9d.SLJH7pmt/3eirjo76V.U6Aw4rppb8dq", Role: models.RoleAgent, FirstName: "Agent", LastName: "E", Department: "Operations", ActiveStatus: true},
		{Username: "agent6", Email: "agent6@volnaya.gov", PasswordHash: "$2y$10$DY3nZ5wOLS8zpEMigxr9d.SLJH7pmt/3eirjo76V.U6Aw4rppb8dq", Role: models.RoleAgent, FirstName: "Agent", LastName: "F", Department: "Operations", ActiveStatus: true},
	}

	if err := database.Create(&users).Error; err != nil {
		return err
	}
	logger.Info("Created initial users", zap.Int("count", len(users)))

	for _, u := range users {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

		share := models.KeyShare{
			UserID:         u.ID,
			EncryptedShare: privPEM,
			ShareIndex:     1,
			Version:        1,
			Status:         "ACTIVE",
		}
		if err := database.Create(&share).Error; err != nil {
			return err
		}
		logger.Info("Stored RSA key for user", zap.String("username", u.Username), zap.Uint("user_id", u.ID))
	}

	logger.Info("Database seeding completed successfully")
	return nil
}
