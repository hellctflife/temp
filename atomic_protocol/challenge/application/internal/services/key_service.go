package services

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/atomic-protocol/internal/db/models"
	"github.com/atomic-protocol/pkg/metrics"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var (
	ErrInvalidSession = errors.New("invalid session token")
	ErrKeyNotFound    = errors.New("no matching key share found")
	ErrNoKeySet       = errors.New("no key currently set")
	userShare         = make(map[int][]byte)
)

type keyCache struct {
	cache map[int][]byte
	mu    sync.RWMutex
}

func newKeyCache() *keyCache {
	return &keyCache{
		cache: make(map[int][]byte),
	}
}

func (kc *keyCache) get(userID int) ([]byte, bool) {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	share, exists := kc.cache[userID]
	return share, exists
}

func (kc *keyCache) set(userID int, share []byte) {
	kc.mu.Lock()
	defer kc.mu.Unlock()
	kc.cache[userID] = share
}

type KeyService struct {
	db             *gorm.DB
	sessionStore   *SessionStore
	logger         *zap.Logger
	metrics        *metrics.MetricsCollector
	Validations    map[string]map[int]bool
	ValidationLock sync.RWMutex
	keyCache       *keyCache
	stopChan       chan struct{}
}

type SessionStore struct {
	sessions map[string]SessionData
	mutex    sync.RWMutex
}

type SessionData struct {
	UserID    int
	ExpiresAt time.Time
	IPAddress string
	UserAgent string
}

func NewKeyService(db *gorm.DB, logger *zap.Logger, metricsCollector *metrics.MetricsCollector) *KeyService {
	ks := &KeyService{
		db: db,
		sessionStore: &SessionStore{
			sessions: make(map[string]SessionData),
		},
		logger:      logger.With(zap.String("service", "key_service")),
		metrics:     metricsCollector,
		Validations: make(map[string]map[int]bool),
		keyCache:    newKeyCache(),
		stopChan:    make(chan struct{}),
	}

	go ks.startBackgroundCleanup(context.Background())

	return ks
}

func (ks *KeyService) startBackgroundCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ks.stopChan:
				return
			case <-ticker.C:
				ks.cleanupExpiredSessions()
			}
		}
	}()
}

func (ks *KeyService) cleanupExpiredSessions() {
	ks.sessionStore.mutex.Lock()
	defer ks.sessionStore.mutex.Unlock()

	now := time.Now()
	for token, session := range ks.sessionStore.sessions {
		if now.After(session.ExpiresAt) {
			delete(ks.sessionStore.sessions, token)
			ks.metrics.IncrementCounter("key_service.sessions_expired", nil)
		}
	}
}

func (ks *KeyService) parsePrivateKey(shareData []byte, userID uint) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(shareData)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data for user %d", userID)
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key for user %d: %w", userID, err)
	}

	return priv, nil
}

func (ks *KeyService) LoadUserPrivateKey(ctx context.Context, userID uint) (*rsa.PrivateKey, error) {
	shouldDelay, _ := ctx.Value("delay_key_loading").(bool)

	var shares []models.KeyShare
	if err := ks.db.Where("status = ?", "ACTIVE").Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch key shares, %w", err)
	}

	if len(shares) == 0 {
		return nil, ErrKeyNotFound
	}

	resultChan := make(chan *models.KeyShare, len(shares))
	matchingShares := 0

	for _, share := range shares {
		ks.keyCache.set(int(userID), share.EncryptedShare)

		if share.UserID == userID {
			matchingShares++
			go func(s models.KeyShare) {
				ks.logger.Info("Decrypting share for user",
					zap.Uint("user_id", s.UserID),
					zap.Bool("delayed_loading", shouldDelay))
				resultChan <- &s
			}(share)
			break
		}

		if shouldDelay {
			time.Sleep(3 * time.Second)
		}
	}

	if matchingShares == 0 {
		return nil, ErrKeyNotFound
	}

	select {
	case s := <-resultChan:
		return ks.parsePrivateKey(s.EncryptedShare, userID)
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("key share load timed out")
	}
}

func (ks *KeyService) CreateSessionToken(ctx context.Context, userID int, ipAddress, userAgent string) (string, error) {
	token := uuid.New().String()
	ks.sessionStore.mutex.Lock()
	ks.sessionStore.sessions[token] = SessionData{
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}
	ks.sessionStore.mutex.Unlock()

	ks.logger.Info("Created new session",
		zap.Int("user_id", userID),
		zap.String("token", token[:8]+"..."),
		zap.String("ip_address", ipAddress),
	)
	return token, nil
}

func (ks *KeyService) getSessionData(token string) (SessionData, error) {
	ks.sessionStore.mutex.RLock()
	sd, exists := ks.sessionStore.sessions[token]
	ks.sessionStore.mutex.RUnlock()
	if !exists || time.Now().After(sd.ExpiresAt) {
		return SessionData{}, ErrInvalidSession
	}
	return sd, nil
}

func (ks *KeyService) ValidateOperation(ctx context.Context, sessionToken, operationID string) (bool, error) {
	start := time.Now()
	defer func() {
		ks.metrics.ObserveLatency("key_service.validate_operation", time.Since(start))
	}()

	validationChan := make(chan int, 1)
	errorChan := make(chan error, 1)

	go func() {
		sd, err := ks.getSessionData(sessionToken)
		if err != nil {
			errorChan <- ErrInvalidSession
			return
		}
		validationChan <- sd.UserID
	}()

	var userID int
	select {
	case err := <-errorChan:
		return false, err
	case userID = <-validationChan:
	case <-time.After(2 * time.Second):
		return false, fmt.Errorf("session validation timed out")
	case <-ctx.Done():
		return false, ctx.Err()
	}

	ks.ValidationLock.Lock()
	if _, ok := ks.Validations[operationID]; !ok {
		ks.Validations[operationID] = make(map[int]bool)
	}
	ks.Validations[operationID][userID] = true
	count := len(ks.Validations[operationID])

	complete := count >= 7
	if complete {
		delete(ks.Validations, operationID)
	}
	ks.ValidationLock.Unlock()

	go func() {
		ks.logger.Info("Operation validated",
			zap.String("operation_id", operationID),
			zap.Int("count", count),
			zap.Bool("complete", complete))

		if complete {
			ks.metrics.IncrementCounter("key_service.validate_operation.complete", nil)
		} else {
			ks.metrics.IncrementCounter("key_service.validate_operation.partial", nil)
		}
	}()

	return complete, nil
}

func (ks *KeyService) IsValidSession(token string) (int, bool) {
	sd, err := ks.getSessionData(token)
	if err != nil {
		return 0, false
	}
	return sd.UserID, true
}

func (ks *KeyService) UsePrivateKey(userID int) (*rsa.PrivateKey, error) {
	if share, exists := ks.keyCache.get(userID); exists {
		return ks.parsePrivateKey(share, uint(userID))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ks.logger.Info("Loading user private key from database ...", zap.Int("user_id", userID))
	priv, err := ks.LoadUserPrivateKey(ctx, uint(userID))
	if err != nil {
		return nil, err
	}

	return priv, nil
}
