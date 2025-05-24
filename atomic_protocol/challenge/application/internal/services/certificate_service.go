package services

import (
    "context"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "strconv"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "encoding/base64"
    "errors"
    "fmt"
    "time"
    "strings"

    "github.com/atomic-protocol/internal/db/models"
    "github.com/google/uuid"
    "go.uber.org/zap"
    "gorm.io/gorm"
)

var (
    ErrCertificateNotFound = errors.New("certificate not found")
    ErrCertificateExpired  = errors.New("certificate has expired")
    ErrCertificateRevoked  = errors.New("certificate has been revoked")
    ErrBadSignature       = errors.New("invalid signature")
)

type CertificateService struct {
    keyService *KeyService
    db         *gorm.DB
    logger     *zap.Logger
}

func NewCertificateService(keyService *KeyService, db *gorm.DB, logger *zap.Logger) *CertificateService {
    return &CertificateService{
        keyService: keyService,
        db:         db,
        logger:     logger.With(zap.String("service", "certificate_service")),
    }
}

func (cs *CertificateService) CreateCertificate(ctx context.Context, sessionToken, subject string, validFor time.Duration) (*models.Certificate, error) {
    sessionData, err := cs.keyService.getSessionData(sessionToken)
    if err != nil {
        return nil, ErrInvalidSession
    }
    userID := uint(sessionData.UserID)

    subject = strings.ReplaceAll(subject, " ", "")
    subject = strings.ReplaceAll(subject, "-", "")

    certID := uuid.New().String()
    certData := fmt.Sprintf("CERTIFICATE-DATA|%s", subject)

    privKey, err := cs.keyService.UsePrivateKey(int(userID))
    if err != nil {
        cs.logger.Error("failed to load user key for certificate", zap.Uint("user_id", userID), zap.Error(err))
        return nil, err
    }

    hash := sha256.Sum256([]byte(certData))
    sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
    if err != nil {
        cs.logger.Error("failed to sign certificate", zap.Error(err))
        return nil, fmt.Errorf("failed to sign certificate: %w", err)
    }

    certData = fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", base64.StdEncoding.EncodeToString([]byte(certData + "|" + base64.StdEncoding.EncodeToString(sigBytes))))

    cert := &models.Certificate{
        ID:               certID,
        UserID:           userID,
        Subject:          subject,
        Data:             certData,
        Signature:        base64.StdEncoding.EncodeToString(sigBytes),
        IssuedAt:         time.Now(),
        ExpiresAt:        time.Now().Add(validFor),
        Status:           "VALID",
        RevocationDate:   nil,
        RevocationReason: "",
    }
    if err := cs.db.Create(cert).Error; err != nil {
        return nil, err
    }

    cs.logger.Info("Certificate created",
        zap.String("cert_id", certID),
        zap.Uint("user_id", userID),
        zap.String("subject", subject),
    )
    return cert, nil
}

func (cs *CertificateService) GetCertificate(ctx context.Context, certID string) (*models.Certificate, error) {
    var cert models.Certificate
    if err := cs.db.First(&cert, "id = ?", certID).Error; err != nil {
        return nil, ErrCertificateNotFound
    }
    return &cert, nil
}

func (cs *CertificateService) VerifyCertificate(ctx context.Context, certID string) (bool, error) {
    cert, err := cs.GetCertificate(ctx, certID)
    if err != nil {
        return false, err
    }
    if cert.Status == "REVOKED" {
        return false, ErrCertificateRevoked
    }
    if time.Now().After(cert.ExpiresAt) {
        return false, ErrCertificateExpired
    }
    return true, nil
}

func (cs *CertificateService) RevokeCertificate(ctx context.Context, sessionToken, certID, reason string) error {
    sessionData, err := cs.keyService.getSessionData(sessionToken)
    if err != nil {
        return ErrInvalidSession
    }
    userID := sessionData.UserID

    var cert models.Certificate
    if err := cs.db.First(&cert, "id = ?", certID).Error; err != nil {
        return ErrCertificateNotFound
    }

    if int(cert.UserID) != userID && !cs.isAdmin(userID) {
        return errors.New("permission denied")
    }

    now := time.Now()
    cert.Status = "REVOKED"
    cert.RevocationDate = &now
    cert.RevocationReason = reason

    if err := cs.db.Save(&cert).Error; err != nil {
        return err
    }

    cs.logger.Info("Certificate revoked",
        zap.String("cert_id", certID),
        zap.Int("user_id", userID),
        zap.String("reason", reason),
    )
    return nil
}

func (cs *CertificateService) GetRawCertificatePEM(certID string) string {
    var cert models.Certificate
    if err := cs.db.First(&cert, "id = ?", certID).Error; err != nil {
        cs.logger.Warn("GetRawCertificatePEM: certificate not found", zap.String("cert_id", certID))
        return ""
    }
    return cert.Data
}

func (cs *CertificateService) isAdmin(userID int) bool {
    var user models.User
    if err := cs.db.First(&user, userID).Error; err != nil {
        return false
    }
    return user.Role == models.RoleAdmin
}

func (cs *CertificateService) ValidateCertificate(data string, signature string) (string, error) {
    sig, err := base64.StdEncoding.DecodeString(signature)
    if err != nil {
        return "", ErrBadSignature
    }

    digest := sha256.Sum256([]byte(data))

    var shares[] models.KeyShare
    if err := cs.db.Where("status = ?", "ACTIVE").Find(&shares).Error; err != nil {
        return "", fmt.Errorf("failed to fetch key shares")
    }
    if len(shares) == 0 {
        return "", ErrKeyNotFound
    }

    resultChan := make(chan string, len(shares))
    errorChan := make(chan error, len(shares))

    for _, share := range shares {
        go func(s models.KeyShare) {
            block, _ := pem.Decode(s.EncryptedShare)
            if block == nil {
                errorChan <- errors.New("invalid PEM block")
                return
            }

            var pubKey *rsa.PublicKey
            switch block.Type {
            case "RSA PUBLIC KEY":
                p, err := x509.ParsePKCS1PublicKey(block.Bytes)
                if err != nil {
                    errorChan <- err
                    return
                }
                pubKey = p

            case "RSA PRIVATE KEY":
                priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
                if err != nil {
                    errorChan <- err
                    return
                }
                pubKey = &priv.PublicKey

            default:
                if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
                    if p2, ok := parsed.(*rsa.PublicKey); ok {
                        pubKey = p2
                    }
                }
            }

            if pubKey == nil {
                errorChan <- errors.New("invalid key type")
                return
            }

            if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sig); err == nil {
                resultChan <- strconv.FormatUint(uint64(s.UserID), 10)
            } else {
                errorChan <- err
            }
        }(share)
    }

    timeout := time.After(5 * time.Second)

    for i := 0; i < len(shares); i++ {
        select {
        case result := <-resultChan:
            cs.logger.Info("Certificate signature verified", 
                zap.String("user_id", result))
            return result, nil
        case <-errorChan:
            continue
        case <-timeout:
            return "", fmt.Errorf("verification timed out")
        }
    }

    return "", ErrBadSignature
}