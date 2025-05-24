package services

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "time"
    "sort"
    "fmt"

    "github.com/atomic-protocol/internal/db/models"
    "github.com/atomic-protocol/pkg/metrics"
    "github.com/google/uuid"
    "go.uber.org/zap"
    "gorm.io/gorm"
)

type DocumentService struct {
    db         *gorm.DB
    keyService *KeyService
    logger     *zap.Logger
    metrics    *metrics.MetricsCollector
}

type DocSummary struct {
    ID             string
    Title          string
    CreatedAt      time.Time
    Classification string
    Status         models.DocumentStatus
}

func NewDocumentService(db *gorm.DB, keyService *KeyService, logger *zap.Logger, metrics *metrics.MetricsCollector) *DocumentService {
    return &DocumentService{
        db:         db,
        keyService: keyService,
        logger:     logger.With(zap.String("service", "document_service")),
        metrics:    metrics,
    }
}

func (ds *DocumentService) collectMetrics(ctx context.Context, fn func()) {
    go func() {
        defer func() {
        }()
        
        select {
        case <-ctx.Done():
            return
        default:
            fn()
        }
    }()
}

func (ds *DocumentService) GetDocument(ctx context.Context, docID string) (*models.Document, error) {
    var doc models.Document
    if err := ds.db.First(&doc, "id = ?", docID).Error; err != nil {
        return nil, err
    }
    return &doc, nil
}

func (ds *DocumentService) ListDocuments(ctx context.Context, userID int) ([]DocSummary, error) {
    var docs []models.Document

    if err := ds.db.Where("user_id = ? OR classification = ?", userID, "PUBLIC").
        Order("created_at DESC").
        Find(&docs).Error; err != nil {
        return nil, err
    }

    summariesChan := make(chan DocSummary, len(docs))
    errorChan := make(chan error, 1)
    
    const maxWorkers = 5
    sem := make(chan struct{}, maxWorkers)

    for _, doc := range docs {
        sem <- struct{}{}
        go func(d models.Document) {
            defer func() { <-sem }()
            
            select {
            case <-ctx.Done():
                errorChan <- ctx.Err()
                return
            default:
                summariesChan <- DocSummary{
                    ID:             d.ID,
                    Title:          d.Title,
                    CreatedAt:      d.CreatedAt,
                    Classification: d.Classification,
                    Status:         d.Status,
                }
            }
        }(doc)
    }

    for i := 0; i < maxWorkers; i++ {
        sem <- struct{}{}
    }

    timeout := time.After(5 * time.Second)
    summaries := make([]DocSummary, 0, len(docs))

    for i := 0; i < len(docs); i++ {
        select {
        case summary := <-summariesChan:
            summaries = append(summaries, summary)
        case err := <-errorChan:
            return nil, fmt.Errorf("error processing documents: %w", err)
        case <-timeout:
            return nil, fmt.Errorf("document processing timed out")
        case <-ctx.Done():
            return nil, ctx.Err()
        }
    }

    sort.Slice(summaries, func(i, j int) bool {
        return summaries[i].CreatedAt.After(summaries[j].CreatedAt)
    })

    return summaries, nil
}

func (ds *DocumentService) CountDocuments(ctx context.Context, userID uint) (int, error) {
    var count int64
    if err := ds.db.Model(&models.Document{}).
        Where("user_id = ?", userID).
        Count(&count).Error; err != nil {
        return 0, err
    }
    return int(count), nil
}

func (ds *DocumentService) ListPending(ctx context.Context, userID uint) ([]DocSummary, error) {
    var docs []models.Document
    if err := ds.db.
        Where("user_id = ? AND status = ?", userID, models.StatusDraft).
        Order("created_at DESC").
        Find(&docs).Error; err != nil {
        return nil, err
    }
    summaries := make([]DocSummary, 0, len(docs))
    for _, d := range docs {
        summaries = append(summaries, DocSummary{
            ID:             d.ID,
            Title:          d.Title,
            CreatedAt:      d.CreatedAt,
            Classification: d.Classification,
            Status:         d.Status,
        })
    }
    return summaries, nil
}

func (ds *DocumentService) RevokeDocument(ctx context.Context, docID string, userID uint) error {
    var doc models.Document
    if err := ds.db.First(&doc, "id = ? AND user_id = ?", docID, userID).Error; err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return errors.New("document not found or permission denied")
        }
        return err
    }
    if err := ds.db.Model(&doc).
        Update("status", models.StatusRevoked).Error; err != nil {
        return err
    }
    ds.logger.Info("Document revoked", zap.String("doc_id", docID), zap.Uint("user_id", userID))
    return nil
}

func (ds *DocumentService) UploadDocument(ctx context.Context, userID int, title, classification string, content []byte) (string, error) {
    start := time.Now()
    id := uuid.New().String()
    hash := sha256.Sum256(content)
    metadata := "{}"

    status := models.StatusDraft
    if classification != "PUBLIC" {
        status = models.StatusSigned
    }

    doc := &models.Document{
        ID:             id,
        Title:          title,
        Content:        content,
        ContentHash:    hex.EncodeToString(hash[:]),
        UserID:         uint(userID),
        Classification: classification,
        Status:         status,
        Metadata:       metadata,
    }

    if err := ds.db.Create(doc).Error; err != nil {
        return "", err
    }

    ds.collectMetrics(ctx, func() {
        ds.metrics.IncrementCounter("documents_uploaded", nil)
        ds.metrics.ObserveSize("document_size", float64(len(content)))  
        ds.metrics.ObserveLatency("document_upload", time.Since(start))
    })

    return id, nil
}

func (ds *DocumentService) SignWithUserKey(ctx context.Context, docID string, userID uint, signature []byte) error {
    start := time.Now()
    var existing models.DocumentSignature
    err := ds.db.
        Where("document_id = ? AND user_id = ?", docID, userID).
        First(&existing).Error
    if err == nil {
        return errors.New("already signed by this user")
    }
    if !errors.Is(err, gorm.ErrRecordNotFound) {
        return err
    }

    sig := &models.DocumentSignature{
        DocumentID: docID,
        UserID:     userID,
        Signature:  signature,
        Timestamp:  time.Now(),
    }

    if err := ds.db.Create(sig).Error; err != nil {
        return err
    }

    ds.collectMetrics(ctx, func() {
        ds.metrics.IncrementCounter("documents_signed", nil)
        ds.metrics.ObserveLatency("document_signature", time.Since(start))
    })

    return nil
}

func (ds *DocumentService) IsFullySigned(ctx context.Context, docID string, requiredUsers []uint) (bool, error) {
    var count int64
    if err := ds.db.
        Model(&models.DocumentSignature{}).
        Where("document_id = ?", docID).
        Distinct("user_id").
        Count(&count).Error; err != nil {
        return false, err
    }
    return int(count) == len(requiredUsers), nil
}

func (ds *DocumentService) MarkSigned(ctx context.Context, docID string) error {
    if err := ds.db.
        Model(&models.Document{}).
        Where("id = ?", docID).
        Update("status", models.StatusSigned).Error; err != nil {
        return err
    }

    ds.collectMetrics(ctx, func() {
        ds.metrics.IncrementCounter("documents_completed", nil)
    })

    ds.logger.Info("Document marked as fully signed", zap.String("doc_id", docID))
    return nil
}

func (ds *DocumentService) ReclassifyDocument(ctx context.Context, docID string, newClass string) error {
    status := models.StatusSigned
    if newClass == "PUBLIC" {
        status = models.StatusDraft
    }

    return ds.db.Model(&models.Document{}).
        Where("id = ?", docID).
        Updates(map[string]interface{}{
            "classification": newClass,
            "status":         status,
        }).Error
}