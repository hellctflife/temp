package handlers

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"encoding/base64"

	"github.com/atomic-protocol/internal/db/models"
	"github.com/atomic-protocol/internal/services"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type DocumentHandler struct {
	documentService *services.DocumentService
	keyService      *services.KeyService
	db              *gorm.DB
	logger          *zap.Logger
}

type Signer struct {
    Username    string
    UserID      uint
    SignedAt    time.Time
    Last        bool
    RawSignature string
}

type DocSummary struct {
	ID                 string
	Title              string
	CreatedAt          time.Time
	Classification     string
	Status             models.DocumentStatus
	SignatureCount     int
	RequiredSignatures int
	Signers            []Signer
}
type DashboardData struct {
	Title          string
	TotalDocuments int
	PendingDocs    []DocSummary
	User           string
}

func NewDocumentHandler(
	documentService *services.DocumentService,
	keyService *services.KeyService,
	db *gorm.DB,
	logger *zap.Logger,
) *DocumentHandler {
	return &DocumentHandler{
		documentService: documentService,
		keyService:      keyService,
		db:              db,
		logger:          logger.With(zap.String("handler", "document")),
	}
}

func (h *DocumentHandler) ShowSignPage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "documents/sign.html", gin.H{
		"Title": "Sign Document",
		"User":  username,
	})
}

func (h *DocumentHandler) ShowDashboard(c *gin.Context) {
	username := c.GetString("username")
	userID := c.GetUint("userID")

	total, err := h.documentService.CountDocuments(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("count documents failed", zap.Error(err))
		total = 0
	}

	pendingSummaries, err := h.documentService.ListPending(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("list pending failed", zap.Error(err))
		pendingSummaries = nil
	}

	pending := make([]DocSummary, len(pendingSummaries))
	for i, d := range pendingSummaries {
		pending[i] = DocSummary{
			ID:             d.ID,
			Title:          d.Title,
			CreatedAt:      d.CreatedAt,
			Classification: d.Classification,
			Status:         d.Status,
		}
	}

	c.HTML(http.StatusOK, "root/dashboard.html", gin.H{
		"Title":          "Dashboard",
		"User":           username,
		"TotalDocuments": total,
		"PendingDocs":    pending,
	})
}

func (h *DocumentHandler) ListDocuments(c *gin.Context) {
    username := c.GetString("username")
    userID, _ := c.Get("userID")

    docs, err := h.documentService.ListDocuments(c.Request.Context(), userID.(int))
    if err != nil {
        h.logger.Error("list documents failed", zap.Error(err))
        c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
            "message": "Error retrieving documents",
            "User":    username,
        })
        return
    }

    var users []models.User
    if err := h.db.Find(&users).Error; err != nil {
        h.logger.Error("failed to load users", zap.Error(err))
        users = []models.User{}
    }
    requiredSignatures := len(users)

    userMap := make(map[uint]string)
    for _, u := range users {
        userMap[u.ID] = u.Username
    }

    summaries := make([]DocSummary, len(docs))
    for i, d := range docs {
        var signatures []models.DocumentSignature
        if err := h.db.Where("document_id = ?", d.ID).
            Order("timestamp ASC").
            Find(&signatures).Error; err != nil {
            h.logger.Warn("failed to load signatures", zap.Error(err), zap.String("doc_id", d.ID))
            signatures = []models.DocumentSignature{}
        }

        signers := make([]Signer, len(signatures))
        for j, sig := range signatures {
            signerUsername := userMap[sig.UserID]
            if signerUsername == "" {
                signerUsername = "Unknown User"
            }

            encodedSig := base64.StdEncoding.EncodeToString(sig.Signature)
            
            signers[j] = Signer{
                Username:    signerUsername,
                UserID:      sig.UserID,
                SignedAt:    sig.Timestamp,
                Last:        j == len(signatures)-1,
                RawSignature: encodedSig,
            }
        }

        summaries[i] = DocSummary{
            ID:                 d.ID,
            Title:              d.Title,
            CreatedAt:          d.CreatedAt,
            Classification:     d.Classification,
            Status:             d.Status,
            SignatureCount:     len(signatures),
            RequiredSignatures: requiredSignatures,
            Signers:            signers,
        }
    }

    c.HTML(http.StatusOK, "documents/list.html", gin.H{
        "Title":     "User's Documents",
        "User":      username,
        "Documents": summaries,
    })
}

func (h *DocumentHandler) ShowUploadPage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "documents/upload.html", gin.H{
		"Title": "Upload Document",
		"User":  username,
	})
}

func (h *DocumentHandler) UploadDocument(c *gin.Context) {
	username := c.GetString("username")
	userID, _ := c.Get("userID")
	userIDUint := uint(userID.(int))

	title := c.PostForm("title")
	classification := c.PostForm("classification")

	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.HTML(http.StatusBadRequest, "documents/upload.html", gin.H{
			"title":   "Upload Document",
			"User":    username,
			"message": "Please choose a file to upload",
			"error":   true,
		})
		return
	}

	if ext := strings.ToLower(filepath.Ext(fileHeader.Filename)); ext != ".pdf" {
		c.HTML(http.StatusBadRequest, "documents/upload.html", gin.H{
			"title":   "Upload Document",
			"User":    username,
			"message": "Only PDF files are allowed",
			"error":   true,
		})
		return
	}

	f, err := fileHeader.Open()
	if err != nil {
		h.logger.Error("open uploaded file failed", zap.Error(err))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		h.logger.Error("read file failed", zap.Error(err))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	docID, err := h.documentService.UploadDocument(c.Request.Context(), userID.(int), title, classification, content)
	if err != nil {
		h.logger.Error("save document failed", zap.Error(err))
		c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
			"message": "Could not save document",
			"User":    username,
			"Title":   "Error",
		})
		return
	}

	h.logger.Info("Document created, proceeding to automatic signing", zap.String("doc_id", docID))
	
	hash := sha256.Sum256(content)
	
	priv, err := h.keyService.UsePrivateKey(userID.(int))
	if err != nil {
		h.logger.Error("auto-signing failed: could not load key", zap.Error(err), zap.String("doc_id", docID))
		c.Redirect(http.StatusSeeOther, "/documents")
		return
	}
	
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		h.logger.Error("auto-signing failed: could not create signature", zap.Error(err), zap.String("doc_id", docID))
		c.Redirect(http.StatusSeeOther, "/documents")
		return
	}
	
	err = h.documentService.SignWithUserKey(c.Request.Context(), docID, userIDUint, sig)
	if err != nil {
		h.logger.Warn("auto-signing failed: could not save signature", zap.Error(err), zap.String("doc_id", docID))
		c.Redirect(http.StatusSeeOther, "/documents")
		return
	}
	
	if classification == "CONFIDENTIAL" {
		if err := h.documentService.MarkSigned(c.Request.Context(), docID); err != nil {
			h.logger.Error("couldn't mark CONFIDENTIAL document as signed", zap.Error(err), zap.String("doc_id", docID))
		}
	} else if classification == "PUBLIC" {
		var users []models.User
		if err := h.db.Find(&users).Error; err == nil {
			required := make([]uint, len(users))
			for i, u := range users {
				required[i] = u.ID
			}
			if done, _ := h.documentService.IsFullySigned(c.Request.Context(), docID, required); done {
				if err := h.documentService.MarkSigned(c.Request.Context(), docID); err != nil {
					h.logger.Error("mark signed failed", zap.Error(err))
				}
			}
		}
	}
	
	h.logger.Info("Document automatically signed by uploader", zap.String("doc_id", docID))
	c.Redirect(http.StatusSeeOther, "/documents")
}

func (h *DocumentHandler) DownloadDocument(c *gin.Context) {
	docID := c.Param("id")

	doc, err := h.documentService.GetDocument(c.Request.Context(), docID)
	if err != nil {
		c.HTML(http.StatusNotFound, "root/error.html", gin.H{
			"message": "Document not found",
			"User":    c.GetString("username"),
		})
		return
	}

	if doc.Classification == "PUBLIC" {
		var users []models.User
		if err := h.db.Find(&users).Error; err != nil {
			h.logger.Error("load users failed", zap.Error(err))
			c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
				"message": "Error loading users",
				"User":    c.GetString("username"),
			})
			return
		}
		required := make([]uint, len(users))
		for i, u := range users {
			required[i] = u.ID
		}
		if done, _ := h.documentService.IsFullySigned(c.Request.Context(), docID, required); !done {
			c.HTML(http.StatusBadRequest, "root/error.html", gin.H{
				"message": "Document is not fully signed",
				"User":    c.GetString("username"),
			})
			return
		}
	}

	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", `inline; filename="`+doc.Title+`.pdf"`)
	c.Writer.Write(doc.Content)
}

func (h *DocumentHandler) RevokeDocument(c *gin.Context) {
	username := c.GetString("username")
	userID := c.GetUint("userID")
	docID := c.Param("id")

	if err := h.documentService.RevokeDocument(c.Request.Context(), docID, userID); err != nil {
		h.logger.Error("revoke document failed", zap.Error(err))
		c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
			"message": "Error revoking document: " + err.Error(),
			"User":    username,
		})
		return
	}

	c.Redirect(http.StatusSeeOther, "/documents")
}

func (h *DocumentHandler) SignDocument(c *gin.Context) {
	username := c.GetString("username")
	user_id, _ := c.Get("userID")
	userID := user_id.(int)

	docID := c.Param("id")

	if docID == "" {
		docID = c.PostForm("id")
	}

	if docID == "" {
		c.HTML(http.StatusBadRequest, "root/error.html", gin.H{
			"message": "Missing document ID to sign",
			"User":    username,
			"Title":   "Error",
		})
		return
	}

	doc, err := h.documentService.GetDocument(c.Request.Context(), docID)
	if err != nil {
		c.HTML(http.StatusNotFound, "root/error.html", gin.H{
			"message": "Document not found",
			"User":    username,
		})
		return
	}

	hash := sha256.Sum256(doc.Content)

	priv, err := h.keyService.UsePrivateKey(userID)
	if err != nil {
		h.logger.Error("load user key failed", zap.Error(err))
		c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
			"message": "Could not load your signing key",
			"User":    username,
		})
		return
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		h.logger.Error("signing failed", zap.Error(err))
		c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
			"message": "Error signing document",
			"User":    username,
		})
		return
	}

	err = h.documentService.SignWithUserKey(c.Request.Context(), docID, uint(userID), sig)
	if err != nil {
		h.logger.Warn("record signature failed", zap.Error(err))
		if err.Error() == "already signed by this user" {
			docs, _ := h.documentService.ListDocuments(c.Request.Context(), userID)
			c.HTML(http.StatusOK, "documents/list.html", gin.H{
				"Documents": docs,
				"Title":     "User's Documents",
				"message":   "You have already signed that document.",
				"error":     true,
				"User":      username,
			})
			return
		}
		c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
			"message": "Could not save your signature",
			"User":    username,
		})
		return
	}

	var users []models.User
	if err := h.db.Find(&users).Error; err != nil {
		h.logger.Error("load users failed", zap.Error(err))
	}
	required := make([]uint, len(users))
	for i, u := range users {
		required[i] = u.ID
	}
	if done, _ := h.documentService.IsFullySigned(c.Request.Context(), docID, required); done {
		if err := h.documentService.MarkSigned(c.Request.Context(), docID); err != nil {
			h.logger.Error("mark signed failed", zap.Error(err))
		}
	}

	c.Redirect(http.StatusSeeOther, "/documents")
}

func (h *DocumentHandler) ReclassifyDocument(c *gin.Context) {
	username := c.GetString("username")
	userID, _ := c.Get("userID")
	docID := c.Query("id")
	newClass := c.Query("class")

	if docID == "" || newClass == "" {
		c.HTML(http.StatusBadRequest, "root/error.html", gin.H{
			"message": "Missing document ID or classification",
			"User":    username,
			"Title":   "Error",
		})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		h.logger.Error("user not found", zap.Error(err))
		c.HTML(http.StatusUnauthorized, "root/error.html", gin.H{
			"message": "You are not authorized to reclassify this document",
			"User":    username,
			"Title":   "Error",
		})
		return
	}

	var doc models.Document
	if err := h.db.First(&doc, "id = ? AND user_id = ?", docID, user.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.HTML(http.StatusNotFound, "root/error.html", gin.H{
				"message": "Document not found or permission denied",
				"User":    username,
				"Title":   "Error",
			})
			return
		}
		h.logger.Error("load document failed", zap.Error(err))
		c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
			"message": "Error loading document",
			"User":    username,
			"Title":   "Error",
		})
		return
	}

	if err := h.documentService.ReclassifyDocument(c.Request.Context(), docID, newClass); err != nil {
		h.logger.Error("reclassify document failed", zap.Error(err))
		c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
			"message": "Error reclassifying document: " + err.Error(),
			"User":    username,
			"Title":   "Error",
		})
		return
	}

	c.Redirect(http.StatusSeeOther, "/documents")
}