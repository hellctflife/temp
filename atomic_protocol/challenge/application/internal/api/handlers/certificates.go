package handlers

import (
	"net/http"

	"github.com/atomic-protocol/internal/db/models"
	"github.com/atomic-protocol/internal/services"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"time"
)

type CertificateHandler struct {
	certificateService *services.CertificateService
	keyService         *services.KeyService
	db                 *gorm.DB
	logger             *zap.Logger
}

func NewCertificateHandler(
	keyService *services.KeyService,
	certificateService *services.CertificateService,
	db *gorm.DB,
	logger *zap.Logger,
) *CertificateHandler {
	return &CertificateHandler{
		keyService:         keyService,
		certificateService: certificateService,
		db:                 db,
		logger:             logger.With(zap.String("handler", "certificate")),
	}
}

func (ch *CertificateHandler) ListCertificates(c *gin.Context) {
	username := c.GetString("username")
	userID, _ := c.Get("userID")

	var certificates []models.Certificate
	ch.db.Where("user_id = ?", userID.(int)).Find(&certificates)

	c.HTML(http.StatusOK, "certificates/list.html", gin.H{
		"Title":        "My Certificates",
		"certificates": certificates,
		"User":         username,
	})
}

func (ch *CertificateHandler) ShowCreatePage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "certificates/create.html", gin.H{
		"Title": "Create Certificate",
		"User":  username,
	})
}

func (ch *CertificateHandler) CreateCertificate(c *gin.Context) {
	username := c.GetString("username")
	sessionToken, err := c.Cookie("session_token")
	if err != nil {
		c.HTML(http.StatusUnauthorized, "root/error.html", gin.H{
			"Title":   "Error",
			"message": "You must be logged in to create certificates",
			"error":   true,
			"User":    username,
		})
		return
	}

	subject := c.PostForm("subject")
	validityDays := 365

	cert, err := ch.certificateService.CreateCertificate(
		c.Request.Context(),
		sessionToken,
		subject,
		time.Duration(validityDays)*24*time.Hour,
	)
	if err != nil {
		ch.logger.Error("Failed to create certificate",
			zap.String("subject", subject),
			zap.Error(err),
		)
		c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
			"Title":   "Error",
			"message": "Error creating certificate: " + err.Error(),
			"error":   true,
			"User":    username,
		})
		return
	}

	zap.L().Info("Certificate created",
		zap.String("cert_id", cert.ID),
		zap.String("subject", subject),
		zap.Time("expires_at", cert.ExpiresAt),
		zap.String("user_id", username),
	)

	c.Redirect(http.StatusSeeOther, "/certificates")
}

func (ch *CertificateHandler) RevokeCertificate(c *gin.Context) {
	username := c.GetString("username")
	sessionToken, err := c.Cookie("session_token")
	if err != nil {
		c.HTML(http.StatusUnauthorized, "root/error.html", gin.H{
			"Title":   "Error",
			"message": "You must be logged in to revoke certificates",
			"error":   true,
			"User":    username,
		})
		return
	}

	certID := c.Param("id")
	reason := c.PostForm("reason")

	if certID == "" || reason == "" {
		c.HTML(http.StatusBadRequest, "root/error.html", gin.H{
			"Title":   "Error",
			"message": "Certificate ID and reason are required",
			"error":   true,
			"User":    username,
		})
		return
	}

	if err := ch.certificateService.RevokeCertificate(
		c.Request.Context(),
		sessionToken,
		certID,
		reason,
	); err != nil {
		ch.logger.Error("Failed to revoke certificate",
			zap.String("cert_id", certID),
			zap.Error(err),
		)
		c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
			"Title":   "Error",
			"message": "Error revoking certificate: " + err.Error(),
			"error":   true,
			"User":    username,
		})
		return
	}

	c.Redirect(http.StatusSeeOther, "/certificates")
}

func (ch *CertificateHandler) DownloadCertificate(c *gin.Context) {
	username := c.GetString("username")
	_, err := c.Cookie("session_token")
	if err != nil {
		c.HTML(http.StatusUnauthorized, "root/error.html", gin.H{
			"Title":   "Certificate Download",
			"message": "You must be logged in to download",
			"error":   true,
			"User":    username,
		})
		return
	}

	certID := c.PostForm("certificate_id")

	ok, verr := ch.certificateService.VerifyCertificate(
		c.Request.Context(),
		certID,
	)
	if !ok || verr != nil {
		ch.logger.Warn("certificate verification failed", zap.String("cert_id", certID), zap.Error(verr))
		c.HTML(http.StatusForbidden, "root/error.html", gin.H{
			"Title":   "Authenticate Certificate",
			"message": "Certificate authentication failed",
			"User":    username,
		})
		return
	}

	c.Header("Content-Type", "application/x-pem-file")
	c.Header("Content-Disposition", `attachment; filename="`+certID+`.pem"`)
	c.String(http.StatusOK, ch.certificateService.GetRawCertificatePEM(certID))
}