package api

import (
	"html/template"
	"net/http"

	"github.com/atomic-protocol/internal/api/handlers"
	"github.com/atomic-protocol/internal/api/middleware"
	"github.com/atomic-protocol/internal/services"
	"github.com/atomic-protocol/pkg/metrics"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Router struct {
	engine         *gin.Engine
	logger         *zap.Logger
	metrics        *metrics.MetricsCollector
	keyService     *services.KeyService
	docService     *services.DocumentService
	authHandler    *handlers.AuthHandler
	docHandler     *handlers.DocumentHandler
	certHandler    *handlers.CertificateHandler
	userHandler    *handlers.UserHandler
	authMiddleware *middleware.AuthMiddleware
	reqMiddleware  *middleware.RequestMiddleware
}

func NewRouter(
	logger *zap.Logger,
	metrics *metrics.MetricsCollector,
	keyService *services.KeyService,
	docService *services.DocumentService,
	certService *services.CertificateService,
	db *gorm.DB,
) *Router {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	reqMiddleware := middleware.NewRequestMiddleware(logger)
	authMiddleware := middleware.NewAuthMiddleware(keyService, db)

	engine.Use(reqMiddleware.ProcessRequest())
	engine.Use(reqMiddleware.RecoverPanic())
	engine.Use(reqMiddleware.LoginAttemptMiddleware())

	logger.Info("Loading templates with FuncMap and glob…")
	tmpl := template.Must(template.New("").ParseGlob("templates/layout/*.html"))
	tmpl = template.Must(tmpl.ParseGlob("templates/**/*.html"))
	environment := engine
	environment.SetHTMLTemplate(tmpl)

	environment.Static("/static", "./static")
	environment.StaticFile("/favicon.ico", "./static/img/favicon.ico")

	authHandler := handlers.NewAuthHandler(certService, keyService, db, logger)
	docHandler := handlers.NewDocumentHandler(docService, keyService, db, logger)
	certHandler := handlers.NewCertificateHandler(keyService, certService, db, logger)
	userHandler := handlers.NewUserHandler(keyService, db, logger)

	return &Router{
		engine:         environment,
		logger:         logger,
		metrics:        metrics,
		keyService:     keyService,
		docService:     docService,
		authHandler:    authHandler,
		docHandler:     docHandler,
		certHandler:    certHandler,
		userHandler:    userHandler,
		authMiddleware: authMiddleware,
		reqMiddleware:  reqMiddleware,
	}
}

func (r *Router) SetupRoutes() {
	r.engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "up", "name": "atomic-protocol"})
	})

	r.engine.GET("/metrics", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"counters":  r.metrics.GetCounters(),
			"latencies": r.metrics.GetLatencies(),
		})
	})

	r.engine.GET("/", func(c *gin.Context) { c.Redirect(http.StatusSeeOther, "/login") })
	
	r.engine.GET("/login", r.authHandler.ShowLoginPage)
	r.engine.POST("/login", r.authHandler.Login)
	r.engine.GET("/logout", r.authHandler.Logout)

	authorized := r.engine.Group("/")
	authorized.Use(r.authMiddleware.RequireAuth())
	{
		authorized.GET("/dashboard", r.docHandler.ShowDashboard)
		authorized.GET("/profile", r.userHandler.ShowProfilePage)
		authorized.POST("/profile", r.userHandler.UpdateProfile)
		authorized.GET("/users", r.userHandler.ListUsers)
		authorized.GET("/documents", r.docHandler.ListDocuments)
		authorized.GET("/documents/sign/:id", r.docHandler.SignDocument)
		authorized.POST("/documents/sign", r.docHandler.SignDocument)
		authorized.GET("/documents/edit", r.docHandler.ReclassifyDocument)
		authorized.GET("/documents/download/:id", r.docHandler.DownloadDocument)
		authorized.POST("/documents/revoke/:id", r.docHandler.RevokeDocument)
		authorized.POST("/documents/upload", r.docHandler.UploadDocument)
		authorized.GET("/documents/upload", r.docHandler.ShowUploadPage)
		authorized.GET("/certificates", r.certHandler.ListCertificates)
		authorized.GET("/certificates/create", r.certHandler.ShowCreatePage)
		authorized.POST("/certificates/create", r.certHandler.CreateCertificate)
		authorized.POST("/certificates/download", r.certHandler.DownloadCertificate)	
		authorized.POST("/certificates/revoke/:id", r.certHandler.RevokeCertificate)
	}
}

func (r *Router) GetEngine() *gin.Engine {
	return r.engine
}

func (r *Router) Run(addr string) error {
	r.logger.Info("Starting HTTP server", zap.String("address", addr))
	return r.engine.Run(addr)
}