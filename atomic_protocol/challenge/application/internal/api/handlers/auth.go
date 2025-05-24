package handlers

import (
	"io"
	"net/http"
	"time"

	"github.com/atomic-protocol/internal/db/models"
	"github.com/atomic-protocol/internal/services"
	"github.com/atomic-protocol/internal/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type AuthHandler struct {
	keyService         *services.KeyService
	certificateService *services.CertificateService
	db                 *gorm.DB
	logger             *zap.Logger
}

func NewAuthHandler(certService *services.CertificateService, keyService *services.KeyService, db *gorm.DB, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		keyService:         keyService,
		certificateService: certService,
		db:                 db,
		logger:             logger.With(zap.String("handler", "auth")),
	}
}

func (ah *AuthHandler) ShowLoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "auth/login.html", gin.H{
		"title": "Login",
	})
}

func (ah *AuthHandler) Login(c *gin.Context) {
	var user models.User

	username := c.PostForm("username")
	password := c.PostForm("password")

	certHdr, certErr := c.FormFile("certificate")

	if (username == "" || password == "") && certErr != nil {
		c.HTML(http.StatusBadRequest, "auth/login.html", gin.H{
			"Title":   "Login",
			"message": "Username/password or certificate file required",
			"error":   true,
		})
		return
	}

	if certErr == nil {
		f, err := certHdr.Open()
		if err != nil {
			c.HTML(http.StatusBadRequest, "auth/login.html", gin.H{
				"Title":   "Login",
				"message": "Could not read uploaded certificate",
				"error":   true,
			})
			return
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			c.HTML(http.StatusBadRequest, "auth/login.html", gin.H{
				"Title":   "Login",
				"message": "Could not read certificate data",
				"error":   true,
			})
			return
		}
		datatext := string(data)
		sig, certData, err := utils.ExtractCertData(datatext)

		if err != nil {
			ah.logger.Warn("Invalid certificate format", zap.Error(err))
			c.HTML(http.StatusBadRequest, "auth/login.html", gin.H{
				"Title":   "Login",
				"message": "Invalid certificate format",
				"error":   true,
			})
			return
		}

		userID, err := ah.certificateService.ValidateCertificate(certData, sig)
		if err != nil {
			ah.logger.Warn("Invalid certificate login", zap.Error(err))
			c.HTML(http.StatusUnauthorized, "auth/login.html", gin.H{
				"Title":   "Login",
				"message": "Invalid or expired certificate",
				"error":   true,
			})
			return
		}

		if res := ah.db.First(&user, userID); res.Error != nil {
			c.HTML(http.StatusUnauthorized, "auth/login.html", gin.H{
				"Title":   "Login",
				"message": "Unknown user",
				"error":   true,
			})
			return
		}
	} else {
		if username == "" || password == "" {
			c.HTML(http.StatusBadRequest, "auth/login.html", gin.H{
				"Title":   "Login",
				"message": "Username and password required",
				"error":   true,
			})
			return
		}
		if res := ah.db.Where("username = ?", username).First(&user); res.Error != nil {
			ah.logger.Warn("Invalid username", zap.String("username", username))
			c.HTML(http.StatusUnauthorized, "auth/login.html", gin.H{
				"Title":   "Login",
				"message": "Invalid username or password",
				"error":   true,
			})
			return
		}
		if ok, err := utils.VerifyPassword(user.PasswordHash, password); !ok || err != nil {
			ah.logger.Warn("Invalid password", zap.String("username", username))
			c.HTML(http.StatusUnauthorized, "auth/login.html", gin.H{
				"Title":   "Login",
				"message": "Invalid username or password",
				"error":   true,
			})
			return
		}
		if !user.ActiveStatus {
			ah.logger.Warn("Inactive account login", zap.String("username", username))
			c.HTML(http.StatusUnauthorized, "auth/login.html", gin.H{
				"Title":   "Login",
				"message": "Account deactivated",
				"error":   true,
			})
			return
		}
	}

	token, err := ah.keyService.CreateSessionToken(
		c.Request.Context(),
		int(user.ID),
		c.ClientIP(),
		c.Request.UserAgent(),
	)
	if err != nil {
		ah.logger.Error("Could not create session", zap.Error(err))
		c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
			"Title":   "Error",
			"message": "Internal error",
			"error":   true,
		})
		return
	}
	ah.keyService.LoadUserPrivateKey(c.Request.Context(), user.ID)
	ah.db.Model(&user).Update("last_login", time.Now())
	c.SetCookie("session_token", token, 3600, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func (ah *AuthHandler) ShowRegisterPage(c *gin.Context) {
	c.HTML(http.StatusOK, "auth/register.html", gin.H{
		"title": "Register New Account",
	})
}

func (ah *AuthHandler) Register(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirm_password")
	email := c.PostForm("email")
	firstName := c.PostForm("first_name")
	lastName := c.PostForm("last_name")

	if username == "" || password == "" || confirmPassword == "" || email == "" {
		c.HTML(http.StatusBadRequest, "auth/register.html", gin.H{
			"title":   "Register New Account",
			"message": "All fields are required",
			"error":   true,
		})
		return
	}

	if password != confirmPassword {
		c.HTML(http.StatusBadRequest, "auth/register.html", gin.H{
			"title":   "Register New Account",
			"message": "Passwords do not match",
			"error":   true,
		})
		return
	}

	var existingUser models.User
	result := ah.db.Where("username = ?", username).First(&existingUser)
	if result.Error == nil {
		c.HTML(http.StatusConflict, "auth/register.html", gin.H{
			"title":   "Register New Account",
			"message": "Username already exists",
			"error":   true,
		})
		return
	}

	result = ah.db.Where("email = ?", email).First(&existingUser)
	if result.Error == nil {
		c.HTML(http.StatusConflict, "auth/register.html", gin.H{
			"title":   "Register New Account",
			"message": "Email already exists",
			"error":   true,
		})
		return
	}

	pass_hash, err := utils.EncryptPassword(password)
	if err != nil {
		ah.logger.Error("Failed to encrypt password",
			zap.String("username", username),
			zap.String("ip", c.ClientIP()),
			zap.Error(err))
		return
	}

	newUser := models.User{
		Username:     username,
		Email:        email,
		PasswordHash: pass_hash,
		FirstName:    firstName,
		LastName:     lastName,
		Role:         models.RoleAgent,
		ActiveStatus: true,
		LastLogin:    time.Now(),
	}

	result = ah.db.Create(&newUser)
	if result.Error != nil {
		ah.logger.Error("Failed to create user",
			zap.String("username", username),
			zap.Error(result.Error))

		c.HTML(http.StatusInternalServerError, "root/error.html", gin.H{
			"title":   "Error",
			"message": "Error creating user: " + result.Error.Error(),
			"error":   true,
		})
		return
	}

	ah.logger.Info("User registered successfully",
		zap.String("username", username),
		zap.Uint("user_id", newUser.ID))

	c.HTML(http.StatusOK, "auth/login.html", gin.H{
		"title":   "Login",
		"message": "Registration successful! You can now log in.",
	})
}

func (ah *AuthHandler) Logout(c *gin.Context) {
	sessionToken, err := c.Cookie("session_token")
	if err == nil {
		userID, valid := ah.keyService.IsValidSession(sessionToken)
		if valid {
			ah.logger.Info("User logged out",
				zap.Int("user_id", userID),
				zap.String("ip", c.ClientIP()))
		}
	}

	c.SetCookie("session_token", "", -1, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/login")
}