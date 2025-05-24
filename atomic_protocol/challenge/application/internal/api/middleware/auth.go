package middleware

import (
	"net/http"

	"github.com/atomic-protocol/internal/db/models"
	"github.com/atomic-protocol/internal/services"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AuthMiddleware struct {
	keyService *services.KeyService
	db         *gorm.DB
}

func NewAuthMiddleware(keyService *services.KeyService, db *gorm.DB) *AuthMiddleware {
	return &AuthMiddleware{
		keyService: keyService,
		db:         db,
	}
}

func (am *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionToken, err := c.Cookie("session_token")
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		userID, valid := am.keyService.IsValidSession(sessionToken)
		if !valid {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		c.Set("userID", userID)
		var user models.User
		err = am.db.First(&user, userID).Error

		if err != nil {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}
		c.Set("username", user.Username)
		c.Set("role", user.Role)
		c.Next()
	}
}