package handlers

import (
	"net/http"
	"github.com/atomic-protocol/internal/db/models"
	"github.com/atomic-protocol/internal/services"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type UserHandler struct {
	keyService *services.KeyService
	db         *gorm.DB
	logger     *zap.Logger
}

func NewUserHandler(keyService *services.KeyService, db *gorm.DB, logger *zap.Logger) *UserHandler {
	return &UserHandler{
		keyService: keyService,
		db:         db,
		logger:     logger.With(zap.String("handler", "user")),
	}
}

func (uh *UserHandler) ShowProfilePage(c *gin.Context) {
	userID, _ := c.Get("userID")

	var user models.User
	result := uh.db.First(&user, userID)
	if result.Error != nil {
		c.HTML(http.StatusNotFound, "root/error.html", gin.H{
			"Title":   "Error",
			"message": "User not found",
			"error":   true,
		})
		return
	}

	c.HTML(http.StatusOK, "users/profile.html", gin.H{
		"Title": "My Profile",
		"User":  user.Username,
		"user": user,
	})
}

func (uh *UserHandler) UpdateProfile(c *gin.Context) {
	userID, _ := c.Get("userID")

	var user models.User
	result := uh.db.First(&user, userID)
	if result.Error != nil {
		c.HTML(http.StatusNotFound, "root/error.html", gin.H{
			"Title":   "Error",
			"message": "User not found",
			"error":   true,
		})
		return
	}

	user.FirstName = c.PostForm("firstName")
	user.LastName = c.PostForm("lastName")
	user.Email = c.PostForm("email")

	uh.db.Save(&user)

	c.Redirect(http.StatusSeeOther, "/profile")
}

func (uh *UserHandler) ListUsers(c *gin.Context) {
	userID, _ := c.Get("userID")

	var users []models.User
	uh.db.Find(&users)

	c.HTML(http.StatusOK, "users/list.html", gin.H{
		"Title":     "Users",
		"users":     users,
		"currentID": userID,
		"user":      userID,
	})
}