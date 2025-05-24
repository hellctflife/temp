package models

import (
	"time"

	"gorm.io/gorm"
)


type UserRole string

const (
    RoleAgent UserRole = "AGENT"
    RoleAdmin UserRole = "ADMIN"
)



type User struct {
	gorm.Model
	Username        string    `gorm:"unique;not null"`
	Email           string    `gorm:"unique;not null"`
	PasswordHash    string    `gorm:"not null"` // Bcrypt hash of password
	Salt            string    // Salt used in password hashing
	Role            UserRole  `gorm:"not null;default:'AGENT'"`
	FirstName       string
	LastName        string
	Department      string
	ActiveStatus    bool      `gorm:"not null;default:true"`
	LastLogin       time.Time
	FailedAttempts  int       `gorm:"not null;default:0"`
	LockoutUntil    time.Time
	MFAEnabled      bool      `gorm:"not null;default:false"`
	MFASecret       string
	RequirePasswordChange bool `gorm:"not null;default:false"`
	KeyShares       []KeyShare
	Documents       []Document
	Certificates    []Certificate
}