package models

import (
	"time"

	"gorm.io/gorm"
)

type Certificate struct {
	gorm.Model
	ID 			    string       `gorm:"primaryKey"`
	UserID          uint       `gorm:"index"`
	Subject         string     `gorm:"not null"`
	Issuer          string
	SerialNumber    string
	Data            string     `gorm:"not null"`
	Signature       string     `gorm:"not null"`
	PublicKey       string
	IssuedAt        time.Time  `gorm:"default:CURRENT_TIMESTAMP"`
	ExpiresAt       time.Time  `gorm:"not null"`
	RevocationDate  *time.Time
	RevocationReason string
	Status          string     `gorm:"not null;default:'VALID'"`
}