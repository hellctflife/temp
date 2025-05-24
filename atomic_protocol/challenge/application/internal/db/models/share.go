package models

import (
	"time"

	"gorm.io/gorm"
)


type KeyShare struct {
	gorm.Model
	ID             uint      `gorm:"primaryKey"`
	UserID         uint      `gorm:"index"`
	EncryptedShare []byte    `gorm:"type:bytea"`
	ShareIndex     int       
	Version        int       
	Created        time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	LastAccessed   time.Time
	Description    string
	Status         string    // "ACTIVE", "REVOKED", etc.
}