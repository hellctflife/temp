package models

import (
	"time"

	"gorm.io/gorm"
)


type DocumentStatus string

const (
	StatusDraft    DocumentStatus = "DRAFT"
	StatusSigned   DocumentStatus = "SIGNED"
	StatusRevoked  DocumentStatus = "REVOKED"
	StatusArchived DocumentStatus = "ARCHIVED"
)


type Document struct {
	gorm.Model
	ID             string         `gorm:"primaryKey"`
	Title          string         `gorm:"not null"`
	Content        []byte         `gorm:"type:bytea"`
	ContentHash    string         `gorm:"not null"`
	Signature      []byte         `gorm:"type:bytea"`
	SignatureB64   string
	UserID         uint           `gorm:"index"`
	Timestamp      time.Time      `gorm:"default:CURRENT_TIMESTAMP"`
	Status         DocumentStatus `gorm:"not null;default:'SIGNED'"`
	Version        int            `gorm:"not null;default:1"`
	Tags           string
	Classification string         // "PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"
	Metadata       string         `gorm:"type:json"`
}