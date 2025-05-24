package models

import (
  "time"
  "gorm.io/gorm"
)

type DocumentSignature struct {
  gorm.Model
  DocumentID string    `gorm:"index;not null"`
  UserID     uint      `gorm:"index;not null"`
  Signature  []byte    `gorm:"type:bytea;not null"`
  Timestamp  time.Time `gorm:"autoCreateTime"`
}
