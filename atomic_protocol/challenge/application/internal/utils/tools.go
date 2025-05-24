package utils

import (
	"golang.org/x/crypto/bcrypt"
	"strings"
	"fmt"
	"encoding/base64"
)

func EncryptPassword(password string)(string, error){
	
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func VerifyPassword(hashedPassword, password string) (bool, error) {
	
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, err
	}
	return true, nil
}


func ExtractCertData(pemText string) (signature string, certData string, err error) {
	const (
		beginMarker = "-----BEGIN CERTIFICATE-----"
		endMarker   = "-----END CERTIFICATE-----"
		dataPrefix  = "CERTIFICATE-DATA|"
	)

	
	bidx := strings.Index(pemText, beginMarker)
	eidx := strings.Index(pemText, endMarker)
	if bidx == -1 || eidx == -1 || bidx >= eidx {
		err = fmt.Errorf("invalid certificate format: missing BEGIN/END markers")
		return
	}

	
	b64 := strings.TrimSpace(pemText[bidx+len(beginMarker) : eidx])
	raw, derr := base64.StdEncoding.DecodeString(b64)
	if derr != nil {
		err = fmt.Errorf("failed to decode Base64: %w", derr)
		return
	}

	decoded := string(raw)
	
	if !strings.HasPrefix(decoded, dataPrefix) {
		err = fmt.Errorf("invalid data format: missing prefix %q", dataPrefix)
		return
	}

	
	remainder := decoded[len(dataPrefix):]

	
	parts := strings.SplitN(remainder, "|", 2)
	if len(parts) != 2 {
		err = fmt.Errorf("invalid data format: expected 'subject|signature', got %q", remainder)
		return
	}

	subject := parts[0]
	signature = parts[1]

	
	certData = dataPrefix + subject
	return
}