package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// GenerateDeviceFingerprint creates a hash from user agent and IP subnet (/24 for IPv4)
func GenerateDeviceFingerprint(userAgent, ipAddress string) string {
	subnet := ipAddress
	// Simple IPv4 subnet masking to /24 to prevent false alarms on dynamic IPs
	if strings.Contains(ipAddress, ".") && !strings.Contains(ipAddress, ":") {
		parts := strings.Split(ipAddress, ".")
		if len(parts) == 4 {
			subnet = strings.Join(parts[:3], ".") + ".0"
		}
	}

	data := userAgent + "|" + subnet
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
