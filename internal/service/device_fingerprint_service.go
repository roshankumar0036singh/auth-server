package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
)

// DeviceFingerprintService detects logins from previously unseen
// device/location combinations and alerts the user (#168).
type DeviceFingerprintService struct {
	repo         *repository.DeviceFingerprintRepository
	emailService EmailSender
	auditService *AuditService
}

func NewDeviceFingerprintService(repo *repository.DeviceFingerprintRepository, emailService EmailSender, auditService *AuditService) *DeviceFingerprintService {
	return &DeviceFingerprintService{repo: repo, emailService: emailService, auditService: auditService}
}

// CheckAndAlert looks up the fingerprint of (userAgent, ip). If it was never
// seen for this user, a "new device" alert email is sent and the fingerprint
// is recorded. Known fingerprints just refresh last_seen.
func (s *DeviceFingerprintService) CheckAndAlert(ctx context.Context, userID, userEmail, ipAddress, userAgent string) error {
	subnet := ipSubnet(ipAddress)
	hash := fingerprintHash(userAgent, subnet)

	known, err := s.repo.Exists(userID, hash)
	if err != nil {
		return err
	}
	if known {
		s.repo.TouchLastSeen(userID, hash, time.Now())
		return nil
	}

	fp := &models.DeviceFingerprint{
		UserID:    userID,
		Hash:      hash,
		UserAgent: truncate(userAgent, 60),
		IP:        subnet,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	if err := s.repo.Create(fp); err != nil {
		return err
	}

	// Best effort: alert failures must never fail the login itself.
	if err := s.emailService.SendNewDeviceEmail(userEmail, fp.UserAgent, fp.IP, fp.FirstSeen); err != nil {
		return err
	}

	s.auditService.LogEvent(&userID, "NEW_DEVICE_ALERT", "DEVICE_FINGERPRINT", fp.ID, ipAddress, userAgent, nil)
	return nil
}

// ipSubnet reduces an IP address to its /24 (IPv4) or /64 (IPv6) prefix,
// matching the issue's "IP subnet" requirement while preserving privacy.
func ipSubnet(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "0.0.0.0/0"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// fingerprintHash is a stable, non-reversible key for (userAgent, subnet).
func fingerprintHash(userAgent, subnet string) string {
	sum := sha256.Sum256([]byte(userAgent + "|" + subnet))
	return hex.EncodeToString(sum[:])
}

// IPSubnetForTest exposes the subnet logic for unit tests.
func IPSubnetForTest(raw string) string { return ipSubnet(raw) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
