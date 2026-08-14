package config

import (
	"log"
	"net"

	"github.com/gin-gonic/gin"
)

// ApplyTrustedProxies configures Gin's IP trust model so that
// c.ClientIP() only honors X-Forwarded-For from explicitly trusted
// reverse proxies (issue #151). With no trusted proxies configured the
// default is RemoteAddr-only, so spoofed headers are ignored entirely.
//
// Returns the effective list of trusted CIDRs (nil = no proxies trusted).
func ApplyTrustedProxies(router *gin.Engine, cfg *Config) []string {
	proxies := cfg.Security.TrustedProxies
	platform := cfg.Security.TrustedPlatform

	switch {
	case platform != "":
		router.TrustedPlatform = platform
		log.Printf("TrustedPlatform set to %q — X-Forwarded-For trusted unconditionally", platform)
		return proxies

	case len(proxies) > 0:
		if err := router.SetTrustedProxies(proxies); err != nil {
			log.Printf("Invalid TRUSTED_PROXIES %v: %v — falling back to RemoteAddr-only", proxies, err)
			return nil
		}
		log.Printf("Trusted proxies: %v", proxies)
		return proxies

	default:
		// Explicit RemoteAddr-only: spoofed X-Forwarded-For is ignored.
		router.SetTrustedProxies(nil)
		log.Println("No trusted proxies configured — using RemoteAddr only (spoof-proof)")
		return nil
	}
}

// IsTrusted reports whether an IP matches any configured trusted CIDR.
// Exported for tests.
func IsTrusted(ip string, trusted []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range trusted {
		if cidr == ip {
			return true
		}
		if _, network, err := net.ParseCIDR(cidr); err == nil && network.Contains(parsed) {
			return true
		}
	}
	return false
}
