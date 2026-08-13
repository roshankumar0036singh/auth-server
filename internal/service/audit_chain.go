package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
)

// ChainBroken describes a specific link whose hash no longer matches its
// recomputed value, or whose PrevHash does not match its predecessor (#154).
type ChainBroken struct {
	ID       string
	Expected string
	Actual   string
	Index    int
}

// AuditChainVerifier recomputes the audit hash chain for a volume of logs.
type AuditChainVerifier struct {
	repo *repository.AuditRepository
}

func NewAuditChainVerifier(repo *repository.AuditRepository) *AuditChainVerifier {
	return &AuditChainVerifier{repo: repo}
}

// Verify walks every audit entry in insertion order and validates both the
// entry hash and the link to its predecessor.
func (v *AuditChainVerifier) Verify() (bool, []ChainBroken) {
	var broken []ChainBroken
	var prevHash string
	index := 0

	offset := 0
	const batch = 200
	for {
		logs, err := v.repo.FindChained(offset, batch)
		if err != nil {
			broken = append(broken, ChainBroken{ID: "<query error>", Actual: err.Error(), Index: index})
			return false, broken
		}
		if len(logs) == 0 {
			break
		}
		for _, l := range logs {
			expected := HashEntry(prevHash, chainPayload(l))
			if l.PrevHash != prevHash {
				broken = append(broken, ChainBroken{ID: l.ID, Expected: prevHash, Actual: l.PrevHash, Index: index})
			}
			if l.Hash != expected {
				broken = append(broken, ChainBroken{ID: l.ID, Expected: expected, Actual: l.Hash, Index: index})
			}
			prevHash = l.Hash
			index++
		}
		offset += len(logs)
		if len(logs) < batch {
			break
		}
	}
	return len(broken) == 0, broken
}

// HashEntry computes the chain hash of a log given its predecessor hash.
func HashEntry(prevHash, payload string) string {
	sum := sha256.Sum256([]byte(prevHash + "|" + payload))
	return hex.EncodeToString(sum[:])
}

// chainPayload canonicalizes the immutable fields that are hashed.
func chainPayload(l models.AuditLog) string {
	uid := ""
	if l.UserID != nil {
		uid = *l.UserID
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		uid, l.Action, l.Entity, l.EntityID, l.IPAddress, l.Metadata,
		l.CreatedAt.UTC().Format(time.RFC3339Nano))
}
