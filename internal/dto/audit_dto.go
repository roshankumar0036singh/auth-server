package dto

import "github.com/roshankumar0036singh/auth-server/internal/models"

type PaginationMetaData struct {
	TotalCount  int64 `json:"totalCount"`
	CurrentPage int   `json:"currentPage"`
	HasMore     bool  `json:"hasMore"`
}

type AuditLogsResponse struct {
	Logs     []models.AuditLog  `json:"logs"`
	MetaData PaginationMetaData `json:"metaData"`
}