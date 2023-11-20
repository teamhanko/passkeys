package request

import "time"

type ListAuditLogDto struct {
	GetTenantDto
	Page         int        `query:"page"`
	PerPage      int        `query:"per_page"`
	StartTime    *time.Time `query:"start_time"`
	EndTime      *time.Time `query:"end_time"`
	Types        []string   `query:"type"`
	UserId       string     `query:"actor_user_id"`
	IP           string     `query:"meta_source_ip"`
	SearchString string     `query:"q"`
}
