package request

type UserListRequest struct {
	PerPage       int    `query:"per_page"`
	Page          int    `query:"page"`
	SortDirection string `query:"sort_direction"`
}
