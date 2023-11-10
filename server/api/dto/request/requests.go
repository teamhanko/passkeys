package request

type CredentialRequest interface {
	ListCredentialsDto | DeleteCredentialsDto | UpdateCredentialsDto
}

type TenantDto struct {
	TenantId string `param:"tenant_id" validate:"required,uuid4"`
}

type ListCredentialsDto struct {
	UserId string `query:"user_id" validate:"required"`
}

type DeleteCredentialsDto struct {
	Id string `param:"credential_id" validate:"required"`
}

type UpdateCredentialsDto struct {
	CredentialId string `param:"credential_id" validate:"required"`
	Name         string `json:"name" validate:"required"`
}

type InitRegistrationDto struct {
	UserId      string  `json:"user_id" validate:"required"`
	Username    string  `json:"username" validate:"required"`
	DisplayName *string `json:"display_name"`
	Icon        *string `json:"icon"`
}
