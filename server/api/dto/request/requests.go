package request

type CredentialRequest interface {
	ListCredentialsDto | DeleteCredentialsDto | UpdateCredentialsDto
}

type ListCredentialsDto struct {
	UserId string `query:"userid" validate:"required,uuid4"`
}

type DeleteCredentialsDto struct {
	Id string `param:"credentialId" validate:"required"`
}

type UpdateCredentialsDto struct {
	CredentialId string `param:"credentialId" validate:"required"`
	Name         string `json:"name" validate:"required"`
}

type InitRegistrationDto struct {
	UserId      string  `json:"userid" validate:"required,uuid4"`
	Username    string  `json:"username" validate:"required"`
	DisplayName *string `json:"displayname"`
	Icon        *string `json:"icon"`
}
