package response

import (
	"github.com/gofrs/uuid"
	"github.com/teamhanko/passkey-server/api/dto/response"
	"github.com/teamhanko/passkey-server/persistence/models"
)

type UserListDto struct {
	ID          uuid.UUID `json:"id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	Icon        string    `json:"icon"`
	DisplayName string    `json:"display_name"`
}

func UserListDtoFromModel(user models.WebauthnUser) UserListDto {
	return UserListDto{
		ID:          user.ID,
		UserID:      user.UserID,
		Name:        user.Name,
		Icon:        user.Icon,
		DisplayName: user.DisplayName,
	}
}

type UserGetDto struct {
	UserListDto
	Credentials  []response.CredentialDto  `json:"credentials"`
	Transactions []response.TransactionDto `json:"transactions"`
}

func UserGetDtoFromModel(user models.WebauthnUser) UserGetDto {
	dto := UserGetDto{
		UserListDto: UserListDto{
			ID:          user.ID,
			UserID:      user.UserID,
			Name:        user.Name,
			Icon:        user.Icon,
			DisplayName: user.DisplayName,
		},
		Credentials:  make([]response.CredentialDto, 0),
		Transactions: make([]response.TransactionDto, 0),
	}

	for _, credential := range user.WebauthnCredentials {
		dto.Credentials = append(dto.Credentials, response.CredentialDtoFromModel(credential))
	}

	for _, transaction := range user.Transactions {
		dto.Transactions = append(dto.Transactions, response.TransactionDtoFromModel(transaction))
	}

	return dto
}
