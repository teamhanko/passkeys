package admin

import (
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/dto/admin/response"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
)

type UserService interface {
	List(request request.UserListRequest) ([]response.UserListDto, int, error)
	Get(userId uuid.UUID) (*response.UserGetDto, error)
	Delete(userId uuid.UUID) error
}

type CreateUserServiceParams struct {
	Ctx    echo.Context
	Tenant models.Tenant

	UserPersister persisters.WebauthnUserPersister
}

type userService struct {
	ctx           echo.Context
	tenant        models.Tenant
	userPersister persisters.WebauthnUserPersister
}

func NewUserService(params CreateUserServiceParams) UserService {
	return &userService{
		ctx:           params.Ctx,
		tenant:        params.Tenant,
		userPersister: params.UserPersister,
	}
}

func (us *userService) List(listRequest request.UserListRequest) ([]response.UserListDto, int, error) {
	list := make([]response.UserListDto, 0)

	count, err := us.userPersister.Count(us.tenant.ID)
	if err != nil {
		us.ctx.Logger().Error(err)
		return nil, 0, echo.NewHTTPError(http.StatusInternalServerError, "unable to count users").SetInternal(err)
	}

	users, err := us.userPersister.AllForTenant(us.tenant.ID, listRequest.Page, listRequest.PerPage, listRequest.SortDirection)
	if err != nil {
		us.ctx.Logger().Error(err)
		return nil, 0, echo.NewHTTPError(http.StatusInternalServerError, "unable to list users").SetInternal(err)
	}

	for _, user := range users {
		list = append(list, response.UserListDtoFromModel(user))
	}

	return list, count, nil
}

func (us *userService) Get(userId uuid.UUID) (*response.UserGetDto, error) {
	user, err := us.userPersister.GetById(userId)
	if err != nil {
		us.ctx.Logger().Error(err)
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "unable to get user from db").SetInternal(err)
	}

	if user == nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, "user not found")
	}

	dto := response.UserGetDtoFromModel(*user)
	return &dto, nil
}

func (us *userService) Delete(userId uuid.UUID) error {
	user, err := us.userPersister.GetById(userId)
	if err != nil {
		us.ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, "unable to get user from db").SetInternal(err)
	}

	if user == nil {
		return echo.NewHTTPError(http.StatusNotFound, "user not found")
	}

	err = us.userPersister.Delete(user)
	if err != nil {
		us.ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, "unable to delete user from db").SetInternal(err)
	}

	return nil
}
