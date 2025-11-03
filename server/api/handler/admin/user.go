package admin

import (
	"fmt"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	adminRequest "github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/api/pagination"
	"github.com/teamhanko/passkey-server/api/services/admin"
	"github.com/teamhanko/passkey-server/persistence"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type UserHandler interface {
	List(ctx echo.Context) error
	Get(ctx echo.Context) error
	Remove(ctx echo.Context) error
}

type userHandler struct {
	persister persistence.Persister
}

func NewUserHandler(persister persistence.Persister) UserHandler {
	return &userHandler{persister: persister}
}

func (uh *userHandler) List(ctx echo.Context) error {
	var request adminRequest.UserListRequest
	err := ctx.Bind(&request)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to list users").SetInternal(err)
	}

	err = ctx.Validate(&request)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to list users").SetInternal(err)
	}

	if request.Page == 0 {
		request.Page = 1
	}

	if request.PerPage == 0 {
		request.PerPage = 20
	}

	if request.SortDirection == "" {
		request.SortDirection = "desc"
	}

	switch strings.ToLower(request.SortDirection) {
	case "desc", "asc":
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "sort_direction must be desc or asc")
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return uh.persister.GetConnection().Transaction(func(tx *pop.Connection) error {
		userPersister := uh.persister.GetWebauthnUserPersister(tx)
		userService := admin.NewUserService(admin.CreateUserServiceParams{
			Ctx:           ctx,
			Tenant:        *h.Tenant,
			UserPersister: userPersister,
		})

		users, count, err := userService.List(request)
		if err != nil {
			return err
		}

		u, _ := url.Parse(fmt.Sprintf("%s://%s%s", ctx.Scheme(), ctx.Request().Host, ctx.Request().RequestURI))

		ctx.Response().Header().Set("Link", pagination.CreateHeader(u, count, request.Page, request.PerPage))
		ctx.Response().Header().Set("X-Total-Count", strconv.FormatInt(int64(count), 10))

		return ctx.JSON(http.StatusOK, users)
	})
}

func (uh *userHandler) Get(ctx echo.Context) error {
	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	userIdString := ctx.Param("user_id")
	if userIdString == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "user_id must be a valid uuid4")
	}

	userId, err := uuid.FromString(userIdString)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "user_id must be a valid uuid4")
	}

	return uh.persister.GetConnection().Transaction(func(tx *pop.Connection) error {
		userPersister := uh.persister.GetWebauthnUserPersister(tx)
		userService := admin.NewUserService(admin.CreateUserServiceParams{
			Ctx:           ctx,
			Tenant:        *h.Tenant,
			UserPersister: userPersister,
		})

		user, err := userService.Get(userId)
		if err != nil {
			return err
		}

		return ctx.JSON(http.StatusOK, user)
	})
}

func (uh *userHandler) Remove(ctx echo.Context) error {
	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	userIdString := ctx.Param("user_id")
	if userIdString == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "user_id must be a valid uuid4")
	}

	userId, err := uuid.FromString(userIdString)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "user_id must be a valid uuid4")
	}

	return uh.persister.GetConnection().Transaction(func(tx *pop.Connection) error {
		userPersister := uh.persister.GetWebauthnUserPersister(tx)
		userService := admin.NewUserService(admin.CreateUserServiceParams{
			Ctx:           ctx,
			Tenant:        *h.Tenant,
			UserPersister: userPersister,
		})

		err := userService.Delete(userId)
		if err != nil {
			return err
		}

		return ctx.NoContent(http.StatusNoContent)
	})
}
