package admin

import (
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/api/services/admin"
	"github.com/teamhanko/passkey-server/persistence"
	"net/http"
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

		users, err := userService.List()
		if err != nil {
			return err
		}

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
		return echo.NewHTTPError(http.StatusBadRequest, "missing user_id")
	}

	userId, err := uuid.FromString(userIdString)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
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
		return echo.NewHTTPError(http.StatusBadRequest, "missing user_id")
	}

	userId, err := uuid.FromString(userIdString)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid user_id")
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
