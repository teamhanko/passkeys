package admin

import (
	"fmt"
	"github.com/gobuffalo/pop/v6"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/api/dto/admin/request"
	"github.com/teamhanko/passkey-server/api/dto/admin/response"
	"github.com/teamhanko/passkey-server/api/helper"
	"github.com/teamhanko/passkey-server/api/pagination"
	"github.com/teamhanko/passkey-server/api/services/admin"
	"github.com/teamhanko/passkey-server/persistence"
	"net/http"
	"net/url"
	"strconv"
)

type TenantHandler struct {
	persister persistence.Persister
}

func NewTenantHandler(persister persistence.Persister) *TenantHandler {
	return &TenantHandler{
		persister: persister,
	}
}

func (th *TenantHandler) List(ctx echo.Context) error {
	service := admin.NewTenantService(admin.CreateTenantServiceParams{
		Ctx:             ctx,
		TenantPersister: th.persister.GetTenantPersister(nil),
	})

	tenantList, err := service.List()
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, tenantList)
}

func (th *TenantHandler) Create(ctx echo.Context) error {
	var dto request.CreateTenantDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to create tenant").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to create tenant").SetInternal(err)
	}

	return th.persister.Transaction(func(tx *pop.Connection) error {
		service := admin.NewTenantService(admin.CreateTenantServiceParams{
			Ctx: ctx,

			TenantPersister:         th.persister.GetTenantPersister(tx),
			ConfigPersister:         th.persister.GetConfigPersister(tx),
			CorsPersister:           th.persister.GetCorsPersister(tx),
			WebauthnConfigPersister: th.persister.GetWebauthnConfigPersister(tx),
			RelyingPartyPerister:    th.persister.GetWebauthnRelyingPartyPersister(tx),
			AuditConfigPersister:    th.persister.GetAuditLogConfigPersister(tx),
			SecretPersister:         th.persister.GetSecretsPersister(tx),
			JwkPersister:            th.persister.GetJwkPersister(tx),
			MFAConfigPersister:      th.persister.GetMFAConfigPersister(tx),
		})

		createResponse, err := service.Create(dto)
		if err != nil {
			return err
		}

		return ctx.JSON(http.StatusCreated, createResponse)
	})
}

func (th *TenantHandler) Get(ctx echo.Context) error {
	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return ctx.JSON(http.StatusOK, response.ToGetTenantResponse(h.Tenant))
}

func (th *TenantHandler) Update(ctx echo.Context) error {
	var dto request.UpdateTenantDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to update tenant").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to update tenant").SetInternal(err)
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	service := admin.NewTenantService(admin.CreateTenantServiceParams{
		Ctx:             ctx,
		Tenant:          h.Tenant,
		TenantPersister: th.persister.GetTenantPersister(nil),
	})

	err = service.Update(dto)
	if err != nil {
		return err
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (th *TenantHandler) Remove(ctx echo.Context) error {
	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	err = th.persister.GetTenantPersister(nil).Delete(h.Tenant)
	if err != nil {
		return err
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (th *TenantHandler) UpdateConfig(ctx echo.Context) error {
	var dto request.UpdateConfigDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to update tenant config").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to update tenant config").SetInternal(err)
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	return th.persister.GetConnection().Transaction(func(tx *pop.Connection) error {
		service := admin.NewTenantService(admin.CreateTenantServiceParams{
			Ctx:    ctx,
			Tenant: h.Tenant,

			ConfigPersister:         th.persister.GetConfigPersister(tx),
			CorsPersister:           th.persister.GetCorsPersister(tx),
			WebauthnConfigPersister: th.persister.GetWebauthnConfigPersister(tx),
			RelyingPartyPerister:    th.persister.GetWebauthnRelyingPartyPersister(tx),
			AuditConfigPersister:    th.persister.GetAuditLogConfigPersister(tx),
			SecretPersister:         th.persister.GetSecretsPersister(tx),
			MFAConfigPersister:      th.persister.GetMFAConfigPersister(tx),
		})

		err := service.UpdateConfig(dto)
		if err != nil {
			return err
		}

		return ctx.NoContent(http.StatusNoContent)
	})
}

func (th *TenantHandler) ListAuditLog(ctx echo.Context) error {
	var dto request.ListAuditLogDto
	err := ctx.Bind(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to list audit logs").SetInternal(err)
	}

	err = ctx.Validate(&dto)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusBadRequest, "unable to list audit logs").SetInternal(err)
	}

	if dto.Page == 0 {
		dto.Page = 1
	}

	if dto.PerPage == 0 {
		dto.PerPage = 20
	}

	h, err := helper.GetHandlerContext(ctx)
	if err != nil {
		ctx.Logger().Error(err)
		return err
	}

	service := admin.NewTenantService(admin.CreateTenantServiceParams{
		Ctx:    ctx,
		Tenant: h.Tenant,

		AuditLogPersister: th.persister.GetAuditLogPersister(nil),
	})

	auditLogs, logCount, err := service.ListAuditLogs(dto)
	if err != nil {
		return err
	}

	u, _ := url.Parse(fmt.Sprintf("%s://%s%s", ctx.Scheme(), ctx.Request().Host, ctx.Request().RequestURI))

	ctx.Response().Header().Set("Link", pagination.CreateHeader(u, logCount, dto.Page, dto.PerPage))
	ctx.Response().Header().Set("X-Total-Count", strconv.FormatInt(int64(logCount), 10))

	return ctx.JSON(http.StatusOK, auditLogs)
}
