package helper

import (
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/teamhanko/passkey-server/persistence/models"
	"github.com/teamhanko/passkey-server/persistence/persisters"
	"net/http"
)

func FindTenantByIdString(id string, tenantPersister persisters.TenantPersister) (*models.Tenant, error) {
	tenantId, err := uuid.FromString(id)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "unable to parse tenant id").SetInternal(err)
	}

	tenant, err := tenantPersister.Get(tenantId)
	if err != nil {
		return nil, err
	}

	if tenant == nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("no tenant with ID '%s' was found", id))
	}

	return tenant, nil
}
