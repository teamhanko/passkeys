package middleware

import (
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"net/http"
)

type HttpError struct {
	ErrorType  *string            `json:"type,omitempty"`
	Title      *string            `json:"title,omitempty"`
	Details    *string            `json:"details,omitempty"`
	Status     *int               `json:"status,omitempty"`
	Additional *map[string]string `json:"additional,omitempty"`
}

const (
	AboutBlank = "about:blank"
)

func NewHttpError(errorType string, title string, details string, status int, additional *map[string]string) *HttpError {
	return &HttpError{
		ErrorType:  &errorType,
		Title:      &title,
		Details:    &details,
		Status:     &status,
		Additional: additional,
	}
}

func ToHttpError(err error) *HttpError {
	var e *echo.HTTPError
	var errorMessage string

	errorType := "about:blank"

	switch {
	case errors.As(err, &e):
		errorMessage = fmt.Sprintf("%v", e.Message)
		var additional *map[string]string
		internalErrors := make(map[string]string)
		if e.Internal != nil {
			internalErrors["internal"] = fmt.Sprintf("%v", e.Internal)
			additional = &internalErrors
		}

		return &HttpError{
			ErrorType:  &errorType,
			Title:      &errorMessage,
			Details:    nil,
			Status:     &e.Code,
			Additional: additional,
		}
	default:
		errorMessage = http.StatusText(http.StatusInternalServerError)
		code := http.StatusInternalServerError
		return &HttpError{
			ErrorType: &errorType,
			Title:     &errorMessage,
			Status:    &code,
		}
	}
}

type HTTPErrorHandlerConfig struct {
	Debug  bool
	Logger echo.Logger
}

func NewHTTPErrorHandler(config HTTPErrorHandlerConfig) func(err error, c echo.Context) {
	return func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}

		httpError := ToHttpError(err)

		// Send response
		if c.Request().Method == http.MethodHead { // Issue https://github.com/labstack/echo/issues/608
			err = c.NoContent(*httpError.Status)
		} else {
			err = c.JSON(*httpError.Status, httpError)
		}
		if err != nil {
			config.Logger.Error(err)
		}
	}
}
