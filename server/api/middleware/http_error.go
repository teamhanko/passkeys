package middleware

import (
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"net/http"
)

type HttpError struct {
	Title   *string `json:"title,omitempty"`
	Details *string `json:"details,omitempty"`
	Status  *int    `json:"status,omitempty"`
}

func ToHttpError(err error) *HttpError {
	var e *echo.HTTPError
	var errorMessage string

	switch {
	case errors.As(err, &e):
		errorMessage = fmt.Sprintf("%v", e.Message)
		var errorDetails string
		if e.Internal != nil {
			var ie *echo.HTTPError
			if errors.As(e.Internal, &ie) {
				errorDetails = fmt.Sprintf("%v", ie.Message)
			} else {
				errorDetails = fmt.Sprintf("%v", e.Internal.Error())
			}

		}

		return &HttpError{
			Title:   &errorMessage,
			Details: &errorDetails,
			Status:  &e.Code,
		}
	default:
		errorMessage = http.StatusText(http.StatusInternalServerError)
		code := http.StatusInternalServerError

		return &HttpError{
			Title:  &errorMessage,
			Status: &code,
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
