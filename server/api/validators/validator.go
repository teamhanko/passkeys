package validators

import (
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"net/http"
	"reflect"
	"strings"
)

type CustomValidator struct {
	Validator *validator.Validate
}

type ValidationErrors struct {
	Errors []string `json:"errors"`
}

func NewCustomValidator() *CustomValidator {
	v := validator.New()
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]

		if name == "-" {
			return ""
		}

		return name
	})

	return &CustomValidator{Validator: v}
}

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.Validator.Struct(i); err != nil {
		var fieldErrors validator.ValidationErrors
		if errors.As(err, &fieldErrors) {
			vErrs := make([]string, len(fieldErrors))
			for i, err := range fieldErrors {
				switch err.Tag() {
				case "required":
					vErrs[i] = fmt.Sprintf("%s is a required field", err.Field())
				case "email":
					vErrs[i] = fmt.Sprintf("%s must be a valid email address", err.Field())
				case "uuid4":
					vErrs[i] = fmt.Sprintf("%s must be a valid uuid4", err.Field())
				case "url":
					vErrs[i] = fmt.Sprintf("%s must be a valid URL", err.Field())
				case "gte":
					vErrs[i] = fmt.Sprintf("length of %s must be greater or equal to %v", err.Field(), err.Param())
				case "unique":
					vErrs[i] = fmt.Sprintf("%s entries are not unique", err.Field())
				case "oneof":
					vErrs[i] = fmt.Sprintf("%s must be one of '%s'", err.Field(), err.Param())
				case "min":
					vErrs[i] = cv.minMessage(err.Field(), err.Param())
				case "max":
					vErrs[i] = cv.maxMessage(err.Field(), err.Param())
				default:
					vErrs[i] = fmt.Sprintf("something wrong on %s; %s", err.Field(), err.Tag())
				}
			}

			return echo.NewHTTPError(http.StatusBadRequest, strings.Join(vErrs, " and "))
		}
	}

	return nil
}

func (cv *CustomValidator) minMessage(field string, param string) string {
	if param == "1" {
		return fmt.Sprintf("%s must at least have %s entry", field, param)
	} else {
		return fmt.Sprintf("%s must at least have %s entries", field, param)
	}
}

func (cv *CustomValidator) maxMessage(field string, param string) string {
	if param == "1" {
		return fmt.Sprintf("%s cannot have more than %s entry", field, param)
	} else {
		return fmt.Sprintf("%s cannot have more than %s entries", field, param)
	}
}
