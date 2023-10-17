package middleware

import (
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
)

func LoggerMiddleware() echo.MiddlewareFunc {
	return echoMiddleware.LoggerWithConfig(echoMiddleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339_nano}","time_unix":"${time_unix}","id":"${id}","remote_ip":"${remote_ip}",` +
			`"host":"${host}","method":"${method}","uri":"${uri}","user_agent":"${user_agent}",` +
			`"Status":${Status},"error":"${error}","latency":${latency},"latency_human":"${latency_human}"` +
			`,"bytes_in":${bytes_in},"bytes_out":${bytes_out},"referer":"${referer}"}` + "\n",
	})
}
