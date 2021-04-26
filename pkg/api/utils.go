package api

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
)

func performRequestWithData(h http.Handler, method, path string, r io.Reader) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, r)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func performRequest(r http.Handler, method, path string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func jsonError(c *gin.Context, status int, fmtm string, args ...interface{}) {
	c.AbortWithStatusJSON(status, map[string]string{"error": fmt.Sprintf(fmtm, args...)})
}
