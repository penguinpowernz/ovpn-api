package api

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gin-gonic/gin"
)

//meme                      0x2add4c4b1f559973fef06acb253694d9d (valid until 2022-06-09 12:40:48 +0000 UTC)
func getExpiry(data []byte, err error) (string, string, string, error) {
	if err != nil {
		return "", "", "", err
	}

	bits := strings.Split(string(data), "(")
	cnFp := strings.Split(strings.TrimSpace(bits[0]), " ")

	cn := cnFp[0]
	fingerprint := cnFp[len(cnFp)-1]
	validUntil := strings.Split(bits[1], ")")[0]
	bits = strings.Split(validUntil, " ")
	date := fmt.Sprintf("%sT%sZ", bits[2], bits[3])
	return cn, fingerprint, date, nil
}

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
