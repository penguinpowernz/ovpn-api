package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/penguinpowernz/ovpn-api/pkg/export"
)

func (svr *Server) ListClients(c *gin.Context) {
	res := performRequest(svr.pkiapi, "GET", "/users")
	if res.Code != 200 {
		c.AbortWithStatus(503)
		return
	}
	c.Data(200, "application/json", res.Body.Bytes())
}

func (svr *Server) GetClientConf(c *gin.Context) {
	cn := c.Param("cn")

	cl, err := svr.ca.FindClient(cn)
	if err != nil {
		c.AbortWithError(404, err)
		return
	}

	v, err := export.NewClientView(cl, svr.crt, svr.ca.PEM())
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	data, err := export.Export(v, export.UserTemplate)
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	c.Data(200, "text/plain", data)
}

func (svr *Server) GetClient(c *gin.Context) {
	cn := c.Param("cn")

	cl, err := svr.ca.FindClient(cn)
	if err != nil {
		c.AbortWithError(404, err)
		return
	}

	if cl.Subject.CommonName != cn {
		c.AbortWithError(403, fmt.Errorf("common name did not match: requested %s but got %s", cn, cl.Subject.CommonName))
		return
	}

	ccd, err := svr.ccd.Read(cn)
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	bits := strings.Split(ccd, " ")
	ip := bits[1]

	crt := Cert{cl, ip}

	c.JSON(200, crt)
}

func (svr *Server) GetIPList(c *gin.Context) {
	c.JSON(200, svr.ccd.CurrentIPMap())
}

func (svr *Server) CreateClient(c *gin.Context) {
	cn := c.Param("cn")
	validity := c.Query("validity_days")

	if validity == "" {
		validity = "5"
	}

	var ip string
	var err error

	// create IP in the CCD
	if ip, err = svr.ccd.ReadIP(cn); err != nil {
		if err := svr.ccd.WriteNextStaticIP(cn); err != nil {
			c.AbortWithError(500, err)
			return
		}
		ip, _ = svr.ccd.ReadIP(cn)
	}

	res := performRequestWithData(svr.pkiapi, "POST", "/users/"+cn, bytes.NewBufferString(`{"validity_days": `+validity+`}`))

	switch res.Code {
	case 500, 400, 409:
		c.Data(res.Code, "utf8", res.Body.Bytes())
		return
	}

	m := map[string]interface{}{}
	if err := json.Unmarshal(res.Body.Bytes(), &m); err != nil {
		jsonError(c, 500, "failed to validate client creation")
		return
	}

	cl, err := svr.ca.FindClient(cn)
	if err != nil {
		jsonError(c, 404, "client couldn't be found after it was created")
		return
	}

	v, err := export.NewClientView(cl, svr.crt, svr.ca.PEM())
	if err != nil {
		jsonError(c, 500, "failed to create config template")
		return
	}

	data, err := export.Export(v, export.UserTemplate)
	if err != nil {
		jsonError(c, 500, "failed to generate config template")
		return
	}

	data = append([]byte("# fingerprint="+m["fingerprint"].(string)+"\n"), data...)
	m["ip"] = ip
	m["config"] = string(data)

	c.JSON(200, m)
}

func (svr *Server) file(fn ...string) string {
	fn = append([]string{svr.wd}, fn...)
	return path.Join(fn...)
}

func (svr *Server) DeleteClient(c *gin.Context) {
	cn := c.Param("cn")

	// delete cert
	res := performRequest(svr.pkiapi, "DELETE", "/users/"+cn)

	switch res.Code {
	case 500, 400, 409:
		c.Data(res.Code, "utf8", res.Body.Bytes())
		return
	}

	_ = svr.ccd.Delete(cn)

	res = performRequest(svr.pkiapi, "GET", "/crl/"+strconv.Itoa(svr.CRLValidity))
	switch res.Code {
	case 500, 400, 409:
		c.Data(res.Code, "utf8", res.Body.Bytes())
		return
	}

	crlPath := svr.serverCRLPath
	if crlPath == "" {
		crlPath = svr.file("server.crl")
	}

	ioutil.WriteFile(crlPath, res.Body.Bytes(), 0600)

	c.Status(204)
}
