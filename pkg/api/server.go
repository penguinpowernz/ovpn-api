package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/opencoff/go-pki"
	"github.com/penguinpowernz/ovpn-api/pkg/ccd"
)

type Server struct {
	dbPath        string // path to the ovpn-tool database file
	domainName    string // the domain name of the VPN Server
	serverCRLPath string // the path to the CRL file used by the openvpn process
	ccd           ccd.CCD
	CRLValidity   int
	pkiapi        http.Handler
	ca            *pki.CA
	crt           *pki.Cert
	wd            string
}

func NewServer(wd, dbPath, domainName, serverCRLPath string, ccd ccd.CCD, crlValidity int, pkirouter http.Handler, ca *pki.CA, crt *pki.Cert) *Server {
	return &Server{
		dbPath:        dbPath,
		domainName:    domainName,
		serverCRLPath: serverCRLPath,
		ccd:           ccd,
		CRLValidity:   crlValidity,
		pkiapi:        pkirouter,
		ca:            ca,
		crt:           crt,
		wd:            wd,
	}
}

type Cert struct {
	*pki.Cert
	IP string `json:"ip"`
}

func (cert *Cert) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"common_name":      cert.Subject.CommonName,
		"serial":           fmt.Sprintf("%#x", cert.SerialNumber),
		"expired":          time.Now().After(cert.NotAfter),
		"expires_at":       cert.NotAfter.Unix(),
		"expires_at_human": cert.NotAfter.String(),
	})
}

func (svr *Server) SetupRoutes(r gin.IRouter) {
	r.GET("/client_ips", svr.GetIPList)
	r.GET("/clients", svr.ListClients)
	r.GET("/client/:cn", svr.GetClient)
	r.GET("/client/:cn/config", svr.GetClientConf)
	r.POST("/client/:cn", svr.CreateClient)
	r.DELETE("/client/:cn", svr.DeleteClient)
	r.PUT("/crl", svr.RegenCRL)
}

func (svr *Server) RegenCRL(c *gin.Context) {
	validity := strconv.Itoa(svr.CRLValidity)
	if v := c.Query("validity"); v != "" {
		if _, err := strconv.Atoi(v); err != nil {
			c.AbortWithError(400, err)
			return
		}
		validity = v
	}

	res := performRequest(svr.pkiapi, "GET", "/crl/"+validity)

	switch res.Code {
	case 200:
		if err := ioutil.WriteFile(svr.serverCRLPath, res.Body.Bytes(), 0644); err != nil {
			jsonError(c, 500, "failed to write CRL file: %s", err)
			return
		}
	}

	c.Status(204)
}
