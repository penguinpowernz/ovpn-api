package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"time"

	// ovpn "github.com/ovpn-tool/src"

	"github.com/gin-gonic/gin"
	"github.com/opencoff/go-pki"
	pkiapi "github.com/penguinpowernz/go-pki-api"
	"github.com/penguinpowernz/ovpn-api/pkg/api"
	"github.com/penguinpowernz/ovpn-api/pkg/ccd"
	"github.com/penguinpowernz/ovpn-api/pkg/export"
)

var defaultCRLValidity = 3650

var password, dbfile string

func init() {
	if v := os.Getenv("PKI_PASSWORD"); v != "" {
		password = v
	}

	if fn := os.Getenv("PKI_PASSWORD_FILE"); fn != "" {
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			log.Fatalf("couldn't read password file %s: %s", fn, err)
		}
		password = string(data)
	}
}

func main() {
	var db, addr, dn, serverCRL, ccdPath, serverIP, vpnSubnet, wd string
	var crlValidity int

	if wd == "" {
		wd, _ = os.Getwd()
		if wd == "" {
			wd = "./"
		}
	}

	flag.StringVar(&addr, "a", "127.0.0.1:5555", "IP and port to run on")
	flag.StringVar(&dbfile, "db", "foo.db", "path to the ovpn-tool database")
	flag.StringVar(&dn, "d", "vpn.example.com", "domain name of the VPN server to create clients against")
	flag.StringVar(&vpnSubnet, "s", "10.43.0.0/16", "subnet of the VPN")
	flag.StringVar(&serverIP, "gw", "10.43.0.1", "IP of the VPN Gateway")
	flag.StringVar(&ccdPath, "ccd", path.Join(wd, "ccd"), "domain name of the VPN server to create clients against")
	flag.StringVar(&serverCRL, "crl", path.Join(wd, "crl.pem"), "path to the CRL file used by the openvpn server")
	flag.IntVar(&crlValidity, "crlv", defaultCRLValidity, "how long in days the CRL should be valid for")
	flag.StringVar(&wd, "w", wd, "workdir")
	flag.Parse()

	fatalIfEmpty(addr, "address to serve on (-a)")
	fatalIfEmpty(db, "database path (-db)")
	fatalIfEmpty(dn, "VPN domain name (-d)")
	fatalIfEmpty(vpnSubnet, "VPN subnet (-s)")
	fatalIfEmpty(serverIP, "VPN gateway IP (-gw)")
	fatalIfEmpty(ccdPath, "CCD path (-ccd)")
	fatalIfEmpty(serverCRL, "server CRL file (-crl)")

	fatalIfNotFound(serverCRL)
	fatalIfNotFound(ccdPath)
	fatalIfNotFound(db)

	p := pki.Config{Passwd: password}
	ca, err := pki.New(&p, db, false)
	if err != nil {
		log.Fatalf("failed to open the PKI database: %s", err)
	}
	defer ca.Close()

	crt, err := ca.FindServer(dn)
	var conf []byte
	if err != nil {
		crt, conf, err = createServerConfig(ca, dn)
		if err != nil {
			log.Fatalf("ERROR: %s", err)
		}

		if err := ioutil.WriteFile(path.Join(wd, dn+".conf"), conf, 0600); err != nil {
			log.Fatalf("ERROR: %s", err)
		}
	}

	pkirouter := gin.Default()
	pkisvr := pkiapi.NewServer(ca)
	pkisvr.SetupRoutes(pkirouter)

	ccd := ccd.CCD{Path: ccdPath, VpnSubnet: vpnSubnet, GatewayIP: serverIP}
	svr := api.NewServer(wd, db, dn, serverCRL, ccd, crlValidity, pkirouter, ca, crt)

	api := gin.Default()
	svr.SetupRoutes(api)

	api.Run(addr)
}

func fatalIfEmpty(v, desc string) {
	if v == "" {
		log.Fatalf("%s must not be empty", desc)
	}
}

func fatalIfNotFound(fn string) {
	_, err := os.Stat(fn)
	if err != nil {
		log.Fatalf("failed to open %s: %s", fn, err)
	}
}

func createServerConfig(ca *pki.CA, dn string) (*pki.Cert, []byte, error) {
	// TODO: validate args

	ci := &pki.CertInfo{
		Subject:  ca.Subject,
		Validity: time.Hour * 24 * 3650, // 10 years by default

		DNSNames:    []string{dn},
		IPAddresses: []net.IP{},
	}
	ci.Subject.CommonName = dn

	// TODO: add private key password if wanted
	crt, err := ca.NewServerCert(ci, "")
	if err != nil {
		return nil, []byte{}, err
	}

	v, err := export.NewServerView(crt, ca.PEM())
	if err != nil {
		return crt, []byte{}, err
	}

	conf, err := export.Export(v, export.ServerTemplate)
	return crt, conf, err
}
