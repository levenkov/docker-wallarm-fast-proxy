package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"github.com/elazarl/goproxy"
	"github.com/spf13/viper"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func init_env() {
	viper.AutomaticEnv()

	viper.BindEnv("CA_CERT")
	viper.SetDefault("CA_CERT", "/etc/nginx-wallarm/ssl/nginx.crt")

	viper.BindEnv("CA_KEY")
	viper.SetDefault("CA_KEY", "/etc/nginx-wallarm/ssl/nginx.key")
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func setCA(caCert, caKey []byte) error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")

	flag.Parse()

	init_env()

	cert := viper.GetString("CA_CERT")
	key := viper.GetString("CA_KEY")

	if cert != "" && key != "" {
		log.Print("Use custom certs")

		caCert, err := ioutil.ReadFile(cert)
		check(err)
		caKey, err := ioutil.ReadFile(key)
		check(err)

		setCA(caCert, caKey)
	} else {
		log.Print("Use custom certs")
	}

	proxy := goproxy.NewProxyHttpServer()

	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		HandleConnect(goproxy.AlwaysMitm)

	marker, marker_err := ioutil.ReadFile("/etc/wallarm/proxy/marker")
	policy, policy_err := ioutil.ReadFile("/etc/wallarm/proxy/policy")

	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if marker_err == nil {
			req.Header.Set("X-Wallarm-Marker", string(marker))
		}

		if policy_err == nil {
			req.Header.Set("X-Wallarm-Test-Policy", string(policy))
		}

		return req, nil
	})

	proxy.Tr.Dial = func(network, addr string) (c net.Conn, err error) {
		real_addr := ""

		if addr[len(addr)-3:] == "443" {
			real_addr = "127.0.0.1:443"
		} else {
			real_addr = "127.0.0.1:80"
		}

		c, err = net.Dial(network, real_addr)

		if c, ok := c.(*net.TCPConn); err == nil && ok {
			c.SetKeepAlive(true)
		}
		return
	}

	proxy.Verbose = *verbose
	log.Fatal(http.ListenAndServe(*addr, proxy))
}
