package main

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "io"
    "io/ioutil"

    "net/http"
    "os"
    "strings"
    "time"

    "github.com/spf13/cobra"
    "gopkg.in/square/go-jose.v2"
)

func writeKey(path string, k *ecdsa.PrivateKey) error {
    f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        return err
    }
    bytes, err := x509.MarshalECPrivateKey(k)
    if err != nil {
        return err
    }
    b := &pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes}
    if err := pem.Encode(f, b); err != nil {
        f.Close()
        return err
    }
    return f.Close()
}


func thumbprint(key *ecdsa.PrivateKey) string {
    jsonWebKey := jose.JSONWebKey{
        Key:       key,
        //KeyID:     kid,
        Algorithm: string(jose.ES256),
    }

    pub := jsonWebKey.Public()
    th, _ := pub.Thumbprint(crypto.SHA256)
    return base64.RawURLEncoding.EncodeToString(th[:])
}

func createCSR(key *ecdsa.PrivateKey, host string) ([]byte, error) {
    req := &x509.CertificateRequest {
        Subject: pkix.Name { CommonName: host },
        DNSNames: []string { host },
    }
    csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
    if err != nil {
        return []byte{}, err
    }
    return csr, nil
}

type Config struct {
    url string
    insecure bool
    verbose bool
}
func getConfigFromCobra(cmd *cobra.Command) Config {
    var config Config
    config.url, _ = cmd.Flags().GetString("authority-url")
    config.insecure, _ = cmd.Flags().GetBool("insecure")
    config.verbose, _ = cmd.Flags().GetBool("verbose")
    return config
}


func accCreate(cmd *cobra.Command, args []string) {

    config := getConfigFromCobra(cmd)

    fmt.Println("generating private key...")
    ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        fmt.Printf("failed to generate private key: %s\n", err)
        return
    }

    session, err := NewAcmeSession(config.url, config.insecure)
    if err != nil {
        fmt.Printf("can't establish session %s\n", err)
        return
    }
    session.setVerbose(config.verbose)
    session.setKey(ecKey)

    // create new account
    fmt.Println("creating account")
    newAcc := `{"termsOfServiceAgreed":true,"contact":["mailto:adm1@admin.cz"]}`

    res := session.postJWS(session.directory.NewAccount, newAcc)
    if (res == nil) || (res.StatusCode != 201) {
        fmt.Printf("account was not created %s\n", res.Status)
        return
    }
    account := res.Header.Get("Location")
    session.setAccount(account)
    session.save("account.json")
}


func accInfo(cmd *cobra.Command, args []string) {

    config := getConfigFromCobra(cmd)

    session, err := NewAcmeSession(config.url, config.insecure)
    if err != nil {
        fmt.Printf("can't establish session %s\n", err)
        return
    }
    err = session.load("account.json")
    if err != nil {
        fmt.Printf("can't get account information: %s\n", err)
        return
    }
    res := session.postJWS(session.account, "")
    d, _ := ioutil.ReadAll(res.Body)
    res.Body.Close()
    fmt.Println(string(d))
}

func ordersInfo(cmd *cobra.Command, args []string) {

    config := getConfigFromCobra(cmd)

    session, err := NewAcmeSession(config.url, config.insecure)
    if err != nil {
        fmt.Printf("can't establish session %s\n", err)
        return
    }
    session.verbose = config.verbose
    err = session.load("account.json")
    if err != nil {
        fmt.Printf("can't get account information: %s\n", err)
        return
    }
    res := session.postJWS(session.account, "")
    if res.StatusCode != 200 {
        fmt.Printf("can't get account info %s\n", res.Status)
        d, _ := ioutil.ReadAll(res.Body)
        res.Body.Close()
        fmt.Println(string(d))
        return
    }

    var js struct {
        Status string `json:"status"`
        Orders string `json:"orders"`
    }
    decoder := json.NewDecoder(res.Body)
    err = decoder.Decode(&js)
    res.Body.Close()
    if err != nil {
        fmt.Printf("can't parse account info response %s", err)
        return
    }

    if len(js.Orders) == 0 {
        fmt.Println("orders url not provided!")
        return
    }
    res = session.postJWS(js.Orders, "")

    var js2 struct {
        Orders []string `json:"orders"`
    }
    decoder = json.NewDecoder(res.Body)
    err = decoder.Decode(&js2)
    res.Body.Close()
    for _, ourl := range(js2.Orders) {
        fmt.Printf("order %s\n", ourl)
        res = session.postJWS(ourl, "")
        d, _ := ioutil.ReadAll(res.Body)
        res.Body.Close()
        fmt.Println(string(d))
    }
}

func startHttpProofServer(token string, keyAuth string, port string) *http.Server {
    httpHandler := func (w http.ResponseWriter, r *http.Request) {
        if len(r.URL.Path) < 3 {
            w.WriteHeader(200)
            return
        }
        spl := strings.Split(r.URL.Path, "/")
        fmt.Printf("http got request %s\n", r.URL.Path)
        if (len(spl)<4) || (spl[1] != ".well-known") || (spl[2] != "acme-challenge") {
            fmt.Println("unexpected http request")
            w.WriteHeader(404)
            return
        }
        if spl[3] != token {
            fmt.Println("challenge token does not match http challenge request!!")
            w.WriteHeader(400)
            return
        }
        w.Header().Add("Content-Type", "application/octet-stream")
        w.Write([]byte(keyAuth))
        fmt.Printf("http sending response %s\n", keyAuth)
    }

    httpServer := &http.Server{
        Addr:           ":"+port,
        Handler:        http.HandlerFunc(httpHandler),
        ReadTimeout:    10 * time.Second,
        WriteTimeout:   10 * time.Second,
        MaxHeaderBytes: 1 << 20,
    }
    go func() {
        err := httpServer.ListenAndServe()
        if err != nil {
            fmt.Printf("http server listen&serve stop with %s\n", err)
        }
    }()
    for { // make sure our http server is up
        tstRsp, err := http.Get("http://localhost:"+port)
        if (err == nil) && (tstRsp.StatusCode == 200) {
            break
        } else if err != nil {
            fmt.Println(err)
        } else {
            fmt.Println(tstRsp.Status)
        }
        time.Sleep(100*time.Millisecond)
    }
    fmt.Println("http ready")
    return httpServer
}

func downloadIssuedCertificate(session *AcmeSession, orderURL string, hostname string) {
    fmt.Println("try to get cert")
    path := ""
    for {
        res := session.postJWS(orderURL, "")
        resporder, err := parseOrderResponse(res)
        res.Body.Close()
        if err != nil {
            fmt.Printf("problem getting cert %s\n", err.Error())
        } else if resporder.Status != "valid" {
            fmt.Printf("order status: %s\n", resporder.Status)
        } else {
            path = resporder.Certificate
            fmt.Printf("order response cerificate url:%s\n", path)
            if len(path) > 3 {
                break
            }
        }
        time.Sleep(1000 * time.Millisecond)
    }

    res := session.postJWS(path, "")
    fmt.Printf("cert download status %s\n", res.Status)
    chainOut, _ := os.Create(fmt.Sprintf("chain-%s.pem", hostname))
    defer chainOut.Close()
    io.Copy(chainOut, res.Body)
    res.Body.Close()
}


func authorize(typ string, session *AcmeSession, authurl string, proofPort string, host string) error {
    // start authorization
    fmt.Printf("issuing authorization %s\n", authurl)
    res := session.postJWS(authurl, "")
    auth, err := parseAuth(res)
    res.Body.Close()
    if err != nil {
        return fmt.Errorf("can't parse auth response %s\n", err)
    }

    challenge, err := auth.getChallenge(typ)
    if err != nil {
        return fmt.Errorf("can't get %s challenge %s\n", typ, err)
    }

    fmt.Println("starting proof server")

    keyAuth := challenge.Token + "." + thumbprint(session.key)
    var authSrv io.Closer
    switch typ {
    case "dns-01":
        sha := crypto.SHA256.New()
        sha.Write([]byte(keyAuth))
        token := base64.RawURLEncoding.EncodeToString(sha.Sum(nil))
        authSrv = dnsStart(host, token, proofPort)
    case "http-01":
        authSrv = startHttpProofServer(challenge.Token, keyAuth, proofPort)
    default:
        return fmt.Errorf("unknown challenge type %s", typ)
    }

    fmt.Printf("confirm server is ready %s\n", challenge.Url)
    // confirm we arranged resource
    res = session.postJWS(challenge.Url, "{}")
    res.Body.Close()

    // give them time to perform authorization
    time.Sleep(100*time.Millisecond)

    // wait until autorized / status=valid
    for {
        res = session.postJWS(authurl, "")
        aresp, err := parseAuth(res)
        res.Body.Close()
        if err == nil {
            status := aresp.Status
            fmt.Printf("auth url:%s status:%s\n", authurl, status)
            if (res.StatusCode == 200) && (status == "valid") {
                break
            }
        } else {
            fmt.Println(err)
        }
        time.Sleep(1000 * time.Millisecond)
    }

    authSrv.Close()
    return nil
}

func order(cmd *cobra.Command, args []string) {
    config := getConfigFromCobra(cmd)

    challengeType, err := cmd.Flags().GetString("challenge-type")
    if err != nil {
        fmt.Printf("authority-url is required")
        return
    }
    proofPort, err := cmd.Flags().GetString("proof-port")
    if err != nil {
        fmt.Printf("proof-port is required")
        return
    }

    session, err := NewAcmeSession(config.url, config.insecure)
    if err != nil {
        fmt.Printf("can't establish session %s\n", err)
        return
    }
    session.setVerbose(config.verbose)
    err = session.load("account.json")
    if err != nil {
        fmt.Printf("can't get account info %s\n", err)
    }

    hostname := args[0]
    fmt.Printf("order hostname %s\n", hostname)


    ecKeyCSR, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        fmt.Printf("can't generate private key %s\n", err)
        return
    }

    writeKey("key-"+hostname+".pem", ecKeyCSR)
    if err != nil {
        fmt.Printf("can't write private key %s\n", err)
        return
    }

    csr, err := createCSR(ecKeyCSR, hostname)
    if err != nil {
        fmt.Printf("can't generate certificate request %s\n", err)
        return
    }

    // start certificate order
    fmt.Println("issuing new order")
    newOrder := fmt.Sprintf(`{"identifiers": [ { "type": "dns", "value": "%s" } ]}`,hostname)
    res := session.postJWS(session.directory.NewOrder, newOrder)
    if res.StatusCode != 201 {
        fmt.Println("order request failed")
        resp, _ := ioutil.ReadAll(res.Body)
        fmt.Println(string(resp))
        return
    }
    fmt.Printf("order resp: %s\n", res.Status)
    order, err := parseOrderResponse(res)
    res.Body.Close()
    if err != nil {
        fmt.Printf("can't parse order response %s\n", err)
        return
    }

    // perform all athorizations ?
    for _, authURL := range order.Authorizations {
        err = authorize(challengeType, session, authURL, proofPort, hostname)
        if err != nil {
            fmt.Printf("authorize error %s\n", err)
            return
        }
    }


    fmt.Println("send finalize")
    csrReq := `{"csr":"`+ base64.RawURLEncoding.EncodeToString(csr[:])+`"}`
    fmt.Printf("finalize requst: %s\n", csrReq)   
    res = session.postJWS(order.FinalizeUrl, csrReq)
    if res.StatusCode != 200 {
        fmt.Printf("finalize failed %s\n", res.Status)
        d, err := ioutil.ReadAll(res.Body)
        if err == nil {
            fmt.Println(string(d))
        }
    }
    res.Body.Close()

    downloadIssuedCertificate(session, order.OrderUrl, hostname)
}



func main() {

    var rootCmd = &cobra.Command{
        Use:   "acmec [command]",
        Short: "acme client",
    }
    rootCmd.PersistentFlags().StringP("authority-url", "u", "https://localhost:14000/dir", "authority url")
    rootCmd.PersistentFlags().StringP("proof-port", "p", "5002", "proof port")
    rootCmd.PersistentFlags().Bool("insecure", false, "insecure - do not verify server certificates")
    rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose")

    accountCreate := &cobra.Command {
        Use: "acc-create",
        Run: accCreate,
        Short: "create account",
    }
    accountInfo:= &cobra.Command {
        Use: "acc-info",
        Run: accInfo,
        Short: "show account object",
    }

    orderCommand := &cobra.Command {
        Use: "order [hostname]",
        Args: cobra.MinimumNArgs(1),
        Run: order,
        Short: "make signing order",
    }
    orderCommand.Flags().StringP("challenge-type", "t", "http-01", "challenge - http-01/dns-01")

    orderInfoCommand := &cobra.Command {
        Use: "order-info",
        Run: ordersInfo,
        Short: "make signing order",
    }

    dumpCommand := &cobra.Command {
        Use: "dump [file]",
        Args: cobra.MinimumNArgs(1),
        Run: dumpPEM,
        Short: "dump content of pem file",
    }
    pemkey2hexdataCommand := &cobra.Command {
        Use: "pem2hex [file]",
        Args: cobra.MinimumNArgs(1),
        Run: pemkey2hexdata,
        Short: "dump key from pem file",
    }

    rootCmd.AddCommand(accountCreate)
    rootCmd.AddCommand(accountInfo)
    rootCmd.AddCommand(orderCommand)
    rootCmd.AddCommand(dumpCommand)
    rootCmd.AddCommand(orderInfoCommand)
    rootCmd.AddCommand(pemkey2hexdataCommand)
    rootCmd.Execute()
}
