package main

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
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


type Order struct {
    Status string
    Authorizations []string
    FinalizeUrl string
    OrderUrl string
    Certificate string
}


func parseOrderResponse(resp *http.Response) (*Order, error) {
    defer resp.Body.Close()
    orderLocation := resp.Header.Get("Location")
    var js struct {
        Status string`json:"status"`
        Identifiers []struct {
            Type string `json:"type"`
            Value string `json:"value"`
        } `json:"Identifiers"`
        Authorizations []string `json:"authorizations"`
        Finalize string `json:"finalize"`
        Certificate string`json:"certificate"`
    }
    decoder := json.NewDecoder(resp.Body)
    err := decoder.Decode(&js)
    if err != nil {
        return nil, err
    }
    return &Order {
        Authorizations: js.Authorizations,
        FinalizeUrl: js.Finalize,
        OrderUrl: orderLocation,
        Status: js.Status,
        Certificate: js.Certificate,
    }, nil
}

type AuthChallenge struct {
    Type string
    Url string
    Token string
    Status string
}

func parseAuthz(resp *http.Response) *AuthChallenge {
    if resp.StatusCode != 200 {
        fmt.Println(resp.Status)
        msg, _ := ioutil.ReadAll(resp.Body)
        resp.Body.Close()
        fmt.Println(string(msg))
    }
    fmt.Println(resp.Status)
    defer resp.Body.Close()
    var js struct {
        Status string `json:"status"`
        Challenges []struct {
            Type  string `json:"type"`
            Url   string `json:"url"`
            Token string `json:"token"`
        } `json:"challenges"`
    }
    decoder := json.NewDecoder(resp.Body)
    err := decoder.Decode(&js)
    if err != nil {
        panic(err)
    }
    fmt.Println(js)
    for _, ch := range(js.Challenges) {
        if ch.Type == "http-01" {
            return &AuthChallenge{
                Type: ch.Type,
                Url: ch.Url,
                Token: ch.Token,
                Status: js.Status,
            }
        }
    }
    return nil
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

func createCSR(key *ecdsa.PrivateKey, host string) []byte {
    req := &x509.CertificateRequest {
        Subject: pkix.Name{CommonName: host},
        DNSNames: []string{host},
    }
    csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
    if err != nil {
        panic(err)
    }
    return csr
}

func handleGlobalFlags(cmd *cobra.Command) {
    insecure, _ := cmd.Flags().GetBool("insecure")
    if insecure {
        http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
    }
}


func accCreate(cmd *cobra.Command, args []string) {
    handleGlobalFlags(cmd)
    authorityUrl, err := cmd.Flags().GetString("authority-url")
    if err != nil {
        panic(err)
    }

    fmt.Println("generating private key...")
    ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        panic(err)
    }

    session := NewAcmeSession(authorityUrl)
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

func startHttpProofServer(token string, thumb string, port string) *http.Server {
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
        out := spl[3] + "." + thumb
        w.Write([]byte(out))
        fmt.Printf("http sending response %s\n", out)
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
    return httpServer
}

func order(cmd *cobra.Command, args []string) {
    handleGlobalFlags(cmd)
    authorityUrl, err := cmd.Flags().GetString("authority-url")
    if err != nil {
        panic(err)
    }
    proofPort, err := cmd.Flags().GetString("proof-port")
    if err != nil {
        panic(err)
    }

    session := NewAcmeSession(authorityUrl)
    err = session.load("account.json")
    if err != nil {
        panic(err)
    }

    hostname := args[0]
    fmt.Printf("order hostname %s\n", hostname)


    ecKeyCSR, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    writeKey("key-"+hostname+".pem", ecKeyCSR)

    csr := createCSR(ecKeyCSR, hostname)

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

    order, err := parseOrderResponse(res)
    if err != nil {
        panic(err)
    }
    res.Body.Close()
    fmt.Printf("order resp: %s\n", res.Status)
    fmt.Println(order)

    // start authorization
    fmt.Printf("issuing authorization %s\n", order.Authorizations[0])
    res = session.postJWS(order.Authorizations[0], "")
    challenge := parseAuthz(res)
    res.Body.Close()

    fmt.Println("starting http server")
 
    httpServer := startHttpProofServer(challenge.Token, thumbprint(session.key), proofPort)

    fmt.Printf("confirm server is ready %s\n", challenge.Url)
    // confirm we arranged resource
    res = session.postJWS(challenge.Url, "{}")
    res.Body.Close()

    // give them time to perform authorization
    time.Sleep(100*time.Millisecond)

    // wait until autorized / status=valid
    for {
        res = session.postJWS(order.Authorizations[0], "")
        aresp := parseAuthz(res)
        res.Body.Close()
        status := aresp.Status
        fmt.Printf("auth url:%s status: %s\n", order.Authorizations[0], status)
        if (res.StatusCode == 200) && (status == "valid") {
            break
        }
        time.Sleep(1000 * time.Millisecond)
    }

    httpServer.Close()

    fmt.Println("send csr")
    csrReq := `{"csr":"`+ base64.RawURLEncoding.EncodeToString(csr[:])+`"}`
    fmt.Printf("csr requst: %s\n", csrReq)   
    res = session.postJWS(order.FinalizeUrl, csrReq)
    res.Body.Close()

    fmt.Println("try to get cert")
    path := ""
    for {
        res = session.postJWS(order.OrderUrl, "")
        //path = parseOrderFinal(res)
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

    res = session.postJWS(path, "")
    fmt.Printf("cert download status %s\n", res.Status)
    chainOut, _ := os.Create(fmt.Sprintf("chain-%s.pem", hostname))
    defer chainOut.Close()
    io.Copy(chainOut, res.Body)
    res.Body.Close()
}



func main() {

    var rootCmd = &cobra.Command{
        Use:   "acmec [command]",
        Short: "acme client",
    }
    rootCmd.PersistentFlags().StringP("authority-url", "u", "https://localhost:14000/dir", "authority url")
    rootCmd.PersistentFlags().StringP("proof-port", "p", "5002", "proof port")
    rootCmd.PersistentFlags().Bool("insecure", false, "insecure - do not verify server certificates")

    accountCreate := &cobra.Command {
        Use: "acc-create",
        Run: accCreate,
        Short: "create account",
    }

    orderCommand := &cobra.Command {
        Use: "order [hostname]",
        Args: cobra.MinimumNArgs(1),
        Run: order,
        Short: "make signing order",
    }

    dumpCommand := &cobra.Command {
        Use: "dump [file]",
        Args: cobra.MinimumNArgs(1),
        Run: dumpPEM,
        Short: "dump content of pem file",
    }

    rootCmd.AddCommand(accountCreate)
    rootCmd.AddCommand(orderCommand)
    rootCmd.AddCommand(dumpCommand)
    rootCmd.Execute()
}
