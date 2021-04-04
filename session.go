package main

import (
    "crypto/ecdsa"
    "crypto/x509"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "strings"

    "gopkg.in/square/go-jose.v2"
)


type Directory struct {
    NewAccount string
    NewNonce string
    NewOrder string
}

type AcmeSession struct {
    nonce string
    directory Directory
    account string
    key *ecdsa.PrivateKey
    verbose bool
}

func NewAcmeSession(url string) *AcmeSession {
    s := AcmeSession {}
    s.verbose = true
    s.discover(url)
    return &s
}

func (s *AcmeSession) setVerbose(verbose bool) {
    s.verbose = verbose
}

func (s *AcmeSession) setKey(key *ecdsa.PrivateKey) {
    s.key = key
}

func (s *AcmeSession) setAccount(account string) {
    s.account = account
}

type AcmeAccountInfo struct {
    Key string
    Account string
}

func (s *AcmeSession) save(fname string) error {
    keybytes, err := x509.MarshalECPrivateKey(s.key)
    if err != nil {
        return err
    }
    account := AcmeAccountInfo {
        Key: hex.EncodeToString(keybytes),
        Account: s.account,
    }
    serialized, err := json.Marshal(&account)
    ioutil.WriteFile(fname, serialized, 0600)
    return nil
}

func (s *AcmeSession) load(fname string) error {
    serialized, err := ioutil.ReadFile(fname)
    if err != nil {
        return err
    }
    var parsed AcmeAccountInfo
    err = json.Unmarshal(serialized, &parsed)
    if err != nil {
        return err
    }
    keybin, err := hex.DecodeString(parsed.Key)
    if err != nil {
        return err
    }
    s.key, err = x509.ParseECPrivateKey(keybin)
    if err != nil {
        return err
    }
    s.account = parsed.Account
    return nil
}

func (s *AcmeSession) discover(url string) error {
    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return fmt.Errorf("unexpected http status %s", resp.Status)
    }

    var js struct {
        NewAccount string `json:"newAccount"`
        NewNonce   string `json:"newNonce"`
        NewOrder   string `json:"newOrder"`
        RevokeCert string `json:"revokeCert"`
        Meta   struct {
            Terms   string   `json:"termsOfService"`
        }
    }
    decoder := json.NewDecoder(resp.Body)
    err = decoder.Decode(&js)
    if err != nil {
        return err
    }
    if s.verbose {
        log.Println("acme directory:")
        log.Printf("  newAccount: %s\n", js.NewAccount)
        log.Printf("  newNonce:   %s\n", js.NewNonce)
        log.Printf("  newOrder:   %s\n", js.NewOrder)
    }
    s.directory = Directory {
        NewAccount: js.NewAccount,
        NewNonce: js.NewNonce,
        NewOrder: js.NewOrder,
    }
    return nil
}

func (s *AcmeSession) getNonce() string {
    if len(s.nonce) > 0 {
        return s.nonce
    }
    resp, err := http.Get(s.directory.NewNonce)
    if err != nil {
        log.Println(err)
        return ""
    }
    resp.Body.Close()
    s.nonce = resp.Header.Get("replay-nonce")
    return s.nonce
}

type NS struct {
    nonce string
}
func (ns NS)Nonce()(string, error) {
    return ns.nonce, nil
}

func (s *AcmeSession) postJWSNoRetry(url string, payload string) *http.Response {
    options := &jose.SignerOptions{}
    options.WithHeader("url", url)
    if len(s.account) > 0 {
        options.WithHeader("kid", s.account)
    } else {
        options.EmbedJWK = true
    }
    options.NonceSource = NS{
        s.getNonce(),
    }

    signingKey := jose.SigningKey{
        Algorithm: jose.ES256,
        Key: jose.JSONWebKey{
            Key:       s.key,
            Algorithm: string(jose.ES256),
        },
    }
    signer, err := jose.NewSigner(signingKey, options)
    if err != nil {
        panic(err)
    }
    jws, err := signer.Sign([]byte(payload))
    if err != nil {
        fmt.Printf("sign err: %s\n", err.Error())
    }
    output := jws.FullSerialize()
    if s.verbose {
        log.Printf("POST %s\n", url)
    }
    res, err := http.Post(url, "application/jose+json", strings.NewReader(output))
    if err == nil {
        s.nonce = res.Header.Get("replay-nonce")
        if s.verbose {
            fmt.Printf("got nonce: %s [%s]\n", res.Header.Get("replay-nonce"), url)
        }
    } else {
        log.Println(err)
    }
    return res
}

func (s *AcmeSession) postJWS(url string, payload string) *http.Response {
    res := s.postJWSNoRetry(url, payload)
    if res.StatusCode == 400 {
        if s.verbose {
            fmt.Println("JWS retry")
        }
        return s.postJWSNoRetry(url, payload)
    } else {
        return res
    }
}