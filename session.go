package main

import (
    "crypto/ecdsa"
    "crypto/tls"
    "crypto/x509"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "strings"
    "time"

    "gopkg.in/square/go-jose.v2"
)




type AcmeSession struct {
    nonce string
    directory Directory
    account string
    key *ecdsa.PrivateKey
    verbose bool
    client *http.Client
}

func NewAcmeSession(url string, insecure bool) (*AcmeSession, error){
    s := AcmeSession {}
    transport := &http.Transport {
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: insecure,
        },
        IdleConnTimeout: 10 * time.Second,
    }
    s.client = &http.Client{
        Transport: transport,
    }
    err := s.discover(url)
    if err != nil {
        return nil, err
    }
    return &s, nil
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
    resp, err := s.client.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return fmt.Errorf("unexpected http status %s", resp.Status)
    }

    d, err := parseDirectory(resp)
    if err != nil {
        return err
    }
    s.directory = *d
    if s.verbose {
        fmt.Println("acme directory:")
        fmt.Printf("  newAccount: %s\n", s.directory.NewAccount)
        fmt.Printf("  newNonce:   %s\n", s.directory.NewNonce)
        fmt.Printf("  newOrder:   %s\n", s.directory.NewOrder)
    }
    return nil
}

func (s *AcmeSession) getNonce() string {
    if len(s.nonce) > 0 {
        return s.nonce
    }
    resp, err := s.client.Get(s.directory.NewNonce)
    if err != nil {
        fmt.Println(err)
        return ""
    }
    resp.Body.Close()
    s.nonce = resp.Header.Get("replay-nonce")
    return s.nonce
}

type NS struct {
    nonce string
}
func (ns NS) Nonce() (string, error) {
    return ns.nonce, nil
}

func (s *AcmeSession) postJWSNoRetry(url string, payload string) (*http.Response, error) {
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
        return nil, err
    }
    jws, err := signer.Sign([]byte(payload))
    if err != nil {
        fmt.Printf("sign err: %s\n", err.Error())
    }
    output := jws.FullSerialize()
    if s.verbose {
        fmt.Printf("POST %s\n", url)
    }
    res, err := s.client.Post(url, "application/jose+json", strings.NewReader(output))
    if err == nil {
        s.nonce = res.Header.Get("replay-nonce")
        if s.verbose {
            fmt.Printf("got nonce: %s [%s]\n", res.Header.Get("replay-nonce"), url)
        }
    } else {
        return nil, err
    }
    return res, nil
}

func (s *AcmeSession) postJWS(url string, payload string) (*http.Response, []byte, error) {
    var res *http.Response
    var err error
    var body []byte
    for i:=0; i<5; i++ {  // how many wrong nonces wants pebble return ??
        res, err = s.postJWSNoRetry(url, payload)
        if err != nil {
            if s.verbose {
                fmt.Println(err)
            }
            continue
        }
        body, _ = ioutil.ReadAll(res.Body)
        res.Body.Close()
        if res.StatusCode == 400 {
            if s.verbose {
                fmt.Println("JWS retry")
            }
            continue
        } else {
            return res, body, nil
        }
    }
    if (err == nil) && (res != nil) {
        err = fmt.Errorf("%s\n%s", res.Status, string(body))
    }
    return res, []byte{}, fmt.Errorf("postJWS failed: %s", err)
}