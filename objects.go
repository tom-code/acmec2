package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
)

type Directory struct {
    NewAccount string
    NewNonce string
    NewOrder string
}

type Order struct {
    Status string
    Authorizations []string
    FinalizeUrl string
    OrderUrl string
    Certificate string
}

type AuthChallenge struct {
    Type string
    Url string
    Token string
    Status string
}

type AuthObject struct {
    Status string
    Challenges []AuthChallenge
}


func parseOrderResponse(resp *http.Response, body []byte) (*Order, error) {
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
    fmt.Println(string(body))
    err := json.Unmarshal(body, &js)
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

func (ao *AuthObject) getChallenge(typ string) (*AuthChallenge, error) {
    for _, c := range ao.Challenges {
        if c.Type == typ {
            return &c, nil
        }
    }
    return nil, fmt.Errorf("challenge of type %s not found", typ)
}

func parseAuth(resp *http.Response, body []byte) (*AuthObject, error) {
    if resp.StatusCode != 200 {
        fmt.Println(resp.Status)
        msg, _ := ioutil.ReadAll(resp.Body)
        resp.Body.Close()
        fmt.Println(string(msg))
        return nil, fmt.Errorf("unexpected status %s", resp.Status)
    }
    defer resp.Body.Close()
    var js struct {
        Status string `json:"status"`
        Challenges []struct {
            Type  string `json:"type"`
            Url   string `json:"url"`
            Token string `json:"token"`
        } `json:"challenges"`
    }
    fmt.Println(string(body))
    err := json.Unmarshal(body, &js)
    if err != nil {
        return nil, err
    }
    au := AuthObject {
        Status: js.Status,
    }

    for _, ch := range(js.Challenges) {
        c := AuthChallenge {
            Type: ch.Type,
            Url: ch.Url,
            Token: ch.Token,
        }
        au.Challenges = append(au.Challenges, c)

    }
    return &au, nil
}

func parseDirectory(resp *http.Response) (*Directory, error) {
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
    err := decoder.Decode(&js)
    if err != nil {
        return nil, err
    }

    return &Directory {
        NewAccount: js.NewAccount,
        NewNonce: js.NewNonce,
        NewOrder: js.NewOrder,
    }, nil
}