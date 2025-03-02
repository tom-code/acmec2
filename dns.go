package main

import (
    "fmt"
    "time"

    "github.com/miekg/dns"
)


type Handler struct {
    token string
    host string
}


func (h *Handler)ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
    fmt.Printf("[dns] ======= req from:%s to %s opcode:%s id:%d status:%s\n", w.RemoteAddr().String(), w.LocalAddr().String(),
               dns.OpcodeToString[r.Opcode], r.Id, dns.RcodeToString[r.Rcode])
    m := new(dns.Msg)
    m.SetReply(r)
    m.Compress = false
    expectedHost := fmt.Sprintf("_acme-challenge.%s.", h.host)
    if (len(r.Question) < 1) || (r.Question[0].Name != expectedHost) {
        fmt.Printf("[dns] unexpected query - respond with error\n")
        m.Rcode = dns.RcodeNameError
        w.WriteMsg(m)
        return
    }
    txt := fmt.Sprintf(`%s 10 IN TXT "%s"`, r.Question[0].Name, h.token)
    fmt.Printf("[dns] responding %s\n", txt)
    record, _ := dns.NewRR(txt)
    m.Answer = append(m.Answer, record)
    m.Authoritative = true
    w.WriteMsg(m)
}

type dnsSrvCtx struct {
    udp *dns.Server
    tcp *dns.Server
}

func (ctx *dnsSrvCtx) Close() error {
    ctx.udp.Shutdown()
    ctx.tcp.Shutdown()
    return nil
}

func dnsCheck(addr string) bool {
    m := new(dns.Msg)
    m.SetQuestion("test.", dns.TypeTXT)
    c := new(dns.Client)
    in, _, err := c.Exchange(m, addr)
    if err != nil {
        fmt.Println(err)
        return false
    }
    if in == nil {
        return false
    }
    return true
}

func dnsStart(host string, token string, port string) *dnsSrvCtx {
    ctx := &dnsSrvCtx{}
    handler := &Handler{
        token: token,
        host: host,
    }
    ctx.udp = &dns.Server{
        Addr: ":"+port,
        Net: "udp",
        Handler: handler,
    }
    
    ctx.tcp = &dns.Server{
        Addr: ":"+port,
        Net: "tcp",
        Handler: handler,
    }

    go ctx.udp.ListenAndServe()
    go ctx.tcp.ListenAndServe()

    for !dnsCheck("localhost:"+port) {
        time.Sleep(100*time.Millisecond)
    }
    fmt.Println("dns started!")
    
    return ctx
}