package main

import (
    "crypto/x509"
    "encoding/hex"
    "encoding/pem"
    "fmt"
    "io/ioutil"

    "github.com/spf13/cobra"
)



func dumpPEMFile(fname string) error {
    data, err := ioutil.ReadFile(fname)
    if err != nil {
        return err
    }

    for len(data) > 0 {
        block, data_rest := pem.Decode(data)
        if block == nil {
            break
        }
        data = data_rest
        fmt.Printf("***** %s\n", block.Type)
        switch block.Type {
        case "CERTIFICATE":
            cert, err := x509.ParseCertificate(block.Bytes)
            if err != nil {
                fmt.Println(err)
            } else {
                fmt.Printf("  dns names  : %s\n", cert.DNSNames)
                fmt.Printf("  issuer     : %s\n", cert.Issuer.String())
                fmt.Printf("  subject    : %s\n", cert.Subject.String())
                fmt.Printf("  valid_from : %s\n", cert.NotBefore)
                fmt.Printf("  valid_to   : %s\n", cert.NotAfter)
                fmt.Printf("  is_ca      : %t\n", cert.IsCA)
                fmt.Printf("  pl_algo    : %s\n", cert.PublicKeyAlgorithm.String())
                fmt.Printf("  serial     : %s\n", cert.SerialNumber.Text(16))
                /*fmt.Printf("  extensions : \n")
                for _, ext := range cert.Extensions {
                    fmt.Printf("    id : %s\n", ext.Id.String())
                    fmt.Printf("    val: %s\n", hex.EncodeToString(ext.Value))
                }*/
            }
        }
        fmt.Println("")
    }

    return nil
}

func dumpPEM(cmd *cobra.Command, args []string) {
    dumpPEMFile(args[0])
}


func pemkey2hexdata(cmd *cobra.Command, args []string){
    data, err := ioutil.ReadFile(args[0])
    if err != nil {
        fmt.Println(err)
        return
    }
    block, _ := pem.Decode(data)
    str := hex.EncodeToString(block.Bytes)
    fmt.Println(str)
}