package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var configPath = "~/.kube/config"
var day float64 = 365

func main() {
	flag.StringVar(&configPath, "kubeConfig", "", "the kubeconfig")
	flag.Float64Var(&day, "day", 365, "min age")
	flag.Parse()
	config, err := clientcmd.BuildConfigFromFlags("", configPath)
	if err != nil {
		panic(err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}
	nsList, err := client.CoreV1().Namespaces().List(metav1.ListOptions{})
	if err != nil {
		panic(err)
	}

	for _, ns := range nsList.Items {
		ss, err := client.CoreV1().Secrets(ns.Name).List(metav1.ListOptions{})
		if err != nil {
			panic(err)
		}
		for _, s := range ss.Items {
			for k, v := range s.Data {
				if strings.Contains(k, "cert") || strings.Contains(k, "crt") {
					cert, err := parseTLSCert(v)
					if err != nil {
						log.Printf("[Warning] kube-system:[%s] secret:[%s] key:[%v] err:[%v] v:[%v]", ns.Name, s.Name, k, err, string(v))
						continue
					}
					expired := cert.NotAfter.Sub(cert.NotBefore).Hours()
					minAge := 24 * day
					if expired < minAge {
						log.Printf("kube-system:[%s/%s] key:[%v] time:[%v]", ns.Name, s.Name, k, expired)
					}
				}
			}
		}
	}
}

func parseTLSCert(cert []byte) (*x509.Certificate, error) {
	//cert, err := base64.StdEncoding.DecodeString(base64Str)
	//if err != nil {
	//	return nil, err
	//}
	certDERBlock, _ := pem.Decode(cert)
	if certDERBlock == nil {
		return nil, fmt.Errorf("pem decode failed")
	}
	x509Cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}
