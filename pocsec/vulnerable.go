// Package pocsec contem codigo DELIBERADAMENTE VULNERAVEL.
//
// ATENCAO: este pacote existe apenas para validar a deteccao do CodeQL durante a
// POC de migracao do SAST (Checkmarx -> CodeQL). Nada aqui deve ser copiado,
// importado por codigo real ou usado como referencia de implementacao.
//
// Cada funcao abaixo aciona uma query especifica da suite go-security-extended.
package pocsec

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
)

// CWE-022 (TaintedPath): o caminho do arquivo vem direto da query string,
// permitindo "../../etc/passwd".
func DownloadHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")

	f, err := os.Open(name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	io.Copy(w, f)
}

// CWE-918 (RequestForgery / SSRF): a URL de destino e controlada pelo cliente,
// permitindo alcancar a rede interna (ex.: metadata do cloud provider).
func FetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")

	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	io.Copy(w, resp.Body)
}

// CWE-078 (CommandInjection): input do usuario concatenado num shell.
func PingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	if err != nil {
		http.Error(w, "ping failed", http.StatusInternalServerError)
		return
	}

	w.Write(out)
}

// CWE-079 (ReflectedXss): input refletido na resposta HTML sem escaping.
func GreetHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Ola, %s</h1>", name)
}

// CWE-327 (WeakSensitiveDataHashing): MD5 para hash de senha.
func HashPassword(password string) string {
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

// CWE-295 (DisabledCertificateCheck): validacao de certificado TLS desligada.
func InsecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

// CWE-338 (InsecureRandomness): gerador nao-criptografico para token de sessao.
func NewSessionToken() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return hex.EncodeToString(b)
}
