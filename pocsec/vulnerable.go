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

// CORRIGIDO (era CWE-022 / TaintedPath).
// O input do usuario agora e apenas uma CHAVE de allowlist; o caminho real vem
// de um mapa fixo. Como o valor nao deriva mais da request, o fluxo de taint e
// interrompido e o CodeQL deixa de reportar.
var downloadPaths = map[string]string{
	"report": "/var/data/report.csv",
	"audit":  "/var/data/audit.log",
}

func DownloadHandler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("file")

	path, ok := downloadPaths[key]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	f, err := os.Open(path)
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

// CORRIGIDO (era CWE-078 / CommandInjection).
// Duas mudancas: (1) o endereco vem de allowlist, nao da request; (2) o comando
// e invocado com argumentos separados, sem passar por "sh -c", eliminando a
// interpretacao de metacaracteres de shell.
var pingTargets = map[string]string{
	"prod":  "10.0.0.1",
	"stage": "10.0.1.1",
}

func PingHandler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("target")

	addr, ok := pingTargets[key]
	if !ok {
		http.Error(w, "unknown target", http.StatusBadRequest)
		return
	}

	out, err := exec.Command("ping", "-c", "1", addr).Output()
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
