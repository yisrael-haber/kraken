package offline

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/yisrael-haber/kraken/internal/kraken/storage"
)

type CreateKeytabRequest struct {
	Principal       string   `json:"principal"`
	Realm           string   `json:"realm"`
	Password        string   `json:"password"`
	KVNO            int      `json:"kvno"`
	EncryptionTypes []string `json:"encryptionTypes"`
	FileName        string   `json:"fileName,omitempty"`
}

type CreateKeytabResult struct {
	Path            string   `json:"path"`
	Principal       string   `json:"principal"`
	Realm           string   `json:"realm"`
	KVNO            int      `json:"kvno"`
	EncryptionTypes []string `json:"encryptionTypes"`
	CreatedAt       string   `json:"createdAt"`
}

type encryptionType struct {
	name string
	id   int32
}

var supportedEncryptionTypes = []encryptionType{
	{name: "aes256-cts-hmac-sha1-96", id: etypeID.AES256_CTS_HMAC_SHA1_96},
	{name: "aes128-cts-hmac-sha1-96", id: etypeID.AES128_CTS_HMAC_SHA1_96},
	{name: "aes256-cts-hmac-sha384-192", id: etypeID.AES256_CTS_HMAC_SHA384_192},
	{name: "aes128-cts-hmac-sha256-128", id: etypeID.AES128_CTS_HMAC_SHA256_128},
	{name: "rc4-hmac", id: etypeID.RC4_HMAC},
	{name: "des3-cbc-sha1-kd", id: etypeID.DES3_CBC_SHA1_KD},
}

func CreateKeytab(request CreateKeytabRequest) (CreateKeytabResult, error) {
	downloads, err := storage.DefaultDownloadsDir()
	if err != nil {
		return CreateKeytabResult{}, err
	}
	return createKeytab(request, downloads, time.Now())
}

func createKeytab(request CreateKeytabRequest, downloads string, now time.Time) (CreateKeytabResult, error) {
	principal := strings.TrimSpace(request.Principal)
	realm := strings.TrimSpace(request.Realm)
	if principal == "" {
		return CreateKeytabResult{}, fmt.Errorf("principal is required")
	}
	if realm == "" {
		return CreateKeytabResult{}, fmt.Errorf("realm is required")
	}
	if request.Password == "" {
		return CreateKeytabResult{}, fmt.Errorf("password is required")
	}
	if request.KVNO < 0 || request.KVNO > 255 {
		return CreateKeytabResult{}, fmt.Errorf("KVNO must be between 0 and 255")
	}
	types, err := selectedEncryptionTypes(request.EncryptionTypes)
	if err != nil {
		return CreateKeytabResult{}, err
	}
	fileName, err := keytabFileName(request.FileName, principal)
	if err != nil {
		return CreateKeytabResult{}, err
	}

	keytabFile := keytab.New()
	for _, encryption := range types {
		if err := keytabFile.AddEntry(principal, realm, request.Password, now, uint8(request.KVNO), encryption.id); err != nil {
			return CreateKeytabResult{}, fmt.Errorf("create %s entry: %w", encryption.name, err)
		}
	}
	contents, err := keytabFile.Marshal()
	if err != nil {
		return CreateKeytabResult{}, fmt.Errorf("marshal keytab: %w", err)
	}
	outputDir := filepath.Join(downloads, "kraken_keytabs")
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return CreateKeytabResult{}, fmt.Errorf("create keytab directory: %w", err)
	}
	path := filepath.Join(outputDir, fileName)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			return CreateKeytabResult{}, fmt.Errorf("keytab already exists: %s", path)
		}
		return CreateKeytabResult{}, fmt.Errorf("create keytab: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return CreateKeytabResult{}, fmt.Errorf("write keytab: %w", err)
	}
	if err := file.Close(); err != nil {
		return CreateKeytabResult{}, fmt.Errorf("close keytab: %w", err)
	}

	result := CreateKeytabResult{
		Path:      path,
		Principal: principal,
		Realm:     realm,
		KVNO:      request.KVNO,
		CreatedAt: now.Format(time.RFC3339),
	}
	for _, encryption := range types {
		result.EncryptionTypes = append(result.EncryptionTypes, encryption.name)
	}
	return result, nil
}

func selectedEncryptionTypes(requested []string) ([]encryptionType, error) {
	selected := make(map[string]bool, len(requested))
	for _, name := range requested {
		name = strings.TrimSpace(name)
		if name != "" {
			selected[name] = true
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("select at least one encryption type")
	}
	result := make([]encryptionType, 0, len(selected))
	for _, encryption := range supportedEncryptionTypes {
		if selected[encryption.name] {
			result = append(result, encryption)
			delete(selected, encryption.name)
		}
	}
	for name := range selected {
		return nil, fmt.Errorf("unsupported encryption type %q", name)
	}
	return result, nil
}

func keytabFileName(value, principal string) (string, error) {
	name := strings.TrimSpace(value)
	if name == "" {
		name = safeKeytabName(principal)
	}
	if filepath.Base(name) != name || name == "." || name == ".." {
		return "", fmt.Errorf("file name must not contain a directory")
	}
	if !strings.HasSuffix(strings.ToLower(name), ".keytab") {
		name += ".keytab"
	}
	return name, nil
}

func safeKeytabName(principal string) string {
	var value strings.Builder
	for _, char := range principal {
		if unicode.IsLetter(char) || unicode.IsDigit(char) || char == '.' || char == '-' || char == '_' {
			value.WriteRune(char)
		} else {
			value.WriteByte('_')
		}
	}
	name := strings.Trim(value.String(), "._")
	if name == "" {
		name = "keytab"
	}
	return name + ".keytab"
}
