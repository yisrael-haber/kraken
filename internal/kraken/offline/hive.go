package offline

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mandiant/gopacket/pkg/registry"
)

type ExtractHiveSecretsRequest struct {
	SystemPath   string `json:"systemPath"`
	SAMPath      string `json:"samPath,omitempty"`
	SecurityPath string `json:"securityPath,omitempty"`
	OutputPath   string `json:"outputPath"`
}

type ExtractHiveSecretsResult struct {
	OutputPath        string `json:"outputPath"`
	SAMUsers          int    `json:"samUsers"`
	LSASecrets        int    `json:"lsaSecrets"`
	CachedCredentials int    `json:"cachedCredentials"`
}

func ExtractHiveSecrets(request ExtractHiveSecretsRequest) (ExtractHiveSecretsResult, error) {
	request.SystemPath = strings.TrimSpace(request.SystemPath)
	request.SAMPath = strings.TrimSpace(request.SAMPath)
	request.SecurityPath = strings.TrimSpace(request.SecurityPath)
	request.OutputPath = strings.TrimSpace(request.OutputPath)
	if request.SystemPath == "" {
		return ExtractHiveSecretsResult{}, fmt.Errorf("SYSTEM hive is required")
	}
	if request.SAMPath == "" && request.SecurityPath == "" {
		return ExtractHiveSecretsResult{}, fmt.Errorf("select a SAM or SECURITY hive")
	}
	if request.OutputPath == "" {
		return ExtractHiveSecretsResult{}, fmt.Errorf("output file is required")
	}

	systemData, err := os.ReadFile(request.SystemPath)
	if err != nil {
		return ExtractHiveSecretsResult{}, fmt.Errorf("read SYSTEM hive: %w", err)
	}
	systemHive, err := registry.Open(systemData)
	if err != nil {
		return ExtractHiveSecretsResult{}, fmt.Errorf("parse SYSTEM hive: %w", err)
	}
	bootKey, err := registry.GetBootKey(systemHive)
	if err != nil {
		return ExtractHiveSecretsResult{}, fmt.Errorf("extract SYSTEM boot key: %w", err)
	}

	output, err := os.OpenFile(request.OutputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return ExtractHiveSecretsResult{}, fmt.Errorf("open output file: %w", err)
	}
	defer output.Close()
	result := ExtractHiveSecretsResult{OutputPath: request.OutputPath}

	if request.SAMPath != "" {
		users, err := extractSAM(request.SAMPath, bootKey)
		if err != nil {
			return ExtractHiveSecretsResult{}, err
		}
		if _, err := fmt.Fprintln(output, "[SAM]"); err != nil {
			return ExtractHiveSecretsResult{}, err
		}
		for _, user := range users {
			if _, err := fmt.Fprintf(output, "%s:%d:%s:%s:::\n", user.Username, user.RID, hex.EncodeToString(user.LMHash), hex.EncodeToString(user.NTHash)); err != nil {
				return ExtractHiveSecretsResult{}, err
			}
		}
		result.SAMUsers = len(users)
	}

	if request.SecurityPath != "" {
		secrets, credentials, err := extractSecurity(request.SecurityPath, bootKey)
		if err != nil {
			return ExtractHiveSecretsResult{}, err
		}
		if _, err := fmt.Fprintln(output, "[LSA secrets]"); err != nil {
			return ExtractHiveSecretsResult{}, err
		}
		for _, secret := range secrets {
			if _, err := fmt.Fprintf(output, "%s:%s\n", secret.Name, hex.EncodeToString(secret.Value)); err != nil {
				return ExtractHiveSecretsResult{}, err
			}
		}
		if _, err := fmt.Fprintln(output, "[Cached credentials]"); err != nil {
			return ExtractHiveSecretsResult{}, err
		}
		for _, credential := range credentials {
			if _, err := fmt.Fprintf(output, "%s/%s:%s\n", credential.Domain, credential.Username, hex.EncodeToString(credential.EncryptedHash)); err != nil {
				return ExtractHiveSecretsResult{}, err
			}
		}
		result.LSASecrets = len(secrets)
		result.CachedCredentials = len(credentials)
	}
	if err := output.Close(); err != nil {
		return ExtractHiveSecretsResult{}, fmt.Errorf("close output file: %w", err)
	}
	return result, nil
}

func extractSAM(path string, bootKey []byte) ([]registry.SAMUser, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SAM hive: %w", err)
	}
	hive, err := registry.Open(data)
	if err != nil {
		return nil, fmt.Errorf("parse SAM hive: %w", err)
	}
	users, err := registry.DumpSAM(hive, bootKey)
	if err != nil {
		return nil, fmt.Errorf("extract SAM secrets: %w", err)
	}
	return users, nil
}

func extractSecurity(path string, bootKey []byte) ([]registry.LSASecret, []registry.CachedCredential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read SECURITY hive: %w", err)
	}
	hive, err := registry.Open(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse SECURITY hive: %w", err)
	}
	secrets, err := registry.DumpLSASecrets(hive, bootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("extract LSA secrets: %w", err)
	}
	credentials, err := registry.DumpCachedCredentials(hive, bootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("extract cached credentials: %w", err)
	}
	return secrets, credentials, nil
}

func DefaultHiveSecretsOutputName(systemPath string) string {
	base := strings.TrimSuffix(filepath.Base(systemPath), filepath.Ext(systemPath))
	if base == "" || base == "." {
		base = "hive"
	}
	return base + "-secrets.txt"
}
