package offline

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

func TestCreateKeytabWritesSelectedPasswordDerivedEntries(t *testing.T) {
	dir := t.TempDir()
	result, err := createKeytab(CreateKeytabRequest{
		Principal:       "HTTP/web.lab.local",
		Realm:           "LAB.LOCAL",
		Password:        "not stored",
		KVNO:            3,
		EncryptionTypes: []string{"aes256-cts-hmac-sha1-96", "rc4-hmac"},
		FileName:        "web.keytab",
	}, dir, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create keytab: %v", err)
	}
	if result.Path != filepath.Join(dir, "kraken_keytabs", "web.keytab") || len(result.EncryptionTypes) != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if info, err := os.Stat(result.Path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unexpected keytab permissions: %v, %v", info, err)
	}
	loaded, err := keytab.Load(result.Path)
	if err != nil || len(loaded.Entries) != 2 {
		t.Fatalf("load created keytab: entries=%d err=%v", len(loaded.Entries), err)
	}
}
