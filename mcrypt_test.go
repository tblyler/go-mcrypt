package mcrypt

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand"
	"testing"
)

func TestEncrypt(t *testing.T) {
	dataSizes := []int{8, 13, 16, 32, 64, 1024, 1048576, 4194304, (mrand.Int() % 26214400) + 1}

	for _, dataSize := range dataSizes {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			t.Error("Failed to get random data from crypto/rand")
		}
		iv := make([]byte, 32)
		_, err = rand.Read(iv)
		if err != nil {
			t.Error("Failed to get random data from crypto/rand")
		}
		data := make([]byte, dataSize)
		_, err = rand.Read(data)
		if err != nil {
			t.Error("Failed to get random data from crypto/rand")
		}

		encrypted, err := Encrypt(key, iv, data)
		if err != nil {
			t.Error("Failed Encrypt with error: " + err.Error())
		}

		if bytes.Equal(encrypted, data) {
			t.Error("Failed Encrypt: Encrypted data was the same as input data")
		}

		decrypted, err := Decrypt(key, iv, encrypted)
		if err != nil {
			t.Error("Failed Decrypt with error: " + err.Error())
		}

		cryptLen := len(decrypted)
		for i := 0; i < cryptLen; i++ {
			if i >= dataSize {
				if decrypted[i] != 0 {
					t.Error("Failed encryption/decryption: invalid padding")
				}
			} else if decrypted[i] != data[i] {
				t.Error("Failed encryption/decryption: invalid data")
			}
		}
	}

	key := make([]byte, 31)
	iv := make([]byte, 32)
	data := make([]byte, 32)

	_, err := Encrypt(key, iv, data)
	if err == nil {
		t.Error("Failed to receive error for invalid key size")
	}

	key = make([]byte, 32)
	iv = make([]byte, 31)
	_, err = Encrypt(key, iv, data)
	if err == nil {
		t.Error("Failed to receive error for invalid iv size")
	}

	key = make([]byte, 32)
	iv = make([]byte, 32)
	_, err = Encrypt(key, iv, []byte{})
	if err == nil {
		t.Error("Failed to receive error for 0 byte data size")
	}
}

func TestDecrypt(t *testing.T) {
	dataSizes := []int{8, 13, 16, 32, 64, 1024, 1048576, 4194304, (mrand.Int() % 26214400) + 1}

	for _, dataSize := range dataSizes {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			t.Error("Failed to get random data from crypto/rand")
		}
		iv := make([]byte, 32)
		_, err = rand.Read(iv)
		if err != nil {
			t.Error("Failed to get random data from crypto/rand")
		}
		data := make([]byte, dataSize)
		_, err = rand.Read(data)
		if err != nil {
			t.Error("Failed to get random data from crypto/rand")
		}

		encrypted, err := Encrypt(key, iv, data)
		if err != nil {
			t.Error("Failed Encrypt with error: " + err.Error())
		}

		if bytes.Equal(encrypted, data) {
			t.Error("Failed Encrypt: Encrypted data was the same as input data")
		}

		decrypted, err := Decrypt(key, iv, encrypted)
		if err != nil {
			t.Error("Failed Decrypt with error: " + err.Error())
		}

		cryptLen := len(decrypted)
		for i := 0; i < cryptLen; i++ {
			if i >= dataSize {
				if decrypted[i] != 0 {
					t.Error("Failed encryption/decryption: invalid padding")
				}
			} else if decrypted[i] != data[i] {
				t.Error("Failed encryption/decryption: invalid data")
			}
		}
	}

	key := make([]byte, 31)
	iv := make([]byte, 32)
	data := make([]byte, 32)

	_, err := Decrypt(key, iv, data)
	if err == nil {
		t.Error("Failed to receive error for invalid key size")
	}

	key = make([]byte, 32)
	iv = make([]byte, 31)
	_, err = Decrypt(key, iv, data)
	if err == nil {
		t.Error("Failed to receive error for invalid iv size")
	}

	key = make([]byte, 32)
	iv = make([]byte, 32)
	data = make([]byte, 31)
	if err == nil {
		t.Error("Failed to receive error for invalid data size")
	}

	data = make([]byte, 0)
	if err == nil {
		t.Error("Failed to receive error for 0 byte data size")
	}
}
