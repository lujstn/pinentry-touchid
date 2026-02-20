// Copyright (c) 2021 Jorge Luis Betancourt. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/foxcpp/go-assuan/common"
	"github.com/foxcpp/go-assuan/pinentry"
	"github.com/keybase/go-keychain"
)

const (
	emptyPassword = ""
	testPassword  = "toomanysecrets2"
	keyDesc       = `Please enter the passphrase to unlock the OpenPGP secret key:
"Firstname Lastname <test@email.com>"
2048-bit RSA key, ID 61AF059BD632F971,
created 2021-01-01 (main key ID 70D56DF4CA30DE16).
`
	keyInfo = "n/8043823CBC5C5A0C66866520F333076D"
)

var (
	failedAuthFn     = func(reason string) (bool, error) { return false, nil }
	successfulAuthFn = func(reason string) (bool, error) { return true, nil }
	dummyPrompt      = func(s pinentry.Settings) ([]byte, error) { return []byte{}, nil }
)

func TestStoreEntryInKeychain(t *testing.T) {
	err := storePasswordInKeychain("sampleLabel", "keyInfo", []byte(testPassword))

	if err != nil {
		t.Fatalf("storing entry in the Keychain should succeed: %s", err)
	}
}

func TestGetPasswordFromKeychain(t *testing.T) {
	defer func() {
		err := cleanKeychain("sampleLabel")

		if err != nil {
			t.Fatalf("failed to clear entry from Keychain: %s", err)
		}
	}()

	pass, err := passwordFromKeychain("sampleLabel")

	if err != nil {
		t.Fatalf("fetch entry from Keychain should succeed: %s", err)
	}

	if pass != testPassword {
		t.Fatalf("password mismatch got: %s want: %s", pass, testPassword)
	}
}

func TestGetPINSuccessfulAuthentication(t *testing.T) {
	keychainLabel := `Firstname Lastname <test@email.com> (61AF059BD632F971)`
	defer func() { _ = cleanKeychain(keychainLabel) }()

	params := pinentry.Settings{
		Desc:    keyDesc,
		KeyInfo: keyInfo,
	}

	err := storePasswordInKeychain(keychainLabel, keyInfo, []byte(testPassword))
	if err != nil {
		t.Fatalf("failed precreating entry in the Keychain: %s", err)
	}

	logger := &log.Logger{}
	logger.SetOutput(ioutil.Discard)

	fn := GetPIN(successfulAuthFn, dummyPrompt, logger)
	pass, pinErr := fn(params)

	if pinErr != nil {
		t.Fatalf("call to GetPIN should succeed: %s", err)
	}

	if pass != testPassword {
		t.Fatalf("password mismatch got: %s want: %s", pass, testPassword)
	}
}

func TestGetPINUnsuccessfulAuthentication(t *testing.T) {
	keychainLabel := `Firstname Lastname <test@email.com> (61AF059BD632F971)`
	defer func() { _ = cleanKeychain(keychainLabel) }()

	logger := log.New(ioutil.Discard, "", 0)

	params := pinentry.Settings{
		Desc:    keyDesc,
		KeyInfo: keyInfo,
	}

	err := storePasswordInKeychain(keychainLabel, keyInfo, []byte(testPassword))
	if err != nil {
		t.Fatalf("failed precreating entry in the Keychain: %s", err)
	}

	fn := GetPIN(failedAuthFn, dummyPrompt, logger)
	pass, pinErr := fn(params)

	if pinErr != nil {
		t.Fatalf("call to GetPIN should succeed: %s", pinErr)
	}

	if pass != emptyPassword {
		t.Fatalf("password mismatch got: %s want: %s", pass, testPassword)
	}
}

func TestEntryNotInKeychain(t *testing.T) {
	keychainLabel := `Firstname Lastname <test@email.com> (61AF059BD632F971)`
	defer func() { _ = cleanKeychain(keychainLabel) }()

	logger := log.New(ioutil.Discard, "", 0)
	params := pinentry.Settings{
		Desc:    keyDesc,
		KeyInfo: keyInfo,
	}

	// initially the entry for the test key is not in the keychain
	if pass, err := passwordFromKeychain(keychainLabel); err == nil || pass != "" {
		t.Fatalf("unexpected entry found in the keychain: %s", keychainLabel)
	}

	fallBack := false
	validPinFn := func(s pinentry.Settings) ([]byte, error) {
		fallBack = true
		return []byte(testPassword), nil
	}
	fn := GetPIN(successfulAuthFn, validPinFn, logger)
	pass, pinErr := fn(params)
	if pinErr != nil {
		t.Fatalf("call to GetPIN should succeed: %s", pinErr)
	}

	if !fallBack {
		t.Fatalf("the fallback password prompt should have been called")
	}

	if pass != testPassword {
		t.Fatalf("password mismatch got: %s want: %s", pass, testPassword)
	}

	// after the successful run of GetPIN the entry should be present in the keychain
	if pass, err := passwordFromKeychain(keychainLabel); err != nil || pass == "" {
		t.Fatalf("missing entry from the keychain: %s", keychainLabel)
	}
}

// Removes a matching entry from the "main" keychain.
// Since the item gets added in the same process, i.e temporal build while executing the test, it
// shouldn't request the password from the user.
func cleanKeychain(label string) error {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetLabel(label)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	return keychain.DeleteItem(query)
}

func TestWithLoggerDoesNotPanic(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	client := WithLogger(logger)
	if client.logger == nil {
		t.Fatal("expected logger to be set")
	}
}

func TestNewGracefulLogFileHandling(t *testing.T) {
	// Save and restore DefaultLogLocation
	origLocation := DefaultLogLocation
	defer func() { DefaultLogLocation = origLocation }()

	// Point to an unwritable path
	dir := t.TempDir()
	unwritable := filepath.Join(dir, "noperm")
	if err := os.Mkdir(unwritable, 0000); err != nil {
		t.Fatalf("failed to create unwritable dir: %v", err)
	}
	DefaultLogLocation = filepath.Join(unwritable, "test.log")

	// New() should not panic — it should fall back to stderr
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("New() panicked when log file is unwritable: %v", r)
		}
	}()

	client := New()
	if client.logger == nil {
		t.Fatal("expected logger to be set even with unwritable log path")
	}
}

func TestGetInfoHandler(t *testing.T) {
	tests := []struct {
		name      string
		params    string
		wantData  string
		wantError bool
		errorCode int
	}{
		{
			name:      "flavor",
			params:    "flavor",
			wantData:  "touchid",
			wantError: false,
		},
		{
			name:      "version",
			params:    "version", 
			wantData:  version,
			wantError: false,
		},
		{
			name:      "pid",
			params:    "pid",
			wantData:  strconv.Itoa(os.Getpid()),
			wantError: false,
		},
		{
			name:      "ttyinfo",
			params:    "ttyinfo",
			wantData:  strings.TrimSpace(os.Getenv("GPG_TTY") + " " + strconv.Itoa(os.Getppid()) + " " + os.Getenv("TERM")),
			wantError: false,
		},
		{
			name:      "unknown",
			params:    "unknown",
			wantError: true,
			errorCode: int(common.ErrNotFound),
		},
		{
			name:      "empty",
			params:    "",
			wantError: true,
			errorCode: int(common.ErrAssInvValue),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := getInfoHandler(&buf, nil, tt.params)

			if tt.wantError {
				if err == nil {
					t.Errorf("expected error but got nil")
				} else if int(err.Code) != tt.errorCode {
					t.Errorf("expected error code %d but got %d", tt.errorCode, int(err.Code))
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				
				// Check that data was written
				output := buf.String()
				if !strings.Contains(output, tt.wantData) {
					t.Errorf("expected output to contain %q but got %q", tt.wantData, output)
				}
			}
		})
	}
}
