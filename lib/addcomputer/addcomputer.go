// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package addcomputer provides a reusable API for creating, deleting, and
// changing passwords for Active Directory computer accounts.
package addcomputer

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"unicode/utf16"

	"github.com/PatronC2/gopacket/pkg/dcerpc"
	"github.com/PatronC2/gopacket/pkg/dcerpc/samr"
	"github.com/PatronC2/gopacket/pkg/ldap"
	"github.com/PatronC2/gopacket/pkg/session"
	"github.com/PatronC2/gopacket/pkg/smb"
)

// Method selects the protocol used to manage the computer account.
type Method string

const (
	MethodSAMR  Method = "SAMR"
	MethodLDAP  Method = "LDAP"
	MethodLDAPS Method = "LDAPS"
)

// Action selects the account operation to perform.
type Action string

const (
	ActionAdd         Action = "add"
	ActionSetPassword Action = "set-password"
	ActionDelete      Action = "delete"
)

// Options controls an addcomputer operation.
type Options struct {
	Method Method
	Action Action

	ComputerName string
	ComputerPass string

	BaseDN        string
	ComputerGroup string
	DomainNetBIOS string

	// Out receives progress and success messages. Leave nil for quiet operation.
	Out io.Writer
}

// Result contains the normalized account details used by the operation.
type Result struct {
	ComputerName string
	SAMAccount   string
	Password     string
	DN           string
	Method       Method
	Action       Action
}

// Run performs an addcomputer operation using the supplied target and credentials.
func Run(target session.Target, creds session.Credentials, opts Options) (*Result, error) {
	opts = normalizeOptions(opts)

	if opts.ComputerName == "" && opts.Action == ActionAdd {
		opts.ComputerName = GenerateRandomName()
	}
	if opts.ComputerName == "" {
		return nil, fmt.Errorf("computer name is required for %s", opts.Action)
	}
	if opts.ComputerPass == "" && opts.Action != ActionDelete {
		opts.ComputerPass = GenerateRandomPassword()
	}

	name := strings.TrimSuffix(opts.ComputerName, "$")
	result := &Result{
		ComputerName: name,
		SAMAccount:   name + "$",
		Password:     opts.ComputerPass,
		Method:       opts.Method,
		Action:       opts.Action,
	}

	switch opts.Method {
	case MethodSAMR:
		if err := runSAMR(target, creds, opts, result); err != nil {
			return nil, err
		}
	case MethodLDAP, MethodLDAPS:
		if err := runLDAP(target, creds, opts, result); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown method %q: use SAMR or LDAPS", opts.Method)
	}

	return result, nil
}

func normalizeOptions(opts Options) Options {
	if opts.Method == "" {
		opts.Method = MethodSAMR
	}
	opts.Method = Method(strings.ToUpper(string(opts.Method)))

	if opts.Action == "" {
		opts.Action = ActionAdd
	}
	opts.Action = Action(strings.ToLower(string(opts.Action)))

	return opts
}

func runSAMR(target session.Target, creds session.Credentials, opts Options, result *Result) error {
	if target.Port == 0 {
		target.Port = 445
	}

	logf(opts.Out, "[*] Connecting to %s via SMB...\n", target.Addr())
	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		return fmt.Errorf("SMB connection failed: %w", err)
	}
	defer smbClient.Close()
	logf(opts.Out, "[+] SMB session established.\n")

	sessionKey := smbClient.GetSessionKey()
	if len(sessionKey) == 0 {
		return fmt.Errorf("failed to obtain SMB session key")
	}

	pipe, err := smbClient.OpenPipe("samr")
	if err != nil {
		return fmt.Errorf("failed to open SAMR pipe: %w", err)
	}

	rpcClient := dcerpc.NewClient(pipe)
	if err := rpcClient.Bind(samr.UUID, samr.MajorVersion, samr.MinorVersion); err != nil {
		return fmt.Errorf("SAMR bind failed: %w", err)
	}
	logf(opts.Out, "[+] SAMR bind successful.\n")

	samrClient := samr.NewSamrClient(rpcClient, sessionKey)
	if err := samrClient.Connect(); err != nil {
		return fmt.Errorf("SamrConnect5 failed: %w", err)
	}
	defer samrClient.Close()

	selectedDomain, err := selectSAMRDomain(samrClient, creds.Domain, opts.DomainNetBIOS)
	if err != nil {
		return err
	}
	if err := samrClient.OpenDomain(selectedDomain); err != nil {
		return fmt.Errorf("failed to open domain %s: %w", selectedDomain, err)
	}

	switch opts.Action {
	case ActionDelete:
		if err := samrClient.DeleteComputer(result.ComputerName); err != nil {
			return fmt.Errorf("failed to delete %s: %w", result.SAMAccount, err)
		}
		logf(opts.Out, "[*] Successfully deleted %s.\n", result.SAMAccount)
	case ActionSetPassword:
		if err := samrClient.SetComputerPassword(result.ComputerName, opts.ComputerPass); err != nil {
			return fmt.Errorf("failed to set password of %s: %w", result.SAMAccount, err)
		}
		logf(opts.Out, "[*] Successfully set password of %s to %s.\n", result.SAMAccount, opts.ComputerPass)
	case ActionAdd:
		if samrClient.AccountExists(result.ComputerName) {
			return fmt.Errorf("account %s already exists: use ActionSetPassword to change the password", result.SAMAccount)
		}
		if err := samrClient.CreateComputer(result.ComputerName, opts.ComputerPass); err != nil {
			if strings.Contains(err.Error(), "0xc0000022") {
				return fmt.Errorf("user does not have the right to create a machine account: machine account quota may have been exceeded")
			}
			return fmt.Errorf("failed to create %s: %w", result.SAMAccount, err)
		}
		logf(opts.Out, "[*] Successfully added machine account %s with password %s.\n", result.SAMAccount, opts.ComputerPass)
	default:
		return fmt.Errorf("unknown action %q", opts.Action)
	}

	return nil
}

func selectSAMRDomain(client *samr.SamrClient, credentialDomain, requestedNetBIOS string) (string, error) {
	netbiosName := requestedNetBIOS
	if netbiosName == "" {
		netbiosName = credentialDomain
	}
	if netbiosName == "" {
		return "", fmt.Errorf("domain name required")
	}

	domains, err := client.EnumerateDomains()
	if err != nil {
		return "", fmt.Errorf("failed to enumerate domains: %w", err)
	}

	var nonBuiltin []string
	for _, d := range domains {
		if !strings.EqualFold(d, "Builtin") {
			nonBuiltin = append(nonBuiltin, d)
		}
	}

	if len(nonBuiltin) == 1 {
		return nonBuiltin[0], nil
	}
	if len(nonBuiltin) == 0 {
		return "", fmt.Errorf("no non-Builtin domains found on the server")
	}

	for _, d := range nonBuiltin {
		if strings.EqualFold(d, netbiosName) {
			return d, nil
		}
	}

	return "", fmt.Errorf("server provides multiple domains and %q is not one of them; available domains: %s", netbiosName, strings.Join(domains, ", "))
}

func runLDAP(target session.Target, creds session.Credentials, opts Options, result *Result) error {
	if target.Port == 0 {
		target.Port = 636
	}

	logf(opts.Out, "[*] Connecting to %s via LDAPS...\n", target.Addr())
	client := ldap.NewClient(target, &creds)
	defer client.Close()

	if err := client.Connect(true); err != nil {
		return fmt.Errorf("LDAPS connection failed: %w", err)
	}

	if creds.Domain != "" && creds.Hash == "" && !creds.UseKerberos && os.Getenv("GOPACKET_NO_UPN") == "" {
		creds.Username = fmt.Sprintf("%s@%s", creds.Username, creds.Domain)
		creds.Domain = ""
	}

	logf(opts.Out, "[*] Binding as %s...\n", creds.Username)
	if err := client.Login(); err != nil {
		return fmt.Errorf("LDAP bind failed: %w", err)
	}
	logf(opts.Out, "[+] LDAP bind successful.\n")

	domainBase := opts.BaseDN
	if domainBase == "" {
		var err error
		domainBase, err = client.GetDefaultNamingContext()
		if err != nil {
			return fmt.Errorf("failed to get base DN: %w", err)
		}
	}

	container := "CN=Computers"
	if opts.ComputerGroup != "" {
		container = opts.ComputerGroup
	}

	computerDN := fmt.Sprintf("CN=%s,%s,%s", result.ComputerName, container, domainBase)
	result.DN = computerDN

	switch opts.Action {
	case ActionDelete:
		if err := client.Delete(computerDN); err != nil {
			return fmt.Errorf("failed to delete %s: %w", result.SAMAccount, err)
		}
		logf(opts.Out, "[*] Successfully deleted %s.\n", result.SAMAccount)
	case ActionSetPassword:
		encodedPwd := encodeUTF16LE(fmt.Sprintf("\"%s\"", opts.ComputerPass))
		changes := []ldap.ModifyChange{
			{Operation: 2, AttrName: "unicodePwd", AttrVals: []string{string(encodedPwd)}},
		}
		if err := client.Modify(computerDN, changes); err != nil {
			return fmt.Errorf("failed to set password of %s: %w", result.SAMAccount, err)
		}
		logf(opts.Out, "[*] Successfully set password of %s to %s.\n", result.SAMAccount, opts.ComputerPass)
	case ActionAdd:
		filter := fmt.Sprintf("(sAMAccountName=%s)", result.SAMAccount)
		searchResult, err := client.Search(domainBase, filter, []string{"dn"})
		if err == nil && len(searchResult.Entries) > 0 {
			return fmt.Errorf("account %s already exists: use ActionSetPassword to change the password", result.SAMAccount)
		}

		domainParts := parseDNToDomain(domainBase)
		fqdn := fmt.Sprintf("%s.%s", result.ComputerName, domainParts)
		encodedPwd := encodeUTF16LE(fmt.Sprintf("\"%s\"", opts.ComputerPass))

		attrs := map[string][]string{
			"objectClass":        {"top", "person", "organizationalPerson", "user", "computer"},
			"sAMAccountName":     {result.SAMAccount},
			"userAccountControl": {"4096"},
			"dNSHostName":        {fqdn},
			"servicePrincipalName": {
				"HOST/" + result.ComputerName,
				"HOST/" + fqdn,
				"RestrictedKrbHost/" + result.ComputerName,
				"RestrictedKrbHost/" + fqdn,
			},
			"unicodePwd": {string(encodedPwd)},
		}

		if err := client.Add(computerDN, attrs); err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "Unwilling To Perform") || strings.Contains(errStr, "0x216D") {
				return fmt.Errorf("failed to add %s: machine account quota exceeded", result.SAMAccount)
			}
			if strings.Contains(errStr, "Insufficient Access") {
				return fmt.Errorf("user does not have sufficient access rights to create a machine account")
			}
			return fmt.Errorf("failed to create %s: %w", result.SAMAccount, err)
		}
		logf(opts.Out, "[*] Successfully added machine account %s with password %s.\n", result.SAMAccount, opts.ComputerPass)
	default:
		return fmt.Errorf("unknown action %q", opts.Action)
	}

	return nil
}

func logf(w io.Writer, format string, args ...interface{}) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format, args...)
}

// parseDNToDomain converts "DC=corp,DC=local" to "corp.local".
func parseDNToDomain(dn string) string {
	var parts []string
	for _, component := range strings.Split(dn, ",") {
		component = strings.TrimSpace(component)
		if strings.HasPrefix(strings.ToUpper(component), "DC=") {
			parts = append(parts, component[3:])
		}
	}
	return strings.Join(parts, ".")
}

// encodeUTF16LE encodes a string as UTF-16LE bytes.
func encodeUTF16LE(s string) []byte {
	utf16Chars := utf16.Encode([]rune(s))
	b := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

// GenerateRandomName creates a random computer name like "DESKTOP-XXXXXXXX".
func GenerateRandomName() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 8)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return "DESKTOP-" + string(b)
}

// GenerateRandomPassword creates a random 32-character password.
func GenerateRandomPassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}
