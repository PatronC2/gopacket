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

package main

import (
	"flag"
	"log"
	"os"

	"github.com/PatronC2/gopacket/lib/addcomputer"
	"github.com/PatronC2/gopacket/pkg/flags"
	"github.com/PatronC2/gopacket/pkg/session"
)

var (
	computerName  = flag.String("computer-name", "", "Name of the computer account to add (default: random)")
	computerPass  = flag.String("computer-pass", "", "Password for the computer account (default: random)")
	method        = flag.String("method", "SAMR", "Method to use: SAMR or LDAPS")
	baseDN        = flag.String("baseDN", "", "Specify the baseDN for LDAP (default: auto from domain)")
	computerGroup = flag.String("computer-group", "", "Group to add the computer to (LDAP method, default: CN=Computers)")
	noAdd         = flag.Bool("no-add", false, "Don't add a new computer, just set the password on an existing one")
	deleteAcct    = flag.Bool("delete", false, "Delete an existing computer")
	domainNetbios = flag.String("domain-netbios", "", "Domain NetBIOS name. Required if the DC has multiple domains.")
)

func main() {
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		log.Fatalf("[-] Error parsing target string: %v", err)
	}

	opts.ApplyToSession(&target, &creds)

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := addcomputer.Run(target, creds, addcomputer.Options{
		Method:        addcomputer.Method(*method),
		Action:        actionFromFlags(*noAdd, *deleteAcct),
		ComputerName:  *computerName,
		ComputerPass:  *computerPass,
		BaseDN:        *baseDN,
		ComputerGroup: *computerGroup,
		DomainNetBIOS: *domainNetbios,
		Out:           os.Stdout,
	}); err != nil {
		log.Fatalf("[-] %v", err)
	}
}

func actionFromFlags(noAdd, deleteAcct bool) addcomputer.Action {
	if deleteAcct {
		return addcomputer.ActionDelete
	}
	if noAdd {
		return addcomputer.ActionSetPassword
	}
	return addcomputer.ActionAdd
}
