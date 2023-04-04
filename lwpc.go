package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"os"

	"github.com/go-ldap/ldap/v3"
)

func main() {
	weakPasswordPtr := flag.String("wp", "./password.txt", "weakpassword file path")
	ladpServerPtr := flag.String("s", "ldap://127.0.0.1:389", "ldap server address")
	userFilterPtr := flag.String("f", "(objectClass=organizationalPerson)", "user filter")
	baseDnPtr := flag.String("b", "dc=example,dc=com", "base dn")
	usernamePtr := flag.String("u", "admin", "bind user")
	passwordPtr := flag.String("p", "666", "bind user password")
	flag.Parse()

	// read weak password file
	pwdFile, err := os.OpenFile(*weakPasswordPtr, os.O_RDONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer pwdFile.Close()

	// connect to ldap server
	l, err := ldap.DialURL(*ladpServerPtr)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	err = l.Bind(*usernamePtr, *passwordPtr)
	if err != nil {
		panic(err)
	}
	userSearchRequest := ldap.NewSearchRequest(
		*baseDnPtr,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		*userFilterPtr,
		[]string{"dn"},
		nil,
	)
	result, err := l.Search(userSearchRequest)
	if err != nil {
		panic(err)
	}
	log.Printf("%d user found, start check password\n", len(result.Entries))

	for _, entry := range result.Entries {
		// return file head
		_, _ = pwdFile.Seek(0, 0)
		for {
			password, _, err := bufio.NewReader(pwdFile).ReadLine()
			if err == io.EOF {
				log.Printf("user: %s check passed\n", entry.DN)
				break
			}
			err = l.Bind(entry.DN, string(password))
			if err == nil {
				log.Printf("WARNING: user: %s use weak password: %s\n", entry.DN, password)
				break
			}
		}
	}
}
