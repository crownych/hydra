package client

import (
	"fmt"
	"github.com/ory/go-convenience/stringslice"
	"github.com/ory/hydra/pkg"
	"log"
)

func hasStrings(s1 []string, s2 ...string) bool {
	if len(s2) == 0 {
		return false
	}
	for _, needle := range s2 {
		if !stringslice.Has(s1, needle) {
			return false
		}
	}
	return true
}

func sendCommitCode(recipient, commitCode string) {
	if recipient == "foo.bar" {
		return
	}
	_, err := pkg.SendTextMail(recipient+"@104.com.tw", "Client註冊確認碼", "commit_code: "+commitCode)
	if err != nil {
		log.Println(fmt.Sprintf(`send commit_code to "%s" failed`, recipient))
	}
}
