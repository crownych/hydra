package pkg

import (
	"fmt"
	"github.com/ory/go-convenience/stringslice"
	"log"
)

func SendCommitCode(recipient, title, commitCode string) {
	if stringslice.Has([]string{"foo.bar", "auth.admin"}, recipient) {
		return
	}
	_, err := SendTextMail(recipient+"@104.com.tw", title, "commit_code: "+commitCode)
	if err != nil {
		log.Println(fmt.Sprintf(`send commit_code to "%s" failed`, recipient))
	}
}