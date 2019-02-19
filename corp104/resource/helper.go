package resource

import (
	"fmt"
	"github.com/ory/hydra/pkg"
	"github.com/spf13/viper"
	"log"
	"strings"
)

func sendCommitCode(recipient, commitCode string) {
	if recipient == "foo.bar" || strings.Contains(viper.GetString("ADMIN_USERS"), recipient) {
		return
	}
	_, err := pkg.SendTextMail(recipient+"@104.com.tw", "Resource註冊確認碼", "commit_code: "+commitCode)
	if err != nil {
		log.Println(fmt.Sprintf(`send commit_code to %s failed`, recipient))
	}
}

func hasDuplicates(ss []string) bool {
	vm := map[string]int{}
	for _, v := range ss {
		if vm[v] == 0 {
			vm[v] = 1
		} else {
			return true
		}
	}
	return false
}
