package pkg

import (
	"github.com/spf13/viper"
	"strings"
)

func IsAdminUser(user string) bool {
	adminUsers := strings.Split(viper.GetString("ADMIN_USERS"), ",")
	for _, adminUser := range adminUsers {
		if adminUser == user {
			return true
		}
	}
	return false
}
