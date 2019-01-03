package resource

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestResource(t *testing.T) {
	r := &Resource{
		Uri:  "https://v3ms.104.com.tw/jobs",
		Name: "jobs",
		Type: "rest",
	}

	assert.EqualValues(t, UrnPrefix+"rest:jobs", r.GetUrn())
	assert.EqualValues(t, "rest:jobs", r.GetDefaultScope())
}
