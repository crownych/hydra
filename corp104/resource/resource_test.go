package resource

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestResource(t *testing.T) {
	r := &Resource{
		Uri:     "https://v3ms.104.com.tw/job",
		Name:    "job",
		Version: "1.0",
	}

	assert.EqualValues(t, UrnPrefix+"job:v1.0", r.GetUrn())
}
