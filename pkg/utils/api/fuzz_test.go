package api

import (
	"testing"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
)

func FuzzJmespath(f *testing.F) {
	f.Fuzz(func(t *testing.T, jmsString, value string) {
		jp := jmespath.New(nil)
		q, err := jp.Query(jmsString)
		if err != nil {
			return
		}
		q.Search(value)
	})
}
