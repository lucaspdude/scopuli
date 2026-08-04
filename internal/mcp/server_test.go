package mcp

import (
	"encoding/json"
	"testing"
)

// TestToolSchemasRequiredIsArray is a regression test for the Kimi Code
// MCP client rejecting tools/list: a nil required slice marshals to
// "required": null, and strict schema validators (zod) demand an array.
func TestToolSchemasRequiredIsArray(t *testing.T) {
	s := NewServer("http://localhost", "tok")
	for _, tool := range s.toolDefs() {
		b, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal %s: %v", tool.Name, err)
		}
		var schema struct {
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(b, &schema); err != nil {
			t.Fatalf("unmarshal %s schema: %v", tool.Name, err)
		}
		if schema.Required == nil {
			t.Fatalf("tool %s: required marshals to null (want [])", tool.Name)
		}
	}
}
