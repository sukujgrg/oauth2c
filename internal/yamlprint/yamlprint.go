package yamlprint

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v4"
)

const DefaultIndent = 2

// Encoder marshals values to YAML using go.yaml.in/yaml/v4.
type Encoder struct {
	Indent int
}

func New() Encoder {
	return Encoder{Indent: DefaultIndent}
}

func (e Encoder) indent() int {
	if e.Indent < 2 {
		return DefaultIndent
	}
	return e.Indent
}

func (e Encoder) opts() []yaml.Option {
	return []yaml.Option{
		yaml.WithIndent(e.indent()),
		yaml.WithLineWidth(-1),
	}
}

// Marshal encodes v as YAML.
func (e Encoder) Marshal(v any) ([]byte, error) {
	out, err := yaml.Dump(jsonIntegers(v), e.opts()...)
	if err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	return out, nil
}

// FromJSON converts a JSON-tagged value into a generic document for YAML.
func FromJSON(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("yaml: json: %w", err)
	}

	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("yaml: json: %w", err)
	}

	return generic, nil
}

// Write marshals v and writes it to w.
func (e Encoder) Write(w io.Writer, v any) error {
	out, err := e.Marshal(v)
	if err != nil {
		return err
	}

	text := strings.TrimRight(string(out), "\n")
	if text == "" || text == "{}" || text == "null" {
		return nil
	}

	_, err = fmt.Fprintln(w, text)
	return err
}
