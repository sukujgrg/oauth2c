package oauth2

const (
	CheckPass = "pass"
	CheckFail = "fail"
	CheckSkip = "skip"
)

// Verification is a client-side OAuth/OIDC check the CLI prints so each
// flow can be learned from stderr.
type Verification struct {
	Name     string `yaml:"-"`
	Spec     string `yaml:"spec,omitempty"`
	Purpose  string `yaml:"purpose,omitempty"`
	Source   string `yaml:"source,omitempty"`
	Expected string `yaml:"expected,omitempty"`
	Received string `yaml:"received,omitempty"`
	Detail   string `yaml:"detail,omitempty"`
	Result   string `yaml:"result,omitempty"`
}

func passCheck(name, spec, purpose string) Verification {
	return Verification{
		Name:    name,
		Spec:    spec,
		Purpose: purpose,
		Result:  CheckPass,
	}
}

func failCheck(name, spec, purpose, detail string) Verification {
	return Verification{
		Name:    name,
		Spec:    spec,
		Purpose: purpose,
		Detail:  detail,
		Result:  CheckFail,
	}
}
