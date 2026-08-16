package oauth2

const (
	CheckPass = "pass"
	CheckFail = "fail"
	CheckSkip = "skip"
)

// Verification is a client-side OAuth/OIDC check the CLI prints so each
// flow can be learned from stderr.
type Verification struct {
	Name     string `json:"-"`
	Spec     string `json:"spec,omitempty"`
	Purpose  string `json:"purpose,omitempty"`
	Source   string `json:"source,omitempty"`
	Expected string `json:"expected,omitempty"`
	Received string `json:"received,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Result   string `json:"result,omitempty"`
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
