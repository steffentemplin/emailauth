package emailauth

import (
	"net"
	"testing"
)

func TestParseAndEvaluate(t *testing.T) {
	rawRecord := "v=spf1 ip4:192.168.23.0/24 ip4:172.16.44.0/25 ip4:10.20.21.0/24 ?all"
	record, errResult := parseRecord(rawRecord)
	if errResult != nil {
		t.Errorf("Parsing error: %s (%s)", errResult.Result, errResult.Explanation)
	}

	result := evaluateRecord(record, net.ParseIP("10.20.21.77"), "example.com", false, "test@example.com", 0)
	if result.Result != Pass {
		t.Errorf("SPF failed: %s (%s)", result.Result, result.Explanation)
	}
}

func TestCheckHost(t *testing.T) {
	result := new(SPFValidator).Validate(net.ParseIP("10.20.21.77"), "test@ox.io", "localhost")
	if result.Result != Pass {
		t.Errorf("Expected 'pass' result but got '%s'", result.Result)
	}
}

func TestParseSPFDirective(t *testing.T) {
	directive := ParseSPFDirective("~ip4:192.168.0.0/24")
	if directive == nil {
		t.Error("General parsing issue")
	} else {
		if directive.Qualifier != "~" {
			t.Error("Wrong qualifier")
		}

		if directive.Mechanism != "ip4" {
			t.Error("Wrong mechanism")
		}

		if directive.Separator != ":" {
			t.Error("Wrong separator")
		}

		if directive.Value != "192.168.0.0/24" {
			t.Error("Wrong value")
		}
	}

	directive = ParseSPFDirective("redirect=_spf.example.com")
	if directive != nil {
		t.Error("Modifier was parsed as directive")
	}
}

func TestParseSPFModifier(t *testing.T) {
	modifier := ParseSPFModifier("redirect=_spf.example.com")
	if modifier == nil {
		t.Error("General parsing issue")
	} else {
		if modifier.Name != "redirect" {
			t.Error("Wrong name")
		}

		if modifier.MacroString != "_spf.example.com" {
			t.Error("Wrong macro string")
		}
	}

	modifier = ParseSPFModifier("mx")
	if modifier != nil {
		t.Error("Directive was parsed as modifier")
	}
}

func TestDomainValidation(t *testing.T) {
	// valid
	domains := []string{"example.com", "example.com.",
		"sub.example.com", "sub.sub.example.com", "sub.sub.example.com.",
		"subjustunder63chars-subjustunder63chars-subjustunder63chars-sub.example.com"}

	for _, domain := range domains {
		if isInvalidDomain(domain) {
			t.Errorf("Valid domain did not match '%s'", domain)
		}
	}

	// invalid
	domains = []string{".example.com", "com", ".com", ".com.", "example..com", "192.168.0.1",
		"subover63chars-subover63chars-subover63chars-subover63chars-subo.example.com."}

	for _, domain := range domains {
		if isValidDomain(domain) {
			t.Errorf("Invalid domain did match '%s'", domain)
		}
	}
}
