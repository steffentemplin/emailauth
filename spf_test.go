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
		t.Error("Expected Pass result")
	}
}

func TestMech(t *testing.T) {
	directive := directiveExp.FindStringSubmatch("~ip4:192.168.0.0/24")
	if directive == nil {
		t.Fail()
	} else {
		qualifier := directive[1]
		mechanism := directive[2]
		separator := directive[3]
		value := directive[4]

		if qualifier != "~" {
			t.Fail()
		}

		if mechanism != "ip4" {
			t.Fail()
		}

		if separator != ":" {
			t.Fail()
		}

		if value != "192.168.0.0/24" {
			t.Fail()
		}
	}

	directive = directiveExp.FindStringSubmatch("redirect=_spf.example.com")
	if directive != nil {
		t.Fail()
	}
}

func TestModifier(t *testing.T) {
	modifier := modifierExp.FindStringSubmatch("redirect=_spf.example.com")
	if modifier == nil {
		t.Fail()
	} else {
		name := modifier[1]
		macroString := modifier[2]

		if name != "redirect" {
			t.Fail()
		}

		if macroString != "_spf.example.com" {
			t.Fail()
		}
	}

	modifier = modifierExp.FindStringSubmatch("mx")
	if modifier != nil {
		t.Fail()
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
