package emailauth

import (
	"encoding/hex"
	"net"
	"regexp"
	"testing"
)

func TestParseAndEvaluate(t *testing.T) {
	rawRecord := "v=spf1 ip4:192.168.23.0/24 ip4:172.16.44.0/25 ip4:10.20.21.0/24 ?all"
	record, errResult := parseRecord(rawRecord)
	if errResult != nil {
		t.Errorf("Parsing error: %s (%s)", errResult.Result, errResult.Explanation)
	}

	result, err := evaluateRecord(record, net.ParseIP("10.20.21.77"), "example.com", false, "test@example.com", 0)
	if err != nil {
		t.Errorf("Evaluation error: %s", err.Error())
	}

	if result.Result != Pass {
		t.Errorf("SPF failed: %s (%s)", result.Result, result.Explanation)
	}
}

func TestCheckHost(t *testing.T) {
	result := new(SPFValidator).Validate(net.ParseIP("10.20.21.77"), "test@ox.io", "localhost")
	if result.Result != None { // FIXME
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

func TestParseMacro(t *testing.T) {
	macro := "{l1r-.}"
	macroExp := regexp.MustCompile("^{(?P<letter>[slodipvhcrt]{1})(?P<transformers>[0-9]*r?)(?P<delimiters>[\\.\\-+,/_=]*)}")
	macroParts := macroExp.FindStringSubmatch(macro)
	if macroParts == nil {
		t.Errorf("Macro could not be parsed")
	}

	letter := macroParts[1]
	transformers := macroParts[2]
	reverse := false
	if len(transformers) > 0 && transformers[len(transformers)-1] == 'r' {
		if len(transformers) == 1 {
			transformers = ""
		} else {
			transformers = transformers[:len(transformers)-1]
		}
		reverse = true
	}
	delimiters := macroParts[3]

	assertStringEquals("l", letter, t)
	assertStringEquals("1", transformers, t)
	assertBoolEquals(true, reverse, t)
	assertStringEquals("-.", delimiters, t)
}

func assertStringEquals(expected string, actual string, t *testing.T) {
	if expected != actual {
		t.Errorf("Expected '%s' but got '%s'", expected, actual)
	}
}

func assertBoolEquals(expected bool, actual bool, t *testing.T) {
	if expected != actual {
		t.Errorf("Expected '%s' but got '%s'", expected, actual)
	}
}
func TestNormalizeIPv6(t *testing.T) {
	// 2001:db8::cb01
	ip := net.ParseIP("2001:db8::cb01")
	if ip == nil {
		t.Error("IP parsing issue")
	}

	ip4 := ip.To4()
	if ip4 != nil {
		t.Error("IPv6 was recognized as IPv4")
	}

	ip = ip.To16()
	if ip == nil {
		t.Error("IPv6 was not recognized as such")
	}

	buf := make([]byte, 39)
	off := 0
	for i := 0; i < len(ip); i = i + 2 {
		block := ip[i : i+2]
		off += hex.Encode(buf[off:off+4], block)
		if off < len(buf) {
			buf[off] = ':'
			off++
		}
	}

	ipStr := string(buf)
	if ipStr != "2001:0db8:0000:0000:0000:0000:0000:cb01" {
		t.Errorf("Expected '%s' but got '%s'", "2001:0db8:0000:0000:0000:0000:0000:cb01", ipStr)
	}
}
