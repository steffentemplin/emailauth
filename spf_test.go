package emailauth

import (
	"net"
	"regexp"
	"testing"
)

func TestHandlePolicyRecord(t *testing.T) {
	record := "v=spf1 ip4:192.168.23.0/24 ip4:172.16.44.0/25 ip4:10.20.21.0/24 mx include:example.com ?all"

	result := handlePolicyRecord(record, net.ParseIP("10.20.21.77"))
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
	e := "^(?P<qualifier>\\+|-|\\?|~)?(?P<mech>all|include|a|mx|ptr|ip4|ip6|exists)(?:(?P<sep>[:/])(?P<value>.*))?$"
	exp := regexp.MustCompile(e)
	directive := exp.FindStringSubmatch("~ip4:192.168.0.0/24")
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

	directive = exp.FindStringSubmatch("redirect=_spf.example.com")
	if directive != nil {
		t.Fail()
	}
}

func TestModifier(t *testing.T) {
	exp := regexp.MustCompile("^(?P<name>[a-z][a-z0-9_\\-\\.]*)=(?P<macrostring>.*)$")
	modifier := exp.FindStringSubmatch("redirect=_spf.example.com")
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

	modifier = exp.FindStringSubmatch("mx")
	if modifier != nil {
		t.Fail()
	}
}
