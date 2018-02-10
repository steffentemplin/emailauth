package emailauth

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

/*
 * Authentication-Results:
 *  mx1.example.com;
 *  spf=pass (mailfrom)
 *   smtp.mailfrom=example.com (client-ip=192.168.5.24; helo=example.com; envelope-from=test@example.com; receiver=<UNKNOWN>)
 *
 * Authentication-Results:
 *  mx1.example.com;
 *  spf=pass smtp.mailfrom=hans-test@example.com
 *
 * Received-SPF:
 *  Pass (mailfrom) identity=mailfrom;
 *  client-ip=192.168.5.24;
 *  helo=example.com;
 *  envelope-from=test@example.com;
 *  receiver=recipient@acme.org
 */

type SPFResult struct {
	Result      Result
	Explanation string
}

type SPFTerm interface {
	ToDirective() (ok bool, directive *SPFDirective)
	ToModifier() (ok bool, modifier *SPFModifier)
}

type SPFDirective struct {
	Qualifier string
	Mechanism string
	Separator string
	Value     string
	RawValue  string
}

func (d *SPFDirective) ToDirective() (bool, *SPFDirective) {
	return true, d
}

func (d *SPFDirective) ToModifier() (bool, *SPFModifier) {
	return false, nil
}

type SPFModifier struct {
	Name        string
	MacroString string
	RawValue    string
}

func (m *SPFModifier) ToDirective() (bool, *SPFDirective) {
	return false, nil
}

func (m *SPFModifier) ToModifier() (bool, *SPFModifier) {
	return true, m
}

type SPFValidator struct {
}

/*
 * Creates a new directive instance from the given string.
 * If the input does not resolve to a valid directive, nil
 * is returned.
 */
func ParseSPFDirective(directive string) *SPFDirective {
	parts := directiveExp.FindStringSubmatch(directive)
	if parts == nil {
		return nil
	}

	val := &SPFDirective{}
	val.Qualifier = parts[1]
	val.Mechanism = parts[2]
	val.Separator = parts[3]
	val.Value = parts[4]
	val.RawValue = directive

	// apply defaults and validate
	if val.Qualifier == "" {
		val.Qualifier = "+"
	}

	switch val.Mechanism {
	case "all":
		if len(val.Separator) > 0 || len(val.Value) > 0 {
			return nil
		}
		break
	case "include", "exists":
		if val.Separator != ":" {
			return nil
		}
		// TODO: validate <domain-spec>
		break
	case "a", "mx", "ptr":
		if val.Separator != "" && (val.Separator == "/" || val.Value == "") {
			return nil
		}
		// TODO: validate <domain-spec> [<dual-cidr-length>]
		break
	case "ip4", "ip6":
		if val.Separator != ":" || val.Value == "" {
			return nil
		}
		break
	}

	return val
}

func ParseSPFModifier(modifier string) *SPFModifier {
	parts := modifierExp.FindStringSubmatch(modifier)
	if parts == nil {
		return nil
	}

	val := &SPFModifier{}
	val.Name = parts[1]
	val.MacroString = parts[2]
	val.RawValue = modifier
	return val
}

func newSPFResult(result Result, explanation string) *SPFResult {
	r := &SPFResult{Result: result, Explanation: explanation}
	return r
}

const recordPrefix = "v=spf1"

var directiveExp = regexp.MustCompile("^(?P<qualifier>\\+|-|\\?|~)?(?P<mech>all|include|a|mx|ptr|ip4|ip6|exists)(?:(?P<sep>[:/])(?P<value>.*))?$")
var modifierExp = regexp.MustCompile("^(?P<name>[a-z][a-z0-9_\\-\\.]*)=(?P<macrostring>.*)$")
var domainExp = regexp.MustCompile("^([^\\.]{1,63}\\.)+[^\\.]{1,63}(\\.)?$")

func (v SPFValidator) Validate(ip net.IP, from string, heloName string) *SPFResult {
	heloName = strings.TrimSpace(heloName)
	if isValidDomain(heloName) {
		// TODO: check HELO SPF
	}

	from = strings.TrimSpace(from)
	if len(from) == 0 {
		from = heloName
	}

	if from[0] == '<' {
		from = from[1:]
	}

	if from[len(from)-1] == '>' {
		from = from[0 : len(from)-1]
	}

	fromParts := strings.SplitN(from, "@", 1)
	if len(fromParts) != 2 {
		fromParts = []string{"postmaster", from}
	}

	localPart := strings.TrimSpace(fromParts[0])
	if len(localPart) == 0 {
		localPart = "postmaster"
	}

	domain := strings.TrimSpace(fromParts[1])
	if isInvalidDomain(domain) {
		return newSPFResult(None, "Invalid domain name")
	}

	// TODO:
	//  - "from" correct?
	//  - isHeloDomain needed? if so, correct it
	return checkHost(ip, domain, false, from, 0)
}

const (
	lookupLimit    = 10
	mxLookupLimit  = 10
	ptrLookupLimit = 10
)

func checkHost(ip net.IP, domain string, isHeloDomain bool, sender string, lookups uint8) *SPFResult {
	if lookups > lookupLimit {
		return newSPFResult(Permerror, "Too many DNS lookups")
	}

	if isInvalidDomain(domain) {
		return newSPFResult(None, fmt.Sprintf("Invalid domain: %s", sanitizeDomainForPrinting(domain)))
	}

	rawRecord, errResult := findSPFRecord(domain)
	if errResult != nil {
		return errResult
	}

	record, errResult := parseRecord(rawRecord)
	if errResult != nil {
		return errResult
	}

	return evaluateRecord(record, ip, domain, isHeloDomain, sender, lookups)
}

func evaluateRecord(record []SPFTerm, ip net.IP, domain string, isHeloDomain bool, sender string, lookups uint8) *SPFResult {
	for _, term := range record {
		if ok, directive := term.ToDirective(); ok {
			match := false
			// all|include|a|mx|ptr|ip4|ip6|exists
			switch directive.Mechanism {
			case "all":
				break
			case "include":
				break
			case "a":
				break
			case "mx":
				break
			case "ptr":
				break
			case "ip4":
				matchIP, matchNet, err := net.ParseCIDR(directive.Value)
				if err != nil {
					matchIP = net.ParseIP(directive.Value)
					matchNet = nil
				}

				if matchIP == nil || matchIP.To4() == nil {
					return newSPFResult(Permerror, "Invalid IPv4 address")
				}

				if matchNet == nil {
					match = matchIP.Equal(ip)
				} else {
					match = matchNet.Contains(ip)
				}
				break
			case "ip6":
				matchIP, matchNet, err := net.ParseCIDR(directive.Value)
				if err != nil {
					matchIP = net.ParseIP(directive.Value)
					matchNet = nil
				}

				if matchIP == nil || matchIP.To16() == nil {
					return newSPFResult(Permerror, "Invalid IPv6 address")
				}

				if matchNet == nil {
					match = matchIP.Equal(ip)
				} else {
					match = matchNet.Contains(ip)
				}
				break
			case "exists":
				break
			}

			if match {
				switch directive.Qualifier {
				case "+":
					return newSPFResult(Pass, fmt.Sprintf("Allowed sender IP: %v", ip))
				case "-":
					// TODO: section 6.2, explanation string...
					return newSPFResult(Fail, fmt.Sprintf("Disallowed sender IP: %v", ip))
				}
			}
		} else {
			_, modifier := term.ToModifier()
			/*
			* TODO:
			*  - every modifier must appear only once => permerror
			*  - ignore unknown
			 */
			switch modifier.Name {
			case "redirect":
				// TODO: if "all" has occurred, stop
				domain, err := expandMacro(modifier.MacroString)
				if err != nil {
					// TODO
				}
				domain = domain
				/*
				* The result of this new evaluation of check_host() is then considered
				* the result of the current evaluation with the exception that if no
				* SPF record is found, or if the <target-name> is malformed, the result
				* is a "permerror" rather than "none".
				 */
				break
			case "exp":
				break
			default:
				break
			}
		}
	}

	return newSPFResult(Neutral, "Default result")
}

func parseRecord(rawRecord string) ([]SPFTerm, *SPFResult) {
	rawRecord = rawRecord[len(recordPrefix)+1 : len(rawRecord)]
	rawTerms := strings.Split(rawRecord, " ")
	terms := make([]SPFTerm, len(rawTerms), len(rawTerms))
	for i, t := range rawTerms {
		directive := ParseSPFDirective(t)
		if directive == nil {
			modifier := ParseSPFModifier(t)
			if modifier == nil {
				return nil, newSPFResult(Permerror, "Invalid record")
			}
			terms[i] = modifier
		} else {
			terms[i] = directive
		}
	}

	return terms, nil
}

func findSPFRecord(domain string) (string, *SPFResult) {
	records, err := net.LookupTXT(domain)
	if err != nil {
		if err, ok := err.(*net.DNSError); ok {
			if err.IsTimeout || err.IsTemporary {
				return "", newSPFResult(Temperror, err.Error())
			}
		}
		// FIXME: right result?
		return "", newSPFResult(None, err.Error())
	}

	var record string
	for _, r := range records {
		if strings.HasPrefix(r, recordPrefix) {
			if len(r) > len(recordPrefix)+1 && r[len(recordPrefix)] == ' ' {
				if record != "" {
					return "", newSPFResult(Permerror, "Multiple SPF records")
				}

				record = r
			} else if r == recordPrefix {
				// FIXME: right result?
				return "", newSPFResult(Neutral, "No policies specified")
			}
		}
	}

	if record == "" {
		return "", newSPFResult(None, "")
	}

	return record, nil
}

func expandMacro(macro string) (string, error) {
	//FIXME
	return "", nil
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 255 {
		return false
	}

	regexMatch := domainExp.MatchString(domain)
	if regexMatch {
		// must not be an IPv4 address
		return net.ParseIP(domain) == nil
	}

	// TODO: check valid character range
	return false
}

func isInvalidDomain(domain string) bool {
	return !isValidDomain(domain)
}

func sanitizeDomainForPrinting(domain string) string {
	dlen := len(domain)
	if dlen == 0 {
		return "<empty>"
	}

	if dlen > 64 {
		domain = domain[:61] + "..."
	}

	// TODO: remove control characters
	return domain
}
