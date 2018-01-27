package emailauth

import (
	"net"
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

type SPFValidator struct {
}

func newSPFResult(result Result, explanation string) *SPFResult {
	r := &SPFResult{Result: result, Explanation: explanation}
	return r
}

const recordPrefix = "v=spf1"

func (v SPFValidator) Validate(ip net.IP, from string, heloName string) *SPFResult {
	from = strings.TrimSpace(from)
	if len(from) == 0 {
		from = "@" + heloName
	}

	fromParts := strings.Split(from, "@")
	if len(fromParts) != 2 {
		// FIXME: right result?
		return newSPFResult(Permerror, "Invalid sender address")
	}

	localPart := strings.TrimSpace(fromParts[0])
	if len(localPart) == 0 {
		localPart = "postmaster"
	}

	domain := strings.TrimSpace(fromParts[1])
	if !isValid(domain) {
		return newSPFResult(None, "Invalid domain name")
	}

	records, err := net.LookupTXT(domain)
	if err != nil {
		if err, ok := err.(*net.DNSError); ok {
			if err.IsTimeout || err.IsTemporary {
				return newSPFResult(Temperror, err.Error())
			}
		}
		// FIXME: right result?
		return newSPFResult(None, err.Error())
	}

	var record string
	for _, r := range records {
		println("Record: " + r)
		if len(r) > len(recordPrefix)+1 && strings.HasPrefix(r, recordPrefix) {
			if record == "" {
				record = r
			} else {
				return newSPFResult(Permerror, "Multiple SPF records")
			}
		}
	}

	if record == "" {
		return newSPFResult(None, "")
	}

	return handlePolicyRecord(record, ip)
}

//
func handlePolicyRecord(record string, ip net.IP) *SPFResult {
	return checkRecursive(ip, record, 0)
}

func checkRecursive(ip net.IP, record string, depth int8) *SPFResult {
	record = record[len(recordPrefix)+1 : len(record)]
	terms := strings.Split(record, " ")
	for _, t := range terms {
		//"^(+-?)?$"
		if t[0] == '+' {

		}
	}

	return newSPFResult(None, "")
}

func isValid(domain string) bool {
	// FIXME
	return true
}
