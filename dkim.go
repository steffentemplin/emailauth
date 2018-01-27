package emailauth

/*
 * Authentication-Results:
 *  open-xchange.com;
 *  dkim=pass
 *   reason="1024-bit key; unprotected key"
 *   header.d=example.com
 *   header.i=@example.com
 *   header.b=LvCYfMPA;
 *  dkim-adsp=none (unprotected policy);
 *  dkim-atps=neutral
 *
 * DKIM-Signature:
 *  v=1;
 *  a=rsa-sha256;
 *  c=relaxed/relaxed;
 *  d=example.com;
 *  s=example.com;
 *  h=From:Date:Subject:Message-ID:Content-Type:MIME-Version;
 *  bh=z5jYnCiKk17tpksC+DBtpoRPgU6cNlw2qu5lin4K0dc=;
 *  b=LvCYfMPAp0mh6AbfnlOL5CEXFXoQNU3chKtXFZCUrh0XC1DE535EJeyC67fVWuA0VIV5LyZL8lDIwV41XCrbhZa9OfmAL
 *    MW5UbiBr2A6dfEuRQ+Ll7ODnoJQVPxCH4kEX5EIpbTfJIJ+nP1aq8o0wbd8bSTDNdoToX1lpaCVgao=
 */

type DKIMResult struct {
	Result Result
	Reason string
	Tags   map[string]string
}

type DKIMValidator struct {
}

func (v DKIMValidator) Validate(mail *Message) *DKIMResult {
	return newDKIMResult(None, "Not implemented")
}

func newDKIMResult(result Result, reason string) *DKIMResult {
	r := &DKIMResult{Result: result, Reason: reason}
	r.Tags = make(map[string]string)
	return r
}
