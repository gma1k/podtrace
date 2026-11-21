package redactor

import (
	"regexp"
	"strings"
	"unicode"
)

// affixedCredentialKey matches a field, tag or flag name that contains one of
// the credential key names anywhere in it (db_password, accessToken,
// x-api-key).
const affixedCredentialKey = `[\w.\-]{0,64}?(?:` + credentialKeyNames + `)[\w.\-]{0,64}`

var exactCredentialKey = regexp.MustCompile(`(?i)^(?:` + credentialKeyNames + `)$`)

// credentialWords are the words that make a compound name a secret wherever
// they appear in it: dbPassword, client_secret, x-amz-security-token.
var credentialWords = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "passphrase": true, "passcode": true,
	"secret": true, "token": true, "apikey": true, "credential": true, "credentials": true,
	"signature": true, "authorization": true, "cookie": true,
	"jsessionid": true, "phpsessid": true, "sessionid": true,
}

// credentialWordPairs are secrets spelled as two words: api_key, AccessKey,
// session-id.
var credentialWordPairs = map[string]bool{
	"apikey": true, "accesskey": true, "secretkey": true, "privatekey": true,
	"clientkey": true, "accountkey": true, "signingkey": true, "encryptionkey": true,
	"authkey": true, "sessionid": true, "sessionkey": true,
}

// keyMetadataWords, right after a credential word, turn the name into a
// description of the secret rather than the secret itself: secretName,
// token_type, password_policy, --token-file.
var keyMetadataWords = map[string]bool{
	"name": true, "names": true, "type": true, "types": true, "ref": true, "refs": true,
	"id": true, "ids": true, "url": true, "uri": true, "endpoint": true, "path": true,
	"file": true, "dir": true, "env": true, "stdin": true, "count": true, "length": true,
	"len": true, "expiry": true, "expires": true, "expiration": true, "ttl": true,
	"policy": true, "enabled": true, "required": true, "set": true, "present": true,
	"exists": true, "valid": true, "version": true, "prefix": true, "hint": true,
	"field": true, "header": true, "label": true, "kind": true, "mode": true,
	"format": true, "scope": true, "scopes": true, "provider": true, "issuer": true,
	"source": true, "location": true,
}

// credentialKey reports whether name names a secret. Every name the exact
// credential list covers does; a compound name does when one of its words,
// or two adjacent words, is a credential and the word after it does not
// describe the secret instead.
func credentialKey(name string) bool {
	if exactCredentialKey.MatchString(name) {
		return true
	}
	words := keyWords(name)
	for i, w := range words {
		if credentialWords[w] && !describesSecret(words, i+1) {
			return true
		}
		if i+1 < len(words) && credentialWordPairs[w+words[i+1]] && !describesSecret(words, i+2) {
			return true
		}
	}
	return false
}

// containerKeyWords name a group of credentials rather than one secret:
// under {"credentials": {"user": .., "password": ..}} only the members that
// are themselves secrets are masked, so the rest of the context survives.
var containerKeyWords = map[string]bool{
	"credential": true, "credentials": true, "auth": true, "session": true,
}

func containerKey(name string) bool {
	words := keyWords(name)
	return len(words) > 0 && containerKeyWords[words[len(words)-1]]
}

func describesSecret(words []string, next int) bool {
	return next < len(words) && keyMetadataWords[words[next]]
}

// keyWords splits a snake_case, kebab-case, dotted or camelCase name into
// lower-case words; an acronym ends where the next word begins (APIKey is
// api, key).
func keyWords(name string) []string {
	var words []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			words = append(words, strings.ToLower(string(current)))
			current = current[:0]
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if unicode.IsUpper(r) && len(current) > 0 {
			previous := current[len(current)-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if !unicode.IsUpper(previous) || nextLower {
				flush()
			}
		}
		current = append(current, r)
	}
	flush()
	return words
}

// keyGroupValidator returns a Validate func that accepts a match only when
// its group-th submatch is a credential key.
func keyGroupValidator(pattern *regexp.Regexp, group int) func(string) bool {
	return func(match string) bool {
		sub := pattern.FindStringSubmatch(match)
		return len(sub) > group && credentialKey(sub[group])
	}
}

var jsonCredentialKey = regexp.MustCompile(`(?i)"(` + affixedCredentialKey + `)"\s*:\s*`)

// redactJSONCredentials replaces the value of every JSON member whose key is
// a credential with "***": strings, scalars, and whole arrays or objects,
// nesting included.
func redactJSONCredentials(s string) string {
	var b strings.Builder
	last, pos := 0, 0
	for pos < len(s) {
		loc := jsonCredentialKey.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			break
		}
		keyStart, keyEnd, valueStart := pos+loc[2], pos+loc[3], pos+loc[1]
		valueEnd := jsonValueEnd(s, valueStart)
		key := s[keyStart:keyEnd]
		structured := valueEnd > valueStart && (s[valueStart] == '{' || s[valueStart] == '[')
		if valueEnd == valueStart || !credentialKey(key) || (structured && containerKey(key)) {
			pos = keyEnd + 1
			continue
		}
		b.WriteString(s[last : keyStart-1])
		b.WriteString(`"`)
		b.WriteString(key)
		b.WriteString(`":"***"`)
		last, pos = valueEnd, valueEnd
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// jsonValueEnd returns the index just past the JSON value starting at i, or
// len(s) when the value runs off the end of the text.
func jsonValueEnd(s string, i int) int {
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '"':
		return jsonStringEnd(s, i)
	case '[', '{':
		depth := 0
		for j := i; j < len(s); j++ {
			switch s[j] {
			case '"':
				j = jsonStringEnd(s, j) - 1
			case '[', '{':
				depth++
			case ']', '}':
				depth--
				if depth == 0 {
					return j + 1
				}
			}
		}
		return len(s)
	default:
		j := i
		for j < len(s) && !strings.ContainsRune(" \t\r\n,}]\"{[", rune(s[j])) {
			j++
		}
		return j
	}
}

// jsonStringEnd returns the index just past the string literal opening at i.
func jsonStringEnd(s string, i int) int {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return len(s)
}
