package auth

import (
	"regexp"
	"strings"
)

// Domain host patters are passed in as glob style patterns (e.g.
// *.example.com). This function converts these patterns to regular expressions
// for matching against the request host.
func compileGlobPatterns(patterns []string) []regexp.Regexp {
	compiledPatterns := make([]regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		// Convert wildcard pattern to regular expression
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

		compiledPatterns[i] = *regexp.MustCompile(regexPattern)
	}
	return compiledPatterns
}
