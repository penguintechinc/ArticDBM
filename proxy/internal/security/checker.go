package security

import (
	"regexp"
	"strings"
)

type SQLChecker struct {
	enabled  bool
	patterns []*regexp.Regexp
}

func NewSQLChecker(enabled bool) *SQLChecker {
	checker := &SQLChecker{
		enabled: enabled,
	}

	if enabled {
		checker.patterns = []*regexp.Regexp{
			regexp.MustCompile(`(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bunion\b)`),
			regexp.MustCompile(`(?i)(;\s*drop\s+|;\s*delete\s+|;\s*truncate\s+|;\s*alter\s+)`),
			regexp.MustCompile(`(?i)(\bor\b\s*\d+\s*=\s*\d+|\band\b\s*\d+\s*=\s*\d+)`),
			regexp.MustCompile(`(?i)(--|\#|\/\*|\*\/)`),
			regexp.MustCompile(`(?i)(\bexec\s*\(|\bexecute\s*\()`),
			regexp.MustCompile(`(?i)(\bxp_cmdshell\b|\bcmd\.exe\b)`),
			regexp.MustCompile(`(?i)(\bwaitfor\s+delay\b|\bsleep\s*\()`),
			regexp.MustCompile(`(?i)(\bbenchmark\s*\(|\bpg_sleep\s*\()`),
			regexp.MustCompile(`(?i)(\binformation_schema\b|\bsys\.tables\b|\bsyscolumns\b)`),
			regexp.MustCompile(`(?i)(\bload_file\s*\(|\binto\s+outfile\b|\binto\s+dumpfile\b)`),
			regexp.MustCompile(`(?i)(\bupdatexml\s*\(|\bextractvalue\s*\()`),
			regexp.MustCompile(`(?i)(0x[0-9a-f]+|\bhex\s*\(|\bunhex\s*\()`),
			regexp.MustCompile(`(?i)(\bconcat\s*\(.*\bchar\s*\(|\bchar\s*\(.*\bconcat\s*\()`),
			regexp.MustCompile(`(?i)(\b(having|group\s+by)\b.*\b(select|union)\b)`),
		}
	}

	return checker
}

func (c *SQLChecker) IsSQLInjection(query string) bool {
	if !c.enabled {
		return false
	}

	query = strings.ToLower(query)

	for _, pattern := range c.patterns {
		if pattern.MatchString(query) {
			return true
		}
	}

	suspiciousCount := 0
	if strings.Count(query, "'") > 4 {
		suspiciousCount++
	}
	if strings.Count(query, "\"") > 4 {
		suspiciousCount++
	}
	if strings.Contains(query, "1=1") || strings.Contains(query, "1 = 1") {
		suspiciousCount++
	}
	if strings.Contains(query, "' or '") || strings.Contains(query, "\" or \"") {
		suspiciousCount++
	}

	return suspiciousCount >= 2
}

func IsWriteQuery(query string) bool {
	query = strings.TrimSpace(strings.ToUpper(query))
	
	writeKeywords := []string{
		"INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP",
		"TRUNCATE", "RENAME", "REPLACE", "MERGE", "CALL", "LOCK",
		"GRANT", "REVOKE", "SET", "BEGIN", "COMMIT", "ROLLBACK",
		"SAVEPOINT", "RELEASE", "START",
	}

	for _, keyword := range writeKeywords {
		if strings.HasPrefix(query, keyword) {
			return true
		}
	}

	return false
}