package types

import "strings"

// Profile is a type that represents environment where the application is running.
type Profile string

// We define several profiles, to facilitate configuration if an environment matches one of the profiles.
// To run the server in a specific profile, use the -profile flag or the PROFILE environment variable,
// with the value of the profile you want to use.
// No other environment variables are required when using a profile, except for the TSA and email server credentials.
const (
	PROFILE_LOCAL     Profile = "local"
	PROFILE_ALTIA_DEV Profile = "altia-dev"
	PROFILE_ISBE_DEV  Profile = "isbe-dev"
	PROFILE_ISBE_PRE  Profile = "isbe-pre"
	PROFILE_ISBE_PRO  Profile = "isbe-pro"
)

func ProfileFromString(p string) Profile {
	switch strings.ToLower(p) {
	case "local":
		return PROFILE_LOCAL
	case "altia-dev":
		return PROFILE_ALTIA_DEV
	case "isbe-dev":
		return PROFILE_ISBE_DEV
	case "isbe-pre":
		return PROFILE_ISBE_PRE
	case "isbe-pro":
		return PROFILE_ISBE_PRO
	default:
		return PROFILE_LOCAL
	}
}
