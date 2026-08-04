package config

import "os"

// lookupEnv is a small indirection so tests can override env vars without
// poking the global os.Setenv.
var lookupEnv = os.LookupEnv

// setEnv / unsetEnv wrap os.Setenv / os.Unsetenv for tests.
func setEnv(key, value string) error { return os.Setenv(key, value) }
func unsetEnv(key string) error      { return os.Unsetenv(key) }
