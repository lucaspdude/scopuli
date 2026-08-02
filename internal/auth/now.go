package auth

import "time"

// nowMs returns the current time in milliseconds since the Unix epoch.
// Lives in its own file so tests can stub it without touching the auth logic.
var nowMs = func() int64 { return time.Now().UnixMilli() }
