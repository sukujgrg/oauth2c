package oauth2

import (
	"errors"
	"testing"
	"time"
)

func TestDevicePollInterval(t *testing.T) {
	current := 5 * time.Second

	t.Run("authorization_pending keeps interval", func(t *testing.T) {
		next, retry := DevicePollInterval(current, &Error{ErrorCode: ErrAuthorizationPending})
		eq(t, retry, true)
		eq(t, next, current)
	})

	t.Run("slow_down increases interval by five seconds", func(t *testing.T) {
		next, retry := DevicePollInterval(current, &Error{ErrorCode: ErrSlowDown})
		eq(t, retry, true)
		eq(t, next, 10*time.Second)

		next, retry = DevicePollInterval(next, &Error{ErrorCode: ErrSlowDown})
		eq(t, retry, true)
		eq(t, next, 15*time.Second)
	})

	t.Run("other errors stop polling", func(t *testing.T) {
		next, retry := DevicePollInterval(current, &Error{ErrorCode: "access_denied"})
		eq(t, retry, false)
		eq(t, next, current)

		next, retry = DevicePollInterval(current, errors.New("network"))
		eq(t, retry, false)
		eq(t, next, current)
	})
}
