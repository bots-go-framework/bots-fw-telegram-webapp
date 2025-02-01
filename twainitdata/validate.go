package twainitdata

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Validate validating passed init data.
// This method expects initData to be passed in the exact raw format as it could be found
// in window.Telegram.WebApp.initData. Returns true in case init data is
// signed correctly, and it is allowed to trust it.
//
// Current code is implementation of algorithmic code described in official docs:
// https://core.telegram.org/bots/webapps#validating-data-received-via-the-web-app
//
// initData - init data passed from application;
// token - TWA bot secret token which was used to create init data;
// expIn - maximum init data lifetime. It is strongly recommended to use this
// parameter. In case, exp duration is less than or equal to 0, function does
// not check if parameters are expired.
func Validate(initData, token string, expIn time.Duration) error {
	if strings.TrimSpace(token) == "" {
		return ErrAuthTokenRequired
	}
	// Parse passed init data as query string.
	q, err := url.ParseQuery(initData)
	if err != nil {
		return ErrUnexpectedFormat
	}

	var (
		// Init data creation time.
		authDate time.Time
		// Init data sign.
		receivedHash string
		//signature    string
		// All found key-value pairs.
		pairs = make([]string, 0, len(q))
	)

	// Iterate over all key-value pairs of parsed parameters.
	for k, v := range q {
		switch k {
		case "hash":
			receivedHash = v[0]
			continue
		case "signature":
			continue
		case "auth_date":
			if i, err := strconv.Atoi(v[0]); err == nil {
				authDate = time.Unix(int64(i), 0)
			}
		}
		// Append a new pair.
		pairs = append(pairs, k+"="+v[0])
	}

	// Sign is always required.
	if receivedHash == "" {
		return ErrAuthHashIsMissing
	}

	if expIn > 0 { // Do additional checks of parameters if the expiration date is passed.
		if authDate.IsZero() {
			return ErrAuthDateMissing
		}

		// Check if init data is expired.
		if authDate.Add(expIn).Before(time.Now()) {
			return ErrExpired
		}
	}

	if len(pairs) == 0 {
		return fmt.Errorf("no key-value pairs found in init data")
	}

	// According to docs, we sort all the pairs in alphabetical order.
	sort.Strings(pairs)

	dataToSign := strings.Join(pairs, "\n")
	expectedHash := sign(dataToSign, token)

	// In case, our sign is not equal to found one, we should throw an error.
	if expectedHash != receivedHash {
		return ErrUnexpectedHash{ReceivedHash: receivedHash, ExpectedHash: expectedHash, AuthDate: authDate, Data: pairs}
	}
	return nil
}

type ErrUnexpectedHash struct {
	ReceivedHash string
	ExpectedHash string
	AuthDate     time.Time
	Data         []string
}

func (e ErrUnexpectedHash) Error() string {
	return ErrAuthHashIsInvalid.Error()
}

func (e ErrUnexpectedHash) Unwrap() error {
	return ErrAuthHashIsInvalid
}
