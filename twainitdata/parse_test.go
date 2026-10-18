package twainitdata

import (
	"reflect"
	"testing"
)

const (
	_parseTestInitData = "query_id=AAHdF6IQAAAAAN0XohDhrOrc&user=%7B%22id%22%3A279058397%2C%22first_name%22%3A%22Vladislav%22%2C%22last_name%22%3A%22Kibenko%22%2C%22username%22%3A%22vdkfrost%22%2C%22language_code%22%3A%22ru%22%2C%22is_premium%22%3Atrue%7D&auth_date=1662771648&hash=c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2&start_param=abc"
)

type testParse struct {
	initData    string
	expectedErr error
	expectedRes InitData
}

var testsParse = []testParse{
	{
		initData:    _parseTestInitData + ";",
		expectedErr: ErrUnexpectedFormat,
	},
	{
		initData:    "query_id=123&auth_date=abc",
		expectedErr: ErrUnexpectedFormat,
	},
	{
		initData: _parseTestInitData,
		expectedRes: InitData{
			QueryID: "AAHdF6IQAAAAAN0XohDhrOrc",
			User: User{
				ID:           279058397,
				FirstName:    "Vladislav",
				LastName:     "Kibenko",
				Username:     "vdkfrost",
				LanguageCode: "ru",
				IsPremium:    true,
			},
			CanSendAfterRaw: 0,
			AuthDateRaw:     1662771648,
			StartParam:      "abc",
			Hash:            "c501b71e775f74ce10e377dea85a7ea24ecd640b223ea86dfe453e0eaed2e2b2",
		},
	},
}

func TestParse(t *testing.T) {
	for _, test := range testsParse {
		if data, err := Parse(test.initData); err != test.expectedErr {
			t.Errorf("expected error to be %q. \nReceived %q", test.expectedErr, err)
		} else if !reflect.DeepEqual(data, test.expectedRes) {
			t.Errorf("expected result to be %+v. \nReceived %+v", test.expectedRes, data)
		}
	}
}

func TestChatType_Known(t *testing.T) {
	known := []ChatType{
		ChatTypeSender,
		ChatTypePrivate,
		ChatTypeGroup,
		ChatTypeSupergroup,
		ChatTypeChannel,
	}
	for _, ct := range known {
		if !ct.Known() {
			t.Errorf("expected %q to be known", ct)
		}
	}
	if ChatType("unknown").Known() {
		t.Errorf("expected 'unknown' to not be known")
	}
}

func TestInitData_AuthDateAndCanSendAfter(t *testing.T) {
	d := InitData{
		AuthDateRaw:     1662771648,
		CanSendAfterRaw: 30,
	}
	authDate := d.AuthDate()
	if authDate.Unix() != 1662771648 {
		t.Errorf("expected auth date 1662771648, got %d", authDate.Unix())
	}
	canSendAfter := d.CanSendAfter()
	if canSendAfter.Unix() != 1662771678 {
		t.Errorf("expected can send after 1662771678, got %d", canSendAfter.Unix())
	}
}
