package tgloginwidget

import (
	"errors"
	"testing"
)

func TestAuthData_StringToCheck(t *testing.T) {
	tests := []struct {
		name  string
		input AuthData
		want  string
	}{
		{
			name:  "empty",
			input: AuthData{},
			want:  "auth_date=0\nid=0",
		},
		{
			name: "first_name_only",
			input: AuthData{
				AuthDate:  2,
				ID:        1,
				FirstName: "1st",
			},
			want: "auth_date=2\nfirst_name=1st\nid=1",
		},
		{
			name: "last_name_only",
			input: AuthData{
				AuthDate: 2,
				ID:       1,
				LastName: "Last",
			},
			want: "auth_date=2\nid=1\nlast_name=Last",
		},
		{
			name: "username_only",
			input: AuthData{
				AuthDate: 2,
				ID:       1,
				Username: "UserName",
			},
			want: "auth_date=2\nid=1\nusername=UserName",
		},
		{
			name: "all_name",
			input: AuthData{
				AuthDate:  2,
				ID:        1,
				FirstName: "1st",
				LastName:  "Last",
				Username:  "UserName",
			},
			want: "auth_date=2\nfirst_name=1st\nid=1\nlast_name=Last\nusername=UserName",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.StringToCheck(); got != tt.want {
				t.Errorf("StringToCheck() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthData_Check(t *testing.T) {

	tests := []struct {
		name     string
		input    AuthData
		botToken string
		wantErr  error
	}{
		{
			name:     "no_token",
			input:    AuthData{},
			botToken: "",
			wantErr:  ErrBotTokenRequired,
		},
		{
			name: "real",
			input: AuthData{
				AuthDate:  1725433928,
				FirstName: "Alexander",
				LastName:  "Trakhimenok",
				ID:        92819884,
				PhotoURL:  "https://t.me/i/userpic/320/pg1-q43_ej0FnSi2Rj-1JJymbxLghI3DC0ZYzMZVoGg.jpg",
				Username:  "trakhimenok",
				Hash:      "ebad595ffad01e0cb04d0decd5ec05429c51f313dd3b5a6289f57fe2d95a9eb0",
			},
			botToken: "5954447727:AAHkuOHjwojNEKfkmwRgtZlTvDfUJBDDywk",
			wantErr:  nil,
		},
		{
			name:     "hash_mismatch",
			input:    AuthData{ID: 1, AuthDate: 1, Hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			botToken: "test-token",
			wantErr:  ErrHashMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Check(tt.botToken)
			if (err == nil) != (tt.wantErr == nil) || err != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthData_String(t *testing.T) {

	tests := []struct {
		name  string
		input AuthData
		want  string
	}{
		{
			name:  "empty",
			input: AuthData{},
			want:  "AuthData{ID:0, Username:, FirstName:, LastName:, AuthDate:0, PhotoURL:}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthData_Validate(t *testing.T) {

	tests := []struct {
		name    string
		input   AuthData
		wantErr bool
	}{
		{
			name:    "missing_id",
			input:   AuthData{ID: 0, AuthDate: 1, Hash: "abc"},
			wantErr: true,
		},
		{
			name:    "missing_auth_date",
			input:   AuthData{ID: 1, AuthDate: 0, Hash: "abc"},
			wantErr: true,
		},
		{
			name:    "missing_hash",
			input:   AuthData{ID: 1, AuthDate: 1, Hash: ""},
			wantErr: true,
		},
		{
			name:    "invalid_hex",
			input:   AuthData{ID: 1, AuthDate: 2, Hash: "abc"},
			wantErr: true,
		},
		{
			name:    "should_pass",
			input:   AuthData{ID: 1, AuthDate: 2, Hash: "ebad595ffad01e0cb04d0decd5ec05429c51f313dd3b5a6289f57fe2d95a9eb0"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.input.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
