## `package tgloginwidget`

Provides utilities to work with [Telegram Login Widget](https://core.telegram.org/widgets/login).

## Usage/Examples

```go
package main

import "github.com/bots-go-framework/bots-fw-telegram-webapp/tgloginwidget"


func main() {
	
	authData := tgloginwidget.AuthData{
		// ... Initialize AuthData struct.
	}

	// Telegram bot token.
	const token = "XXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXX"

	// Call "Check" method to validate hash.
	if err := authData.Check(token); err != nil {
		// Invalid hash.
		return
	}
	// Hash is valid.
}
```