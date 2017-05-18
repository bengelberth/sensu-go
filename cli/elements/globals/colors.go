package globals

import (
	"strings"

	"github.com/mgutz/ansi"
)

var (
	// TitleStyle can be used to format a string; suitable for titles
	TitleStyle = ansi.ColorFunc("white+bh")

	// PrimaryTextStyle can be used to format a string; suitable for emphasis
	PrimaryTextStyle = ansi.ColorFunc("blue+b")

	// CTATextStyle can be used to format a string; important text
	CTATextStyle = ansi.ColorFunc("red+b:white+h") // Call To Action
)

// BooleanStyle colors instances of 'true' & 'false' blue & red respectively
func BooleanStyle(in string) string {
	trueStyle := ansi.ColorFunc("blue")
	falseStyle := ansi.ColorFunc("red")
	replacer := strings.NewReplacer(
		"false", falseStyle("false"),
		"true", trueStyle("true"),
	)

	return replacer.Replace(in)
}

// BooleanStyleP is like BooleanStyle except takes a boolean as it's argument
func BooleanStyleP(in bool) string {
	if in {
		return BooleanStyle("true")
	}
	return BooleanStyle("false")
}