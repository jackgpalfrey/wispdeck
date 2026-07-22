package wispist

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

func (e *Engine) TransformHTML(binding Binding, body []byte) ([]byte, error) {
	if err := e.validateBinding(binding); err != nil {
		return nil, err
	}
	hasBootstrap, hasHead, hasHTML, err := inspectHTML(body, binding)
	if err != nil {
		return nil, fmt.Errorf("inspect HTML for Wispist bootstrap: %w", err)
	}
	if hasBootstrap {
		return append([]byte(nil), body...), nil
	}
	bootstrap := []byte(`<script src="/_wispist/client/v1.js" data-wispist-bootstrap data-wispist-mode="` +
		string(binding.Mode) + `" data-wispist-read-only="` + strconv.FormatBool(binding.ReadOnly) + `"></script>`)
	if !hasHead && !hasHTML {
		position, err := htmlPreambleEnd(body)
		if err != nil {
			return nil, fmt.Errorf("locate HTML preamble: %w", err)
		}
		insertion := append([]byte(`<head>`), bootstrap...)
		insertion = append(insertion, []byte(`</head>`)...)
		return insertBytes(body, position, insertion), nil
	}

	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	var result bytes.Buffer
	result.Grow(len(body) + len(bootstrap) + 16)
	inserted := false
	for {
		tokenType := tokenizer.Next()
		raw := append([]byte(nil), tokenizer.Raw()...)
		switch tokenType {
		case html.ErrorToken:
			if errors := tokenizer.Err(); errors != nil && errors != io.EOF {
				return nil, errors
			}
			if !inserted {
				return nil, errorsUnexpectedHTML
			}
			return result.Bytes(), nil
		case html.StartTagToken:
			token := tokenizer.Token()
			result.Write(raw)
			if !inserted && hasHead && token.DataAtom == atom.Head {
				result.Write(bootstrap)
				inserted = true
			} else if !inserted && !hasHead && token.DataAtom == atom.Html {
				result.WriteString("<head>")
				result.Write(bootstrap)
				result.WriteString("</head>")
				inserted = true
			}
		default:
			result.Write(raw)
		}
	}
}

var errorsUnexpectedHTML = fmt.Errorf("HTML document has no insertion point")

func inspectHTML(body []byte, binding Binding) (hasBootstrap, hasHead, hasHTML bool, err error) {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	inHead := false
	headHasElement := false
	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			if tokenizer.Err() == io.EOF {
				return hasBootstrap, hasHead, hasHTML, nil
			}
			return false, false, false, tokenizer.Err()
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			switch token.DataAtom {
			case atom.Head:
				hasHead = true
				inHead = true
			case atom.Html:
				hasHTML = true
			case atom.Script:
				if inHead && !headHasElement && exactBootstrap(token, binding) {
					hasBootstrap = true
				}
				if inHead {
					headHasElement = true
				}
			default:
				if inHead {
					headHasElement = true
				}
			}
		case html.EndTagToken:
			if tokenizer.Token().DataAtom == atom.Head {
				inHead = false
			}
		}
	}
}

func exactBootstrap(token html.Token, binding Binding) bool {
	if len(token.Attr) != 4 {
		return false
	}
	want := map[string]string{
		"src": "/_wispist/client/v1.js", "data-wispist-bootstrap": "",
		"data-wispist-mode":      string(binding.Mode),
		"data-wispist-read-only": strconv.FormatBool(binding.ReadOnly),
	}
	for _, attribute := range token.Attr {
		key := strings.ToLower(attribute.Key)
		value, ok := want[key]
		if !ok || attribute.Val != value {
			return false
		}
		delete(want, key)
	}
	return len(want) == 0
}

func htmlPreambleEnd(body []byte) (int, error) {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	position := 0
	for {
		tokenType := tokenizer.Next()
		raw := tokenizer.Raw()
		switch tokenType {
		case html.ErrorToken:
			if tokenizer.Err() == io.EOF {
				return position, nil
			}
			return 0, tokenizer.Err()
		case html.DoctypeToken, html.CommentToken:
			position += len(raw)
		case html.TextToken:
			if strings.TrimSpace(string(raw)) != "" {
				return position, nil
			}
			position += len(raw)
		default:
			return position, nil
		}
	}
}

func insertBytes(body []byte, position int, insertion []byte) []byte {
	result := make([]byte, 0, len(body)+len(insertion))
	result = append(result, body[:position]...)
	result = append(result, insertion...)
	result = append(result, body[position:]...)
	return result
}
