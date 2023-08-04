package app

import (
	"bytes"
	"html/template"
	"strings"

	"github.com/SebastiaanKlippert/go-wkhtmltopdf"
	"github.com/divan/num2words"
	"github.com/pkg/errors"
)

// ParseTemplate parsing template function
func ParseTemplateFile(templateFileName, templateFilePath string, data interface{}) (*bytes.Buffer, error) {
	funcMap := template.FuncMap{
		"inc": func(i int) int {
			return i + 1
		},
		"div": func(i *float32) float32 {
			return *i / 2
		},
		"inWords": func(i float64) string {
			return strings.ToUpper(num2words.Convert(int(i)))
		},
	}
	t, err := template.New(templateFileName).Funcs(funcMap).ParseFiles(templateFilePath)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	if err = t.Execute(buf, data); err != nil {
		return nil, err
	}

	return buf, nil
}

// GentratePDF generate pdf function
func GeneratePDF(body *bytes.Buffer) (*bytes.Buffer, error) {
	pdfg, err := wkhtmltopdf.NewPDFGenerator()
	if err != nil {
		return nil, errors.Wrap(err, "PDF Error: Failed to create pdf generator instance.")
	}
	pdfg.Dpi.Set(300)
	pdfg.PageSize.Set(wkhtmltopdf.PageSizeA4)
	pdfg.AddPage(wkhtmltopdf.NewPageReader(body))

	err = pdfg.Create()
	if err != nil {
		return nil, errors.Wrap(err, "PDF Error: Failed to create pdf dociment.")
	}
	buf := pdfg.Buffer()
	return buf, nil
}
