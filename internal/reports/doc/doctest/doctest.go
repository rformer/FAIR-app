// Package doctest holds sample report documents for the renderers' tests
// (CSV and JSON in internal/reports/doc, PDF in internal/report).
package doctest

import (
	"time"

	"github.com/rformer/fair-app/internal/reports/doc"
)

// Sample is a small risk register report with every kind of block: pairs,
// a paragraph, a list, a table with every column type, and an exceedance
// chart. Its text includes markup, a formula and non-Latin names, so the
// renderers' neutralizing and Unicode handling are exercised.
func Sample() doc.Document {
	at := time.Date(2026, 11, 16, 14, 30, 0, 0, time.UTC)
	return doc.Document{
		Metadata: doc.Metadata{
			RunID: "6f1d2c3b-4a5e-4f60-8172-93a4b5c6d7e8", Kind: "register", Title: "Risk register: Claims",
			BU: doc.Ref{ID: "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9", Name: "Claims"}, Filters: map[string]string{"status": "stale", "category": "Cyber"},
			GeneratedAt: at, GeneratedBy: "Zoë Ångström", DataAsOf: at.Add(-2 * time.Minute), Currency: "USD", Marking: "Confidential",
			Runs: []doc.RunRef{{ID: "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", Scenario: "Ransomware on claims", EngineVersion: "1.0.0",
				Seed: "12345", InputDigest: "4f9a1c0e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a19"}},
			LeftOut: map[string]int{"not_visible": 3, "unquantified": 1},
			Notes:   []string{"Restricted business units are included by their roll-up mode."},
		},
		Sections: []doc.Section{
			{Heading: "Summary", Level: 1, Blocks: []doc.Block{
				{Kind: doc.KindPairs, Pairs: []doc.Pair{{Label: "Open risks", Value: "2"}, {Label: "Mean annualized loss (sum of means)", Value: "1,250,000 USD"}}},
				{Kind: doc.KindParagraph, Text: "Exposure is shown as a distribution: the mean with the 10th and 90th percentiles. <script>alert(1)</script>"},
				{Kind: doc.KindList, Items: []string{"One risk is stale.", "One risk is unquantified."}},
			}},
			{Heading: "Risks", Level: 1, Blocks: []doc.Block{
				{Kind: doc.KindTable, Table: &doc.Table{ID: "risks", Caption: "Open risks by mean annualized loss",
					Columns: []doc.Column{{Key: "title", Title: "Risk", Type: doc.ColText, Width: 3}, {Key: "owner", Title: "Owner", Type: doc.ColText, Width: 2},
						{Key: "mean", Title: "Mean", Type: doc.ColAmount}, {Key: "p10", Title: "10th percentile", Type: doc.ColAmount},
						{Key: "p90", Title: "90th percentile", Type: doc.ColAmount}, {Key: "change", Title: "Change", Type: doc.ColPercent},
						{Key: "expires", Title: "Acceptance expires", Type: doc.ColDate}, {Key: "status", Title: "Exposure", Type: doc.ColText}},
					Rows: [][]string{
						{"Ransomware on claims", "Zoë Ångström", "1000000", "120000.5", "2500000", "-0.125", "2027-03-01", "current"},
						{"=HYPERLINK(\"https://evil.example\")", "Иван Петров", "250000", "10000", "600000", "0.04", "", "stale"},
					}}},
			}},
			{Heading: "Ransomware on claims", Level: 2, Blocks: []doc.Block{
				{Kind: doc.KindChart, Chart: &doc.Chart{Kind: doc.ChartExceedance, Title: "Loss exceedance", Log: true,
					Alt:  "Loss exceedance curve: a 50% chance of losing more than 800,000 USD in a year, and a 10% chance of more than 2,500,000 USD.",
					XKey: "loss", Series: []doc.Ref{{ID: "current", Name: "Current"}},
					Data: &doc.Table{ID: "lec-ransomware", Caption: "Loss exceedance: chance of losing more than each amount in a year",
						Columns: []doc.Column{{Key: "loss", Title: "Annual loss", Type: doc.ColAmount}, {Key: "current", Title: "Current", Type: doc.ColPercent}},
						Rows:    [][]string{{"100000", "0.95"}, {"800000", "0.5"}, {"2500000", "0.1"}, {"6000000", "0.01"}}}}},
			}},
		},
	}
}
