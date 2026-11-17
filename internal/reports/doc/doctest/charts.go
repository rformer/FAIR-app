package doctest

import "github.com/rformer/fair-app/internal/reports/doc"

// Charts is a portfolio report with one chart of each kind besides the
// sample's: two loss exceedance curves on a log axis, a histogram of annual
// loss, and bars of each risk's contribution.
func Charts() doc.Document {
	d := Sample()
	d.Metadata.Kind, d.Metadata.Title = "portfolio", "Portfolio: Claims"
	lec := &doc.Table{ID: "lec", Caption: "Loss exceedance by control set",
		Columns: []doc.Column{{Key: "loss", Title: "Annual loss", Type: doc.ColAmount}, {Key: "current", Title: "Current", Type: doc.ColPercent},
			{Key: "mfa", Title: "With MFA", Type: doc.ColPercent}},
		Rows: [][]string{{"10000", "0.99", "0.97"}, {"100000", "0.9", "0.7"}, {"500000", "0.6", "0.35"}, {"1000000", "0.4", "0.2"},
			{"5000000", "0.08", "0.03"}, {"20000000", "0.005", "0.001"}}}
	hist := &doc.Table{ID: "histogram", Caption: "Distribution of annual loss",
		Columns: []doc.Column{{Key: "from", Title: "Annual loss from", Type: doc.ColAmount}, {Key: "share", Title: "Share of years", Type: doc.ColPercent}},
		Rows:    [][]string{{"0", "0.3"}, {"500000", "0.35"}, {"1000000", "0.2"}, {"1500000", "0.1"}, {"2000000", "0.05"}}}
	contrib := &doc.Table{ID: "contributions", Caption: "Mean annualized loss by risk",
		Columns: []doc.Column{{Key: "risk", Title: "Risk", Type: doc.ColText}, {Key: "mean", Title: "Mean", Type: doc.ColAmount}},
		Rows:    [][]string{{"Ransomware on claims", "1000000"}, {"Fraudulent claims through a compromised adjuster account", "250000"}, {"Records retention fine", "40000"}}}
	d.Sections = append(d.Sections, doc.Section{Heading: "Charts", Level: 1, Blocks: []doc.Block{
		{Kind: doc.KindChart, Chart: &doc.Chart{Kind: doc.ChartExceedance, Title: "Loss exceedance, current and with MFA", Log: true,
			Alt: "Two loss exceedance curves; with MFA, the chance of losing more than 1,000,000 USD falls from 40% to 20%.", XKey: "loss",
			Series: []doc.Ref{{ID: "current", Name: "Current"}, {ID: "mfa", Name: "With MFA"}}, Data: lec}},
		{Kind: doc.KindChart, Chart: &doc.Chart{Kind: doc.ChartHistogram, Title: "Distribution of annual loss",
			Alt: "A histogram: most years lose under 1,000,000 USD; 5% lose 2,000,000 USD or more.", XKey: "from",
			Series: []doc.Ref{{ID: "share", Name: "Share of years"}}, Data: hist}},
		{Kind: doc.KindChart, Chart: &doc.Chart{Kind: doc.ChartBars, Title: "Contributions",
			Alt: "Bars: ransomware contributes 1,000,000 USD of mean annualized loss, fraud 250,000 USD, the fine 40,000 USD.", XKey: "risk",
			Series: []doc.Ref{{ID: "mean", Name: "Mean annualized loss"}}, Data: contrib}},
	}})
	return d
}
