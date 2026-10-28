package oscal

import (
	"time"

	oscaltypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-2-3"
)

// Document is one OSCAL document; exactly one model field is set. It uses
// go-oscal's types except where they disagree with the pinned schema
// (TestTypesMatchSchema keeps it that way).
type Document struct {
	Catalog                   *oscaltypes.Catalog                   `json:"catalog,omitempty"`
	Profile                   *oscaltypes.Profile                   `json:"profile,omitempty"`
	ComponentDefinition       *oscaltypes.ComponentDefinition       `json:"component-definition,omitempty"`
	AssessmentResults         *AssessmentResultsModel               `json:"assessment-results,omitempty"`
	PlanOfActionAndMilestones *oscaltypes.PlanOfActionAndMilestones `json:"plan-of-action-and-milestones,omitempty"`
}

type (
	// CatalogModel is oscal-catalog:catalog.
	CatalogModel = oscaltypes.Catalog
	// ProfileModel is oscal-profile:profile.
	ProfileModel = oscaltypes.Profile
	// ComponentDefinitionModel is oscal-component-definition:component-definition.
	ComponentDefinitionModel = oscaltypes.ComponentDefinition
	// POAMModel is oscal-poam:plan-of-action-and-milestones.
	POAMModel = oscaltypes.PlanOfActionAndMilestones
)

// Metadata and the other aliases in this block are the parts of documents
// that F-015's exports assemble (T-33, T-34).
type (
	Metadata           = oscaltypes.Metadata
	Property           = oscaltypes.Property
	Link               = oscaltypes.Link
	BackMatter         = oscaltypes.BackMatter
	Resource           = oscaltypes.Resource
	ImportAp           = oscaltypes.ImportAp
	ReviewedControls   = oscaltypes.ReviewedControls
	AssessedControls   = oscaltypes.AssessedControls
	ControlByID        = oscaltypes.AssessedControlsSelectControlById
	IncludeAll         = oscaltypes.IncludeAll
	Observation        = oscaltypes.Observation
	SubjectReference   = oscaltypes.SubjectReference
	Finding            = oscaltypes.Finding
	FindingTarget      = oscaltypes.FindingTarget
	ObjectiveStatus    = oscaltypes.ObjectiveStatus
	RelatedObservation = oscaltypes.RelatedObservation
	SystemComponent    = oscaltypes.SystemComponent
	ComponentStatus    = oscaltypes.SystemComponentStatus
	POAMItem           = oscaltypes.PoamItem
	POAMLocalDefs      = oscaltypes.PlanOfActionAndMilestonesLocalDefinitions
	RelatedFinding     = oscaltypes.RelatedFinding
)

// go-oscal v0.7.2 generates a single LocalDefinitions type for three
// different schema shapes, so an assessment result's local definitions lose
// "tasks" and "assessment-assets". The assessment-results subtree is
// therefore declared here, mirroring go-oscal's fields otherwise.

// AssessmentResultsModel is oscal-ar:assessment-results.
type AssessmentResultsModel struct {
	BackMatter       *oscaltypes.BackMatter `json:"back-matter,omitempty"`
	ImportAp         oscaltypes.ImportAp    `json:"import-ap"`
	LocalDefinitions *ARLocalDefinitions    `json:"local-definitions,omitempty"`
	Metadata         oscaltypes.Metadata    `json:"metadata"`
	Results          []Result               `json:"results"`
	UUID             string                 `json:"uuid"`
}

// ARLocalDefinitions is assessment-results/local-definitions.
type ARLocalDefinitions struct {
	Activities           *[]oscaltypes.Activity       `json:"activities,omitempty"`
	ObjectivesAndMethods *[]oscaltypes.LocalObjective `json:"objectives-and-methods,omitempty"`
	Remarks              string                       `json:"remarks,omitempty"`
}

// Result is oscal-ar:result.
type Result struct {
	AssessmentLog    *oscaltypes.AssessmentLog           `json:"assessment-log,omitempty"`
	Attestations     *[]oscaltypes.AttestationStatements `json:"attestations,omitempty"`
	Description      string                              `json:"description"`
	End              *time.Time                          `json:"end,omitempty"`
	Findings         *[]oscaltypes.Finding               `json:"findings,omitempty"`
	Links            *[]oscaltypes.Link                  `json:"links,omitempty"`
	LocalDefinitions *ResultLocalDefinitions             `json:"local-definitions,omitempty"`
	Observations     *[]oscaltypes.Observation           `json:"observations,omitempty"`
	Props            *[]oscaltypes.Property              `json:"props,omitempty"`
	Remarks          string                              `json:"remarks,omitempty"`
	ReviewedControls oscaltypes.ReviewedControls         `json:"reviewed-controls"`
	Risks            *[]oscaltypes.Risk                  `json:"risks,omitempty"`
	Start            time.Time                           `json:"start"`
	Title            string                              `json:"title"`
	UUID             string                              `json:"uuid"`
}

// ResultLocalDefinitions is assessment-results/results/local-definitions.
type ResultLocalDefinitions struct {
	AssessmentAssets *oscaltypes.AssessmentAssets  `json:"assessment-assets,omitempty"`
	Components       *[]oscaltypes.SystemComponent `json:"components,omitempty"`
	InventoryItems   *[]oscaltypes.InventoryItem   `json:"inventory-items,omitempty"`
	Tasks            *[]oscaltypes.Task            `json:"tasks,omitempty"`
	Users            *[]oscaltypes.SystemUser      `json:"users,omitempty"`
}
