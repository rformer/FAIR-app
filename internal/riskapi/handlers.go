package riskapi

import (
	"net/http"

	"github.com/rformer/fair-app/pkg/authz"
)

// The routes' handlers, named as the contract's operationIds.

func (a *API) listScenarios(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.list(scenarios, w, r, p)
}
func (a *API) createScenario(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.create(scenarios, w, r, p)
}
func (a *API) getScenario(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.get(scenarios, w, r, p)
}
func (a *API) saveScenario(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.save(scenarios, w, r, p)
}
func (a *API) listScenarioVersions(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.versions(scenarios, w, r, p)
}
func (a *API) getScenarioVersion(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.getVersion(scenarios, w, r, p)
}

func (a *API) listLibrary(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.list(library, w, r, p)
}
func (a *API) createLibraryEntry(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.create(library, w, r, p)
}
func (a *API) getLibraryEntry(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.get(library, w, r, p)
}
func (a *API) saveLibraryEntry(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.save(library, w, r, p)
}
func (a *API) listLibraryVersions(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.versions(library, w, r, p)
}
func (a *API) getLibraryVersion(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.getVersion(library, w, r, p)
}

func (a *API) listControls(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.list(controls, w, r, p)
}
func (a *API) createControl(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.create(controls, w, r, p)
}
func (a *API) getControl(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.get(controls, w, r, p)
}
func (a *API) saveControl(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.save(controls, w, r, p)
}
func (a *API) listControlVersions(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.versions(controls, w, r, p)
}
func (a *API) getControlVersion(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.getVersion(controls, w, r, p)
}

func (a *API) diffScenario(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.diff(scenarios, w, r, p)
}
func (a *API) adoptScenarioPins(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.adopt(scenarios, w, r, p)
}
func (a *API) diffLibraryEntry(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.diff(library, w, r, p)
}
func (a *API) diffControl(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.diff(controls, w, r, p)
}

func (a *API) getScenarioBundle(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.bundle(scenarios, w, r, p)
}

func (a *API) archiveScenario(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setArchived(scenarios, true, w, r, p)
}
func (a *API) restoreScenario(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setArchived(scenarios, false, w, r, p)
}
func (a *API) archiveLibraryEntry(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setArchived(library, true, w, r, p)
}
func (a *API) restoreLibraryEntry(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setArchived(library, false, w, r, p)
}
func (a *API) archiveControl(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setArchived(controls, true, w, r, p)
}
func (a *API) restoreControl(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setArchived(controls, false, w, r, p)
}

func (a *API) listStarterEntries(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.starterList(w, r, p)
}
func (a *API) copyStarterEntry(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.starterCopy(w, r, p)
}
