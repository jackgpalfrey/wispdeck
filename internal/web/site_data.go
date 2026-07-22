package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	hostedsite "github.com/wispdeck/wispdeck/internal/site"
	"github.com/wispdeck/wispdeck/wispist"
)

const siteDataPageSize = 50

type siteDataCollectionView struct {
	Name      string
	Documents string
	Bytes     string
	Declared  bool
	Selected  bool
	URL       string
}

type siteDataDocumentView struct {
	ID        string
	Revision  string
	UpdatedAt string
	Data      string
}

type siteDataView struct {
	Shell          shellView
	CSRFToken      string
	SiteName       string
	Host           string
	Namespace      string
	NamespaceLabel string
	LiveURL        string
	DraftURL       string
	ExportURL      string
	Usage          string
	UsageDetail    string
	Collections    []siteDataCollectionView
	Selected       string
	Documents      []siteDataDocumentView
	FirstPageURL   string
	NextPageURL    string
	HasPrevious    bool
}

func (s *Server) siteDataPage(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	name, err := hostedsite.NormalizeName(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	site, err := s.managedSiteByName(r.Context(), session, name)
	if errors.Is(err, hostedsite.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "load site data page", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	namespace, ok := siteDataNamespace(r.URL.Query().Get("namespace"))
	if !ok {
		http.Error(w, "invalid namespace", http.StatusBadRequest)
		return
	}
	ref := s.siteDataRef(site.ID, namespace)
	usage, err := s.wispist.NamespaceUsage(r.Context(), ref)
	if err != nil {
		s.renderSiteDataError(w, r, err, "Site data unavailable")
		return
	}
	declared, err := s.siteDeclaredCollections(r.Context(), site, namespace)
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "load Wispist declaration for data page", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	type collectionState struct {
		documents int
		bytes     int64
		declared  bool
	}
	states := make(map[string]collectionState, len(declared)+len(usage.Collections))
	for _, collection := range declared {
		state := states[collection]
		state.declared = true
		states[collection] = state
	}
	for _, stored := range usage.Collections {
		state := states[stored.Name]
		state.documents = stored.Documents
		state.bytes = stored.Bytes
		states[stored.Name] = state
	}
	names := make([]string, 0, len(states))
	for collection := range states {
		names = append(names, collection)
	}
	sort.Strings(names)
	selected := r.URL.Query().Get("collection")
	if selected != "" {
		if !wispist.ValidCollectionName(selected) {
			http.Error(w, "invalid collection", http.StatusBadRequest)
			return
		}
		if _, exists := states[selected]; !exists {
			http.NotFound(w, r)
			return
		}
	} else if len(names) > 0 {
		selected = names[0]
	}

	view := siteDataView{
		Shell: s.shell(session, "home"), CSRFToken: session.CSRFToken,
		SiteName: site.Name, Host: site.Name + "." + s.config.SiteDomain,
		Namespace: namespace, NamespaceLabel: strings.ToUpper(namespace[:1]) + namespace[1:],
		LiveURL:   siteDataURL(site.Name, "live", "", ""),
		DraftURL:  siteDataURL(site.Name, "draft", "", ""),
		ExportURL: "/sites/" + url.PathEscape(site.Name) + "/data/export",
		Usage:     formatBytes(usage.Bytes) + " / " + formatBytes(ref.MaxBytes),
		UsageDetail: fmt.Sprintf(
			"%s document%s across %s collection%s",
			formatCount(int64(usage.Documents)), plural(usage.Documents),
			formatCount(int64(len(states))), plural(len(states)),
		),
		Selected: selected,
	}
	for _, collection := range names {
		state := states[collection]
		view.Collections = append(view.Collections, siteDataCollectionView{
			Name: collection, Documents: formatCount(int64(state.documents)), Bytes: formatBytes(state.bytes),
			Declared: state.declared, Selected: collection == selected,
			URL: siteDataURL(site.Name, namespace, collection, ""),
		})
	}
	if selected != "" {
		after := r.URL.Query().Get("after")
		if len(after) > 4096 {
			http.Error(w, "invalid page cursor", http.StatusBadRequest)
			return
		}
		page, err := s.wispist.ListNamespaceDocuments(
			r.Context(), ref, selected, siteDataPageSize, after,
		)
		if err != nil {
			s.renderSiteDataError(w, r, err, "Site data unavailable")
			return
		}
		now := time.Now().UTC()
		for _, document := range page.Documents {
			view.Documents = append(view.Documents, siteDataDocumentView{
				ID: document.ID, Revision: document.Revision,
				UpdatedAt: shortDateTime(document.UpdatedAt, now), Data: prettyJSON(document.Data),
			})
		}
		view.FirstPageURL = siteDataURL(site.Name, namespace, selected, "")
		view.HasPrevious = after != ""
		if page.After != "" {
			view.NextPageURL = siteDataURL(site.Name, namespace, selected, page.After)
		}
	}
	s.render(w, http.StatusOK, "site_data.html", view)
}

func (s *Server) exportSiteData(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	name, err := hostedsite.NormalizeName(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	site, err := s.managedSiteByName(r.Context(), session, name)
	if errors.Is(err, hostedsite.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "load site for Wispist export", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	refs := []wispist.NamespaceRef{s.siteDataRef(site.ID, "live"), s.siteDataRef(site.ID, "draft")}
	snapshots, err := s.wispist.NamespaceSnapshots(r.Context(), refs)
	if err != nil {
		s.renderSiteDataError(w, r, err, "Site data export failed")
		return
	}
	for _, namespace := range []string{"live", "draft"} {
		declared, err := s.siteDeclaredCollections(r.Context(), site, namespace)
		if err != nil {
			s.config.Logger.ErrorContext(r.Context(), "load Wispist declaration for export", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		snapshot := snapshots[namespace]
		for _, collection := range declared {
			if _, exists := snapshot.Collections[collection]; !exists {
				snapshot.Collections[collection] = []wispist.Document{}
			}
		}
		snapshots[namespace] = snapshot
	}
	export := struct {
		Format     string                               `json:"format"`
		Version    int                                  `json:"version"`
		Site       string                               `json:"site"`
		ExportedAt time.Time                            `json:"exportedAt"`
		Namespaces map[string]wispist.NamespaceSnapshot `json:"namespaces"`
	}{
		Format: "wispist-site-export", Version: 1, Site: site.Name,
		ExportedAt: time.Now().UTC(), Namespaces: snapshots,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(
		`attachment; filename="%s-wispist.json"`, site.Name,
	))
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(export); err != nil {
		s.config.Logger.ErrorContext(r.Context(), "encode Wispist export", "error", err)
	}
}

func (s *Server) updateSiteDataDocument(w http.ResponseWriter, r *http.Request) {
	_, site, ref, collection, ok := s.validSiteDataMutation(w, r, 128<<10)
	if !ok {
		return
	}
	_, err := s.wispist.ReplaceNamespaceDocument(
		r.Context(), ref, collection, r.PostForm.Get("document_id"),
		r.PostForm.Get("revision"), []byte(r.PostForm.Get("data")),
	)
	if err != nil {
		s.renderSiteDataError(w, r, err, "Document not saved")
		return
	}
	s.redirectSiteData(w, r, site.Name, ref.Namespace, collection)
}

func (s *Server) deleteSiteDataDocument(w http.ResponseWriter, r *http.Request) {
	_, site, ref, collection, ok := s.validSiteDataMutation(w, r, 16<<10)
	if !ok {
		return
	}
	if err := s.wispist.DeleteNamespaceDocument(
		r.Context(), ref, collection, r.PostForm.Get("document_id"), r.PostForm.Get("revision"),
	); err != nil {
		s.renderSiteDataError(w, r, err, "Document not deleted")
		return
	}
	s.redirectSiteData(w, r, site.Name, ref.Namespace, collection)
}

func (s *Server) clearSiteDataCollection(w http.ResponseWriter, r *http.Request) {
	_, site, ref, collection, ok := s.validSiteDataMutation(w, r, 16<<10)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != collection {
		http.Error(w, "collection clear must be confirmed", http.StatusBadRequest)
		return
	}
	if _, err := s.wispist.ClearNamespaceCollection(r.Context(), ref, collection); err != nil {
		s.renderSiteDataError(w, r, err, "Collection not cleared")
		return
	}
	s.redirectSiteData(w, r, site.Name, ref.Namespace, collection)
}

func (s *Server) deleteSiteRelease(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validSiteForm(w, r, 16<<10)
	if !ok {
		return
	}
	name, err := hostedsite.NormalizeName(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	site, err := s.managedSiteByName(r.Context(), session, name)
	if err == nil {
		err = s.sites.DeleteRelease(r.Context(), siteActor(session), site.ID, r.PostForm.Get("release_id"))
	}
	if err != nil {
		s.renderSiteManagementError(w, r, err, "Release not deleted")
		return
	}
	http.Redirect(w, r, "/sites/"+url.PathEscape(site.Name), http.StatusSeeOther)
}

func (s *Server) purgeSite(w http.ResponseWriter, r *http.Request) {
	session, ok := s.validSiteForm(w, r, 16<<10)
	if !ok {
		return
	}
	name, err := hostedsite.NormalizeName(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	site, err := s.managedSiteByName(r.Context(), session, name)
	if err != nil {
		s.renderSiteManagementError(w, r, err, "Site not erased")
		return
	}
	if r.PostForm.Get("confirm") != site.Name {
		http.Error(w, "site erase must be confirmed", http.StatusBadRequest)
		return
	}
	if err := s.sites.PurgeContent(r.Context(), siteActor(session), site.ID); err != nil {
		s.renderSiteManagementError(w, r, err, "Site not erased")
		return
	}
	// The control-plane purge runs first so public and preview mutations are
	// impossible while the separate per-site database is being erased.
	for _, namespace := range []string{"live", "draft"} {
		if err := s.wispist.PurgeNamespace(r.Context(), s.siteDataRef(site.ID, namespace)); err != nil {
			s.config.Logger.ErrorContext(
				r.Context(), "purge Wispist after site was taken offline",
				"error", err, "site_id", site.ID, "namespace", namespace,
			)
			s.renderManagementMessage(
				w, http.StatusInternalServerError, "Site data cleanup incomplete",
				"The site is offline and its releases are erased, but some Wispist data could not be removed. Retry the erase action.",
			)
			return
		}
	}
	http.Redirect(w, r, "/sites/"+url.PathEscape(site.Name), http.StatusSeeOther)
}

func (s *Server) validSiteDataMutation(
	w http.ResponseWriter,
	r *http.Request,
	limit int64,
) (auth.Session, hostedsite.Site, wispist.NamespaceRef, string, bool) {
	session, ok := s.validSiteForm(w, r, limit)
	if !ok {
		return auth.Session{}, hostedsite.Site{}, wispist.NamespaceRef{}, "", false
	}
	name, err := hostedsite.NormalizeName(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return auth.Session{}, hostedsite.Site{}, wispist.NamespaceRef{}, "", false
	}
	site, err := s.managedSiteByName(r.Context(), session, name)
	if errors.Is(err, hostedsite.ErrNotFound) {
		http.NotFound(w, r)
		return auth.Session{}, hostedsite.Site{}, wispist.NamespaceRef{}, "", false
	}
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "authorize site data mutation", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return auth.Session{}, hostedsite.Site{}, wispist.NamespaceRef{}, "", false
	}
	namespace, valid := siteDataNamespace(r.PostForm.Get("namespace"))
	collection := r.PostForm.Get("collection")
	if !valid || !wispist.ValidCollectionName(collection) {
		http.Error(w, "invalid site data target", http.StatusBadRequest)
		return auth.Session{}, hostedsite.Site{}, wispist.NamespaceRef{}, "", false
	}
	return session, site, s.siteDataRef(site.ID, namespace), collection, true
}

func (s *Server) siteDataRef(siteID, namespace string) wispist.NamespaceRef {
	maxBytes := s.wispist.Limits().MaxNamespaceBytes
	if namespace == "draft" {
		maxBytes = s.wispist.Limits().MaxDraftNamespaceBytes
	}
	return wispist.NamespaceRef{StoreKey: siteID, Namespace: namespace, MaxBytes: maxBytes}
}

func (s *Server) siteDeclaredCollections(
	ctx context.Context,
	site hostedsite.Site,
	namespace string,
) ([]string, error) {
	releaseID := site.PublishedReleaseID
	if namespace == "draft" {
		releaseID = site.DraftReleaseID
	}
	if releaseID == "" {
		return []string{}, nil
	}
	file, err := s.sites.File(ctx, releaseID, "wispist.json")
	if errors.Is(err, hostedsite.ErrNotFound) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	declaration, err := s.wispist.ParseDeclaration(file.Body)
	if err != nil {
		return nil, err
	}
	collections := make([]string, 0, len(declaration.Collections))
	for collection := range declaration.Collections {
		collections = append(collections, collection)
	}
	sort.Strings(collections)
	return collections, nil
}

func (s *Server) renderSiteDataError(w http.ResponseWriter, r *http.Request, err error, title string) {
	status := http.StatusBadRequest
	message := "The requested data change could not be completed."
	switch {
	case errors.Is(err, wispist.ErrInvalidDocumentData):
		message = "Document data must be a valid JSON object within the configured size limit."
	case errors.Is(err, wispist.ErrRevisionConflict):
		status = http.StatusConflict
		message = "That document changed after this page loaded. Reload the data page before trying again."
	case errors.Is(err, wispist.ErrDocumentNotFound):
		status = http.StatusNotFound
		message = "That document no longer exists."
	case errors.Is(err, wispist.ErrQuotaExceeded):
		status = http.StatusConflict
		message = "The change would exceed this namespace's storage limit."
	case errors.Is(err, wispist.ErrInvalidCursor), errors.Is(err, wispist.ErrInvalidNamespaceRef):
		message = "The site data target or page cursor is invalid."
	default:
		s.config.Logger.ErrorContext(r.Context(), "manage Wispist site data", "title", title, "error", err)
		status = http.StatusInternalServerError
		message = "The data operation failed internally."
	}
	s.renderManagementMessage(w, status, title, message)
}

func (s *Server) redirectSiteData(w http.ResponseWriter, r *http.Request, site, namespace, collection string) {
	http.Redirect(w, r, siteDataURL(site, namespace, collection, ""), http.StatusSeeOther)
}

func siteDataNamespace(value string) (string, bool) {
	if value == "" {
		return "live", true
	}
	return value, value == "live" || value == "draft"
}

func siteDataURL(site, namespace, collection, after string) string {
	query := url.Values{"namespace": {namespace}}
	if collection != "" {
		query.Set("collection", collection)
	}
	if after != "" {
		query.Set("after", after)
	}
	return "/sites/" + url.PathEscape(site) + "/data?" + query.Encode()
}

func prettyJSON(raw []byte) string {
	var output bytes.Buffer
	if err := json.Indent(&output, raw, "", "  "); err != nil {
		return string(raw)
	}
	return output.String()
}
