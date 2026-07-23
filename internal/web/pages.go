package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/branding"
	"github.com/wispdeck/wispdeck/internal/shortlink"
	hostedsite "github.com/wispdeck/wispdeck/internal/site"
	"github.com/wispdeck/wispdeck/internal/updater"
)

// shellView feeds the shared application header partial.
type shellView struct {
	Username        string
	UserInitial     string
	Tab             string
	UpdateAvailable bool
	UpdateApplying  bool
	UpdateVersion   string
}

func (s *Server) shell(session auth.Session, tab string) shellView {
	view := shellView{
		Username:    session.User.Username,
		UserInitial: firstLetter(session.User.Username, "?"),
		Tab:         tab,
	}
	if session.User.Role == auth.RoleSuperuser && s.updates != nil {
		snapshot := s.updates.Snapshot()
		view.UpdateAvailable = snapshot.Available
		view.UpdateApplying = snapshot.Applying
		view.UpdateVersion = snapshot.Latest.Version
	}
	return view
}

func firstLetter(value, fallback string) string {
	for _, r := range value {
		return string(r)
	}
	return fallback
}

func managedAssurance(session auth.Session) bool {
	return session.Assurance == auth.AssuranceMFA || session.Assurance == auth.AssurancePassword
}

// home serves the public landing page to signed-out visitors and the
// dashboard to authenticated users.
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if token, ok := s.sessionFromRequest(r); ok {
		session, err := s.auth.Authenticate(r.Context(), token)
		if err == nil {
			ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
			s.dashboard(w, r.WithContext(ctx))
			return
		}
		if !errors.Is(err, auth.ErrInvalidSession) {
			s.config.Logger.ErrorContext(r.Context(), "session lookup failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		s.clearSessionCookie(w)
	}
	currentBranding := s.branding.Current()
	if !currentBranding.LandingPageEnabled {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.render(w, http.StatusOK, "landing.html", struct {
		Brand      string
		Initial    string
		SiteDomain string
	}{currentBranding.Name, firstLetter(currentBranding.Name, "w"), s.config.SiteDomain})
}

/* ---------- unified dashboard ---------- */

type sparkBarView struct {
	H   int
	Hot bool
}

type dashRowView struct {
	Kind      string
	Badge     string
	Addr      string
	Dest      string
	Owner     string
	Hits      string
	DateLabel string
	Warn      bool
	CopyURL   string
	DetailURL string
	Search    string
	Trend     []sparkBarView

	sortKey time.Time
}

type dashboardView struct {
	Shell          shellView
	CSRFToken      string
	Assurance      auth.Assurance
	ShowOwners     bool
	ShortBase      string
	SiteDomain     string
	CreatedURL     string
	CreatedDisplay string
	ShortenPrefill string
	ShortenValue   string
	Create         shortLinkForm
	Rows           []dashRowView
	LinkCount      int
	SiteCount      int
	TotalCount     int
	Hits30         string
	Audit          []auditEventView
}

func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, status int, form shortLinkForm) {
	session := sessionFromContext(r.Context())
	actor := shortLinkActor(session)
	links, err := s.links.List(r.Context(), actor)
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "list short links", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	auditEvents, err := s.links.AuditEvents(r.Context(), actor, 25)
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "list short-link audit events", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	hostedSites, err := s.sites.List(r.Context(), siteActor(session))
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "list hosted sites", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	showOwners := session.User.Role == auth.RoleSuperuser

	rows := make([]dashRowView, 0, len(links)+len(hostedSites))
	var hits30 int64
	for _, link := range links {
		for _, stat := range link.DailyStats {
			hits30 += stat.Visits
		}
		rows = append(rows, s.linkRow(link, session, now, showOwners))
	}
	for _, site := range hostedSites {
		rows = append(rows, s.siteRow(site, session, now, showOwners))
	}
	sort.SliceStable(rows, func(a, b int) bool { return rows[a].sortKey.After(rows[b].sortKey) })

	audit := make([]auditEventView, 0, len(auditEvents))
	for _, event := range auditEvents {
		audit = append(audit, auditEventView{
			OccurredAt:    event.OccurredAt.Format("2006-01-02 15:04 UTC"),
			ActorUsername: event.ActorUsername, OwnerUsername: event.OwnerUsername,
			Slug: event.Slug, Action: auditAction(event.Kind),
		})
	}

	createdURL := ""
	createdDisplay := ""
	if createdSlug, normalizeErr := shortlink.NormalizeSlug(r.URL.Query().Get("created")); normalizeErr == nil {
		for _, link := range links {
			if link.Slug == createdSlug && link.OwnerUserID == actor.UserID && link.Enabled &&
				(link.ExpiresAt.IsZero() || link.ExpiresAt.After(now)) {
				createdURL = s.shortLinkURL(createdSlug)
				createdDisplay = s.shortLinkDisplay(createdSlug)
				break
			}
		}
	}

	prefill := r.URL.Query().Get("shorten")
	if len(prefill) > 4096 || !(strings.HasPrefix(prefill, "https://") || strings.HasPrefix(prefill, "http://")) {
		prefill = ""
	}

	form = withShortLinkFormDefaults(form)
	shortenValue := prefill
	if form.Destinations[0].URL != "" {
		shortenValue = form.Destinations[0].URL
	}
	s.render(w, status, "dashboard.html", dashboardView{
		Shell:      s.shell(session, "home"),
		CSRFToken:  session.CSRFToken,
		Assurance:  session.Assurance,
		ShowOwners: showOwners,
		ShortBase:  s.config.AppOrigin.Host + "/",
		SiteDomain: s.config.SiteDomain,
		CreatedURL: createdURL, CreatedDisplay: createdDisplay,
		ShortenPrefill: prefill,
		ShortenValue:   shortenValue,
		Create:         form,
		Rows:           rows,
		LinkCount:      len(links),
		SiteCount:      len(hostedSites),
		TotalCount:     len(links) + len(hostedSites),
		Hits30:         formatCount(hits30),
		Audit:          audit,
	})
}

func (s *Server) linkRow(link shortlink.Link, session auth.Session, now time.Time, showOwners bool) dashRowView {
	expired := !link.ExpiresAt.IsZero() && !link.ExpiresAt.After(now)
	dest := ""
	if len(link.Destinations) == 1 {
		dest = link.Destinations[0].URL
	} else {
		dest = fmt.Sprintf("%d destinations · %s", len(link.Destinations), shortLinkModeLabel(link.Mode))
	}
	dateLabel := shortDate(link.CreatedAt, now)
	warn := false
	switch {
	case expired:
		dateLabel += " · expired"
		warn = true
	case !link.Enabled:
		dateLabel += " · paused"
		warn = true
	case !link.ExpiresAt.IsZero():
		dateLabel += " · expires"
		warn = true
	}
	owner := ""
	if showOwners && link.OwnerUserID != session.User.ID {
		owner = link.OwnerUsername
	}
	searchParts := []string{link.Slug, link.Title, link.OwnerUsername}
	for _, destination := range link.Destinations {
		searchParts = append(searchParts, destination.URL, destination.Label)
	}
	return dashRowView{
		Kind:      "link",
		Badge:     "LINK",
		Addr:      s.shortLinkDisplay(link.Slug),
		Dest:      dest,
		Owner:     owner,
		Hits:      formatCount(link.VisitCount),
		DateLabel: dateLabel,
		Warn:      warn,
		CopyURL:   s.shortLinkURL(link.Slug),
		DetailURL: "/links/" + link.ID,
		Search:    strings.Join(searchParts, " "),
		Trend:     sparkline(dailySeries(link.DailyStats, now, 4)),
		sortKey:   link.CreatedAt,
	}
}

func (s *Server) siteRow(site hostedsite.Site, session auth.Session, now time.Time, showOwners bool) dashRowView {
	dest := "no uploads yet"
	if len(site.Releases) > 0 {
		current := currentRelease(site)
		if current != nil {
			dest = fmt.Sprintf("v%d live · %d file%s · %s", current.Version, current.FileCount,
				plural(current.FileCount), formatBytes(current.TotalBytes))
		} else {
			dest = "draft uploaded · nothing published yet"
		}
		if site.Title != "" {
			dest = site.Title + " · " + dest
		}
	} else if site.Title != "" {
		dest = site.Title + " · " + dest
	}

	updated := site.UpdatedAt
	if updated.IsZero() {
		updated = site.CreatedAt
	}
	dateLabel := shortDate(updated, now)
	warn := false
	switch {
	case !site.Enabled:
		dateLabel += " · offline"
		warn = true
	case site.DraftReleaseID != "":
		dateLabel += " · draft"
		warn = true
	}
	owner := ""
	if showOwners && site.OwnerUserID != session.User.ID {
		owner = site.OwnerUsername
	}
	host := site.Name + "." + s.config.SiteDomain
	return dashRowView{
		Kind:      "site",
		Badge:     "SITE",
		Addr:      host,
		Dest:      dest,
		Owner:     owner,
		Hits:      "—",
		DateLabel: dateLabel,
		Warn:      warn,
		CopyURL:   s.siteURL(site.Name, "/").String(),
		DetailURL: "/sites/" + site.Name,
		Search:    strings.Join([]string{host, site.Title, site.OwnerUsername}, " "),
		sortKey:   updated,
	}
}

func currentRelease(site hostedsite.Site) *hostedsite.Release {
	for i := range site.Releases {
		if site.Releases[i].ID == site.PublishedReleaseID {
			return &site.Releases[i]
		}
	}
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

/* ---------- link detail ---------- */

type chartBarView struct {
	H   int
	Tip string
}

type linkDetailView struct {
	Shell          shellView
	CSRFToken      string
	Link           shortLinkView
	Display        string
	PrimaryDest    string
	ExtraDestCount int
	Total30        string
	Today          string
	Bars           []chartBarView
	ChartStart     string
	ChartEnd       string
	OwnerUsername  string
}

func (s *Server) linkDetailPage(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !managedAssurance(session) {
		http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
		return
	}
	links, err := s.links.List(r.Context(), shortLinkActor(session))
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "list short links", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	var link *shortlink.Link
	for i := range links {
		if links[i].ID == id {
			link = &links[i]
			break
		}
	}
	if link == nil {
		http.NotFound(w, r)
		return
	}
	now := time.Now().UTC()
	series := dailySeries(link.DailyStats, now, 30)
	var total30 int64
	for _, visits := range series {
		total30 += visits
	}
	bars := make([]chartBarView, len(series))
	maxVisits := int64(1)
	for _, visits := range series {
		if visits > maxVisits {
			maxVisits = visits
		}
	}
	for i, visits := range series {
		day := now.AddDate(0, 0, i-len(series)+1)
		bars[i] = chartBarView{
			H:   chartBucket(visits, maxVisits),
			Tip: fmt.Sprintf("%d visit%s · %s", visits, plural64(visits), day.Format("Jan 2")),
		}
	}
	primary := ""
	if len(link.Destinations) > 0 {
		primary = link.Destinations[0].URL
	}
	owner := ""
	if session.User.Role == auth.RoleSuperuser && link.OwnerUserID != session.User.ID {
		owner = link.OwnerUsername
	}
	s.render(w, http.StatusOK, "link_detail.html", linkDetailView{
		Shell:          s.shell(session, "home"),
		CSRFToken:      session.CSRFToken,
		Link:           s.shortLinkView(*link, now),
		Display:        s.shortLinkDisplay(link.Slug),
		PrimaryDest:    primary,
		ExtraDestCount: max(0, len(link.Destinations)-1),
		Total30:        formatCount(total30),
		Today:          formatCount(series[len(series)-1]),
		Bars:           bars,
		ChartStart:     now.AddDate(0, 0, -29).Format("Jan 2"),
		ChartEnd:       now.Format("Jan 2"),
		OwnerUsername:  owner,
	})
}

func plural64(n int64) string {
	if n == 1 {
		return ""
	}
	return "s"
}

/* ---------- site detail / creation ---------- */

type siteDetailView struct {
	Shell         shellView
	CSRFToken     string
	Site          siteView
	Host          string
	AliasDisplay  string
	StatusLine    string
	CurrentFiles  string
	CurrentSize   string
	UpdatedAt     string
	CreatedAt     string
	OwnerUsername string
	ReleaseUsage  string
	StorageUsage  string
	OwnerUsage    string
}

func (s *Server) siteDetailPage(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !managedAssurance(session) {
		http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
		return
	}
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
		s.config.Logger.ErrorContext(r.Context(), "load managed site", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	usage, err := s.sites.Usage(r.Context(), siteActor(session), site.ID)
	if err != nil {
		s.config.Logger.ErrorContext(r.Context(), "load hosted-site usage", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	view := siteDetailView{
		Shell:        s.shell(session, "home"),
		CSRFToken:    session.CSRFToken,
		Site:         siteViewFrom(site, s, now),
		Host:         site.Name + "." + s.config.SiteDomain,
		AliasDisplay: s.config.AppOrigin.Host + "/" + site.Name,
		CreatedAt:    shortDate(site.CreatedAt, now),
		ReleaseUsage: fmt.Sprintf("%d / %d", usage.SiteReleases, usage.Limits.MaxReleasesPerSite),
		StorageUsage: formatBytes(usage.SiteBytes),
		OwnerUsage: fmt.Sprintf(
			"%s / %s retained across %d / %d sites",
			formatBytes(usage.OwnerBytes), formatBytes(usage.Limits.MaxStorageBytesPerUser),
			usage.OwnerSites, usage.Limits.MaxSitesPerUser,
		),
	}
	switch {
	case !site.Enabled:
		view.StatusLine = "offline — visitors see a not-found page"
	case site.PublishedReleaseID != "":
		view.StatusLine = "live — serving the current release"
	case site.DraftReleaseID != "":
		view.StatusLine = "draft only — visitors see a sign-in gate"
	default:
		view.StatusLine = "empty — visitors see a reserved-name page"
	}
	if current := currentRelease(site); current != nil {
		view.CurrentFiles = formatCount(int64(current.FileCount))
		view.CurrentSize = formatBytes(current.TotalBytes)
	}
	updated := site.UpdatedAt
	if updated.IsZero() {
		updated = site.CreatedAt
	}
	if !updated.IsZero() {
		view.UpdatedAt = shortDate(updated, now)
	}
	if session.User.Role == auth.RoleSuperuser && site.OwnerUserID != session.User.ID {
		view.OwnerUsername = site.OwnerUsername
	}
	s.render(w, http.StatusOK, "site_detail.html", view)
}

func (s *Server) managedSiteByName(ctx context.Context, session auth.Session, name string) (hostedsite.Site, error) {
	values, err := s.sites.List(ctx, siteActor(session))
	if err != nil {
		return hostedsite.Site{}, err
	}
	for _, value := range values {
		if value.Name == name {
			return value, nil
		}
	}
	return hostedsite.Site{}, hostedsite.ErrNotFound
}

type siteCreateForm struct {
	Name             string
	Title            string
	ConfirmedReclaim string
	Error            string
}

type siteCreateView struct {
	Shell      shellView
	CSRFToken  string
	SiteDomain string
	Create     siteCreateForm
}

func (s *Server) newSitePage(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !managedAssurance(session) {
		http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
		return
	}
	s.renderNewSite(w, session, http.StatusOK, siteCreateForm{})
}

func (s *Server) renderNewSite(w http.ResponseWriter, session auth.Session, status int, form siteCreateForm) {
	s.render(w, status, "site_new.html", siteCreateView{
		Shell: s.shell(session, "home"), CSRFToken: session.CSRFToken,
		SiteDomain: s.config.SiteDomain, Create: form,
	})
}

/* ---------- settings ---------- */

type settingsView struct {
	Shell             shellView
	CSRFToken         string
	Username          string
	Role              auth.Role
	AppHost           string
	SiteDomain        string
	PreviewDomain     string
	IsSuperuser       bool
	MaxLinks          int
	MaxSites          int
	MaxReleases       int
	MaxSiteStorage    string
	MaxWispistLive    string
	MaxWispistDraft   string
	UpdatesConfigured bool
	UpdateAvailable   bool
	UpdateVersion     string
	Branding          branding.Settings
	BrandingAccents   []branding.Accent
	BrandingSaved     bool
	BrandingError     string
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !managedAssurance(session) {
		http.Redirect(w, r, "/security/passkeys", http.StatusSeeOther)
		return
	}
	s.renderSettings(w, r, http.StatusOK, s.branding.Current(), "")
}

func (s *Server) renderSettings(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	brandSettings branding.Settings,
	brandingError string,
) {
	session := sessionFromContext(r.Context())
	updateSnapshot := updater.Snapshot{}
	if s.updates != nil {
		updateSnapshot = s.updates.Snapshot()
	}
	s.render(w, status, "settings.html", settingsView{
		Shell:     s.shell(session, "settings"),
		CSRFToken: session.CSRFToken,
		Username:  session.User.Username,
		Role:      session.User.Role,
		AppHost:   s.config.AppOrigin.Host, SiteDomain: s.config.SiteDomain,
		PreviewDomain:     s.config.PreviewDomain,
		IsSuperuser:       session.User.Role == auth.RoleSuperuser,
		MaxLinks:          s.links.Limits().MaxLinksPerUser,
		MaxSites:          s.sites.Limits().MaxSitesPerUser,
		MaxReleases:       s.sites.Limits().MaxReleasesPerSite,
		MaxSiteStorage:    formatBytes(s.sites.Limits().MaxStorageBytesPerUser),
		MaxWispistLive:    formatBytes(s.wispist.Limits().MaxNamespaceBytes),
		MaxWispistDraft:   formatBytes(s.wispist.Limits().MaxDraftNamespaceBytes),
		UpdatesConfigured: updateSnapshot.Configured,
		UpdateAvailable:   updateSnapshot.Available,
		UpdateVersion:     updateSnapshot.Latest.Version,
		Branding:          brandSettings,
		BrandingAccents:   branding.Accents(),
		BrandingSaved:     r.URL.Query().Get("branding") == "saved",
		BrandingError:     brandingError,
	})
}

func (s *Server) changeBranding(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())
	if !s.validBrowserOrigin(r) || !validCSRF(w, r, session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	landingPageEnabled := r.PostForm.Get("landing_page_enabled")
	settings := branding.Settings{
		Name: r.PostForm.Get("instance_name"), Tagline: r.PostForm.Get("tagline"),
		Accent: r.PostForm.Get("accent"), LandingPageEnabled: landingPageEnabled == "true",
	}
	if landingPageEnabled != "" && landingPageEnabled != "true" {
		s.renderSettings(w, r, http.StatusBadRequest, settings, "Choose whether to show the public landing page.")
		return
	}
	normalized, err := branding.Normalize(settings)
	if err != nil {
		s.renderSettings(
			w, r, http.StatusBadRequest, settings,
			"Use a one-line name up to 48 characters, a one-line tagline up to 160 characters, and one of the available colours.",
		)
		return
	}
	if _, err := s.branding.Update(r.Context(), normalized, branding.Actor{
		UserID: session.User.ID, Username: session.User.Username, ClientIP: s.clientAddress(r),
	}); err != nil {
		s.config.Logger.ErrorContext(r.Context(), "change instance branding", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/settings?branding=saved#branding", http.StatusSeeOther)
}

/* ---------- shared helpers ---------- */

func (s *Server) shortLinkDisplay(slug string) string {
	return s.config.AppOrigin.Host + "/" + slug
}

// dailySeries expands sparse daily stats into a dense series covering the
// last `days` days (oldest first, ending today).
func dailySeries(stats []shortlink.DailyStat, now time.Time, days int) []int64 {
	byDay := make(map[string]int64, len(stats))
	for _, stat := range stats {
		byDay[stat.Day.Format("2006-01-02")] += stat.Visits
	}
	series := make([]int64, days)
	for i := range series {
		day := now.AddDate(0, 0, i-days+1)
		series[i] = byDay[day.Format("2006-01-02")]
	}
	return series
}

// sparkline maps a short series onto 3–15px bars; the newest bar is accented
// whenever it has any visits.
func sparkline(series []int64) []sparkBarView {
	maxVisits := int64(0)
	for _, visits := range series {
		if visits > maxVisits {
			maxVisits = visits
		}
	}
	bars := make([]sparkBarView, len(series))
	for i, visits := range series {
		height := 3
		if maxVisits > 0 {
			height = 3 + int((visits*12)/maxVisits)
		}
		bars[i] = sparkBarView{H: height, Hot: i == len(series)-1 && visits > 0}
	}
	return bars
}

// chartBucket maps a value onto the .ch-* height classes (2px floor, 120px
// max, 4px steps) defined in admin.css.
func chartBucket(visits, maxVisits int64) int {
	if visits <= 0 {
		return 2
	}
	height := int((visits*120 + maxVisits - 1) / maxVisits)
	height = (height + 3) / 4 * 4
	if height < 4 {
		height = 4
	}
	if height > 120 {
		height = 120
	}
	return height
}

func shortDate(value time.Time, now time.Time) string {
	if value.IsZero() {
		return "—"
	}
	if value.Year() == now.Year() {
		return value.Format("Jan 2")
	}
	return value.Format("Jan 2006")
}

func shortDateTime(value time.Time, now time.Time) string {
	if value.IsZero() {
		return "—"
	}
	if value.Year() == now.Year() {
		return value.Format("Jan 2 · 15:04 UTC")
	}
	return value.Format("Jan 2 2006 · 15:04 UTC")
}

func formatCount(value int64) string {
	text := fmt.Sprintf("%d", value)
	if value < 1000 {
		return text
	}
	var b strings.Builder
	lead := len(text) % 3
	if lead == 0 {
		lead = 3
	}
	b.WriteString(text[:lead])
	for i := lead; i < len(text); i += 3 {
		b.WriteString(",")
		b.WriteString(text[i : i+3])
	}
	return b.String()
}
