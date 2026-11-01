package datasets

import "github.com/YeandAmen/identityshield/internal/domain"

func Catalog() []domain.CatalogEntry {
	return []domain.CatalogEntry{
		{ID: "otrf", Name: "OTRF Security Datasets", Category: "Windows / AD", Description: "Documented adversary simulations with portable host events and selected network captures.", Format: "windows-jsonl", License: "MIT (current project LICENSE)", SourceURL: "https://github.com/OTRF/Security-Datasets", Access: "Open download", CanFetch: true, DownloadURL: "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip", Notes: "The quick import downloads the documented Covenant DCSync host capture. Scenario-level annotations are preserved as context; individual events remain unknown until reviewed."},
		{ID: "evtx", Name: "EVTX Attack Samples", Category: "Windows / DFIR", Description: "Native Windows and Sysmon event samples mapped to ATT&CK techniques.", Format: "windows-jsonl", License: "GPL-3.0 (project)", SourceURL: "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES", Access: "Open download", Notes: "Export EVTX with lab/windows/Export-Events.ps1, then import the JSONL. Native EVTX binaries are not accepted by the HTTP importer. Technique labels do not imply every event is malicious."},
		{ID: "lanl", Name: "LANL Enterprise Events", Category: "Authentication", Description: "58 days of de-identified authentication, process, DNS, and network events from an enterprise environment.", Format: "lanl-auth", License: "CC0", SourceURL: "https://csr.lanl.gov/data/cyber1/", Access: "Publisher request form", Notes: "Import a bounded authentication CSV/CSV.GZ slice and optionally redteam.txt. Known compromise labels are sparse; other records remain unknown. Time is relative, and failed-logon collection is filtered."},
		{ID: "bots", Name: "Splunk Boss of the SOC v3", Category: "Multi-source / SOC", Description: "Realistic investigation scenarios across Windows, network, and cloud telemetry.", Format: "windows-jsonl", License: "CC0 (project)", SourceURL: "https://github.com/splunk/botsv3", Access: "Open download", Notes: "The 320.1 MB release is pre-indexed Splunk data. Export compatible Windows events or canonical event JSONL from Splunk before importing; this app does not ingest Splunk index binaries."},
		{ID: "hai", Name: "HAI Industrial Security", Category: "ICS / time series", Description: "Hardware-in-the-loop industrial telemetry with normal and attack-labelled periods.", Format: "hai-csv", License: "README: CC BY-SA 4.0; metadata differs", SourceURL: "https://github.com/icsdataset/hai", Access: "GitHub / publisher Kaggle", KaggleSlug: "icsdataset/hai-security-dataset", Notes: "The repository license section says CC BY-SA 4.0 while its metadata table says CC BY 4.0. Record the release and clarify publisher terms when redistributing. Train a separate feature-compatible ICS model; never join its timeline to LANL."},
		{ID: "swat", Name: "SWaT & WADI", Category: "ICS / water systems", Description: "Water-treatment and distribution testbed sensor, actuator, and selected network releases.", Format: "hai-csv", License: "iTrust research terms; no redistribution", SourceURL: "https://www.sutd.edu.sg/itrust/itrust-labs/datasets/", Access: "Free by publisher request", Notes: "Use the original publisher request. Dataset sharing is prohibited by the published terms. The generic timestamp + numeric tags + attack-label CSV adapter accepts a normalized export; inspect each release's schema first."},
		{ID: "optc", Name: "DARPA OpTC", Category: "Endpoint / provenance", Description: "Endpoint and network telemetry from a large, instrumented Windows evaluation.", Format: "canonical", License: "Public-domain release statement", SourceURL: "https://github.com/FiveDirections/OpTC-data", Access: "Open download", Notes: "Approximately 1 TB compressed. Known duplicate-object and path-format errata exist. Normalize a small relevant subset to the canonical schema; no native eCAR adapter is advertised."},
	}
}

func Entry(id string) (domain.CatalogEntry, bool) {
	for _, entry := range Catalog() {
		if entry.ID == id {
			return entry, true
		}
	}
	return domain.CatalogEntry{}, false
}
