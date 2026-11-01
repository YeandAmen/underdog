package datasets

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/YeandAmen/identityshield/internal/domain"
)

const MaxPayloadBytes = 64 << 20

type Options struct {
	Format         string
	Source         string
	MaxEvents      int
	VerifiedNormal bool
	RedTeam        []byte
}

type Result struct {
	Events  []domain.Event
	SHA256  string
	Skipped int
	Notes   []string
}

func Parse(payload []byte, opts Options) (Result, error) {
	result := Result{Events: []domain.Event{}, Notes: []string{}}
	if len(payload) > MaxPayloadBytes {
		return result, fmt.Errorf("upload exceeds the 64 MiB payload limit; import a bounded slice")
	}
	hash := sha256.Sum256(payload)
	result.SHA256 = fmt.Sprintf("%x", hash)
	if opts.Source == "" {
		opts.Source = "user-import"
	}
	if opts.MaxEvents <= 0 || opts.MaxEvents > 200000 {
		opts.MaxEvents = 20000
	}
	data, err := unpack(payload, opts.Format)
	if err != nil {
		return result, err
	}
	switch opts.Format {
	case "canonical", "windows-jsonl":
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) == 0 {
			return result, errors.New("the file is empty")
		}
		if trimmed[0] == '[' {
			var rows []json.RawMessage
			if err := decoder.Decode(&rows); err != nil {
				return result, fmt.Errorf("invalid JSON array: %w", err)
			}
			for _, raw := range rows {
				if len(result.Events) >= opts.MaxEvents {
					break
				}
				appendJSON(&result, raw, opts)
			}
		} else {
			for len(result.Events) < opts.MaxEvents {
				var raw json.RawMessage
				if err := decoder.Decode(&raw); err == io.EOF {
					break
				} else if err != nil {
					return result, fmt.Errorf("invalid JSON record after %d events: %w", len(result.Events), err)
				}
				appendJSON(&result, raw, opts)
			}
		}
	case "lanl-auth":
		err = parseLANL(data, opts, &result)
	case "hai-csv":
		err = parseICS(data, opts, &result)
	default:
		return result, fmt.Errorf("unsupported format %q; use canonical, windows-jsonl, lanl-auth, or hai-csv", opts.Format)
	}
	if err != nil {
		return result, err
	}
	if len(result.Events) == 0 {
		return result, fmt.Errorf("no valid events found (%d rejected records); check the selected adapter and timestamp fields", result.Skipped)
	}
	if len(result.Events) == opts.MaxEvents {
		result.Notes = append(result.Notes, fmt.Sprintf("Stopped at the configured %d-event limit. The source checksum covers the full uploaded payload.", opts.MaxEvents))
	}
	if result.Skipped > 0 {
		result.Notes = append(result.Notes, fmt.Sprintf("%d records rejected for missing/invalid timestamps, labels, or schema fields.", result.Skipped))
	}
	sort.SliceStable(result.Events, func(i, j int) bool { return result.Events[i].Timestamp.Before(result.Events[j].Timestamp) })
	return result, nil
}

func unpack(data []byte, format string) ([]byte, error) {
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return readBounded(reader)
	}
	if len(data) >= 4 && string(data[:4]) == "PK\x03\x04" {
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, file := range archive.File {
			ext := strings.ToLower(filepath.Ext(file.Name))
			compatible := (format == "canonical" || format == "windows-jsonl") && (ext == ".json" || ext == ".jsonl" || ext == ".ndjson")
			compatible = compatible || ((format == "hai-csv" || format == "lanl-auth") && (ext == ".csv" || ext == ".txt"))
			if !compatible || file.FileInfo().IsDir() {
				continue
			}
			if file.UncompressedSize64 > MaxPayloadBytes {
				return nil, errors.New("archive member exceeds the 64 MiB expanded payload limit")
			}
			reader, err := file.Open()
			if err != nil {
				return nil, err
			}
			body, readErr := readBounded(reader)
			reader.Close()
			return body, readErr
		}
		return nil, errors.New("no compatible JSONL/CSV member found in the archive; select the correct adapter")
	}
	return data, nil
}

func readBounded(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxPayloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxPayloadBytes {
		return nil, errors.New("expanded payload exceeds 64 MiB")
	}
	return data, nil
}

func appendJSON(result *Result, raw []byte, opts Options) {
	var event domain.Event
	var err error
	if opts.Format == "canonical" {
		err = json.Unmarshal(raw, &event)
		if event.Kind == "" || event.Timestamp.IsZero() {
			err = errors.New("canonical events require kind and RFC3339 timestamp")
		}
		if event.Label == "" {
			event.Label = "unknown"
		}
	} else {
		event, err = windowsEvent(raw)
		if opts.VerifiedNormal {
			event.Label = "benign"
		}
	}
	if err != nil || !domain.ValidLabel(event.Label) {
		result.Skipped++
		return
	}
	finalize(&event, raw, opts.Source)
	result.Events = append(result.Events, event)
}

func finalize(event *domain.Event, raw []byte, source string) {
	if event.Data == nil {
		event.Data = map[string]string{}
	}
	if event.ID != "" {
		event.Data["original_event_id"] = event.ID
	}
	rawHash := sha256.Sum256(raw)
	event.RawSHA256 = fmt.Sprintf("%x", rawHash)
	idHash := sha256.Sum256([]byte(source + "|" + event.RawSHA256))
	event.ID = fmt.Sprintf("EVT-%x", idHash[:8])
	event.Source = source
	event.Raw = string(raw)
	event.Timestamp = event.Timestamp.UTC()
	if event.Actor == "" {
		event.Actor = "unknown"
	}
	if event.Host == "" {
		event.Host = "unknown"
	}
	if event.RunID == "" {
		event.RunID = source + "/" + event.Timestamp.Format("2006-01-02")
	}
}

func parseLANL(data []byte, opts Options, result *Result) error {
	red := map[string]bool{}
	if len(opts.RedTeam) > 0 {
		labels, err := unpack(opts.RedTeam, "lanl-auth")
		if err != nil {
			return fmt.Errorf("red-team labels: %w", err)
		}
		reader := csv.NewReader(bytes.NewReader(labels))
		reader.FieldsPerRecord = -1
		for {
			row, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil || len(row) != 4 {
				return errors.New("red-team labels must contain time,user,source computer,destination computer")
			}
			red[strings.Join(row, "|")] = true
		}
	}
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	for len(result.Events) < opts.MaxEvents {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(row) != 9 {
			result.Skipped++
			continue
		}
		seconds, err := strconv.ParseInt(row[0], 10, 64)
		if err != nil || seconds < 0 {
			result.Skipped++
			continue
		}
		kind := "auth_success"
		if strings.EqualFold(row[8], "Fail") || strings.EqualFold(row[8], "Failure") {
			kind = "auth_failure"
		} else if !strings.EqualFold(row[8], "Success") {
			result.Skipped++
			continue
		}
		label := "unknown"
		if red[strings.Join([]string{row[0], row[1], row[3], row[4]}, "|")] {
			label = "malicious"
		} else if opts.VerifiedNormal {
			label = "benign"
		}
		e := domain.Event{Timestamp: time.Unix(seconds, 0).UTC(), Kind: kind, Actor: row[1], Host: row[4], SourceHost: row[3], Label: label, RunID: fmt.Sprintf("%s/relative-day-%d", opts.Source, seconds/86400), Data: map[string]string{"destination_user": row[2], "auth_type": row[5], "logon_type": row[6], "orientation": row[7], "time_basis": "relative seconds; calendar date is undisclosed", "relative_seconds": row[0]}}
		finalize(&e, []byte(strings.Join(row, ",")), opts.Source)
		result.Events = append(result.Events, e)
	}
	result.Notes = append(result.Notes, "LANL epoch values remain relative (displayed against Unix epoch, not an asserted collection date). Unmatched compromise labels do not certify benign activity.")
	return nil
}

func parseICS(data []byte, opts Options, result *Result) error {
	reader := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
	reader.FieldsPerRecord = -1
	firstLine, _, _ := bytes.Cut(data, []byte{'\n'})
	if bytes.Count(firstLine, []byte{';'}) > bytes.Count(firstLine, []byte{','}) {
		reader.Comma = ';'
	} else if bytes.Count(firstLine, []byte{'\t'}) > bytes.Count(firstLine, []byte{','}) {
		reader.Comma = '\t'
	}
	header, err := reader.Read()
	if err != nil {
		return err
	}
	if len(header) < 2 {
		return errors.New("ICS CSV requires a timestamp column and numeric tags")
	}
	timeColumn, labelColumn := 0, -1
	for i, col := range header {
		normalized := strings.ToLower(strings.TrimSpace(col))
		if normalized == "time" || normalized == "timestamp" || normalized == "datetime" {
			timeColumn = i
		}
		if normalized == "attack" || normalized == "label" || normalized == "normal/attack" {
			labelColumn = i
		}
	}
	schemaKeys := []string{}
	for i, col := range header {
		if i != timeColumn && i != labelColumn && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(col)), "attack") {
			schemaKeys = append(schemaKeys, strings.TrimSpace(col))
		}
	}
	sort.Strings(schemaKeys)
	schemaHash := sha256.Sum256([]byte(strings.Join(schemaKeys, "|")))
	for len(result.Events) < opts.MaxEvents {
		recordStart := reader.InputOffset()
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(row) != len(header) {
			result.Skipped++
			continue
		}
		stamp, err := parseTime(row[timeColumn])
		if err != nil {
			result.Skipped++
			continue
		}
		label := "unknown"
		if opts.VerifiedNormal {
			label = "benign"
		}
		if labelColumn >= 0 {
			switch strings.ToLower(strings.TrimSpace(row[labelColumn])) {
			case "0", "0.0", "normal", "benign", "false":
				label = "benign"
			case "1", "1.0", "attack", "malicious", "true":
				label = "malicious"
			case "", "unknown":
			default:
				result.Skipped++
				continue
			}
		}
		fields := map[string]string{"schema": fmt.Sprintf("%s-numeric-%x", opts.Source, schemaHash[:4])}
		for i, col := range header {
			if i == timeColumn || i == labelColumn || strings.HasPrefix(strings.ToLower(col), "attack") {
				continue
			}
			if value, err := strconv.ParseFloat(row[i], 64); err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) {
				fields[strings.TrimSpace(col)] = row[i]
			}
		}
		if len(fields) < 2 {
			result.Skipped++
			continue
		}
		e := domain.Event{Timestamp: stamp, Kind: "ics_sample", Actor: "controller", Host: "imported-ics", Label: label, Data: fields}
		recordRaw := bytes.TrimRight(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})[recordStart:reader.InputOffset()], "\r\n")
		finalize(&e, recordRaw, opts.Source)
		result.Events = append(result.Events, e)
	}
	result.Notes = append(result.Notes, fmt.Sprintf("Detected CSV delimiter %q; original CSV record text is preserved.", reader.Comma))
	result.Notes = append(result.Notes, "ICS tag values retain their original units. Declared attack-column labels are preserved; this dataset must use a separate, schema-compatible model.")
	return nil
}

func flatten(value any, prefix string, out map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		if name, ok := v["Name"].(string); ok {
			if text, exists := v["#text"]; exists {
				out[name] = fmt.Sprint(text)
			}
			if text, exists := v["Value"]; exists {
				out[name] = fmt.Sprint(text)
			}
		}
		for key, nested := range v {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			flatten(nested, path, out)
		}
	case []any:
		for i, nested := range v {
			flatten(nested, prefix+"."+strconv.Itoa(i), out)
		}
	case nil:
	default:
		out[prefix] = fmt.Sprint(v)
	}
}

func windowsEvent(raw []byte) (domain.Event, error) {
	var record map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&record); err != nil {
		return domain.Event{}, err
	}
	fields := map[string]string{}
	flatten(record, "", fields)
	get := func(names ...string) string {
		for _, name := range names {
			for key, value := range fields {
				if strings.EqualFold(key, name) {
					return value
				}
			}
		}
		keys := make([]string, 0, len(fields))
		for key := range fields {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, name := range names {
			for _, key := range keys {
				if strings.HasSuffix(strings.ToLower(key), "."+strings.ToLower(name)) {
					return fields[key]
				}
			}
		}
		return ""
	}
	id := get("EventID", "event_id", "winlog.event_id", "System.EventID.Value", "System.EventID.#text")
	id = strings.TrimSpace(id)
	timestamp := get("TimeCreated.SystemTime", "System.TimeCreated.SystemTime", "UtcTime", "EventTime", "TimeCreated", "@timestamp", "timestamp")
	stamp, err := parseTime(timestamp)
	if err != nil {
		return domain.Event{}, fmt.Errorf("invalid Windows timestamp: %w", err)
	}
	e := domain.Event{Timestamp: stamp, Kind: "windows_event", Actor: get("SubjectUserName", "User", "user.name", "AccountName", "UserID"), Host: get("Computer", "ComputerName", "Hostname", "host.name"), SourceHost: get("IpAddress", "SourceIp", "WorkstationName", "SourceNetworkAddress", "source.ip"), Label: "unknown", Data: map[string]string{"event_id": id, "channel": get("Channel", "winlog.channel"), "command": get("CommandLine", "ProcessCommandLine", "ImagePath", "ServiceFileName"), "image": get("Image", "NewProcessName"), "logon_type": get("LogonType"), "subject_logon_id": get("SubjectLogonId"), "target_logon_id": get("TargetLogonId"), "properties": get("Properties")}}
	e.Data["target_image"], e.Data["source_image"], e.Data["call_trace"] = get("TargetImage"), get("SourceImage"), get("CallTrace")
	switch id {
	case "4624":
		e.Kind, e.Actor = "auth_success", get("TargetUserName", "User", "user.name")
	case "4625", "4771", "4776":
		e.Kind, e.Actor = "auth_failure", get("TargetUserName", "SubjectUserName", "User")
		if id == "4776" && (get("Status") == "0x0" || get("Status") == "0") {
			e.Kind = "auth_success"
		} else if id == "4776" && get("Status") == "" {
			e.Kind = "windows_event"
		}
	case "1", "4688":
		e.Kind = "process"
	case "10":
		e.Kind = "process_access"
	case "4728", "4732", "4756", "4729", "4733", "4757":
		e.Kind, e.Target = "group_change", get("MemberName", "MemberSid")
		e.Data["group"], e.Data["action"] = get("TargetUserName", "GroupName"), "add"
		if id == "4729" || id == "4733" || id == "4757" {
			e.Data["action"] = "remove"
		}
	case "4662":
		e.Kind = "directory_access"
		properties := strings.ToLower(get("Properties"))
		if strings.Contains(properties, "1131f6aa") || strings.Contains(properties, "1131f6ad") || strings.Contains(properties, "89e95b76") {
			e.Kind = "directory_replication"
			e.Data["right"] = "replicate-directory"
		}
	case "5136":
		e.Kind = "directory_change"
		if strings.EqualFold(get("AttributeLDAPDisplayName"), "ntsecuritydescriptor") {
			e.Kind = "acl_change"
			e.Data["right"] = get("NormalizedRight")
		}
	case "7045", "4697":
		e.Kind, e.Data["service"] = "service_created", get("ServiceName")
	case "4698":
		e.Kind, e.Data["task"] = "task_created", get("TaskName")
		if e.Data["command"] == "" {
			e.Data["command"] = get("TaskContent")
		}
	case "1102":
		e.Kind = "log_cleared"
	}
	if e.SourceHost == "-" || e.SourceHost == "?" {
		e.SourceHost = ""
	}
	return e, nil
}

func parseTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", "20060102 15:04:05", "2006-01-02T15:04:05.999999999", "1/2/2006 3:04:05 PM", "02/01/2006 15:04:05"} {
		if stamp, err := time.Parse(layout, value); err == nil {
			return stamp.UTC(), nil
		}
	}
	// Some Windows exports use /Date(milliseconds)/.
	if strings.HasPrefix(value, "/Date(") && strings.HasSuffix(value, ")/") {
		milliseconds, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(value, "/Date("), ")/"), 10, 64)
		if err == nil {
			return time.UnixMilli(milliseconds).UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp %q", value)
}

// SliceLANL streams a bounded number of rows from a potentially very large
// .gz file without loading the original corpus into memory.
func SliceLANL(reader io.Reader, limit int) ([]byte, error) {
	buffered := bufio.NewReader(reader)
	magic, _ := buffered.Peek(2)
	var input io.Reader = buffered
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		input = gz
	}
	var out bytes.Buffer
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	for n := 0; n < limit && scanner.Scan(); n++ {
		if out.Len()+len(scanner.Bytes())+1 > MaxPayloadBytes {
			break
		}
		out.Write(scanner.Bytes())
		out.WriteByte('\n')
	}
	return out.Bytes(), scanner.Err()
}
