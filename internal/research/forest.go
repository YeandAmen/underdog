package research

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/YeandAmen/underdog/internal/domain"
)

type Sample struct {
	Features []float64
	Label    string
	Group    string
	Time     time.Time
	EventIDs []string
}

type Node struct {
	Feature int     `json:"feature"`
	Split   float64 `json:"split"`
	Size    int     `json:"size"`
	Left    *Node   `json:"left,omitempty"`
	Right   *Node   `json:"right,omitempty"`
}

type Metrics struct {
	TruePositive  int      `json:"true_positive"`
	FalsePositive int      `json:"false_positive"`
	TrueNegative  int      `json:"true_negative"`
	FalseNegative int      `json:"false_negative"`
	Unknown       int      `json:"unknown"`
	Precision     *float64 `json:"precision"`
	Recall        *float64 `json:"recall"`
	F1            *float64 `json:"f1"`
	AP            *float64 `json:"average_precision"`
}

type ScoredSample struct {
	Score    float64   `json:"score"`
	Label    string    `json:"label"`
	Group    string    `json:"group"`
	Time     time.Time `json:"time"`
	EventIDs []string  `json:"event_ids"`
}

type Model struct {
	ID               string         `json:"id"`
	Algorithm        string         `json:"algorithm"`
	Domain           string         `json:"domain"`
	DatasetID        string         `json:"dataset_id"`
	FeatureNames     []string       `json:"feature_names"`
	Schema           string         `json:"schema,omitempty"`
	TrainedAt        time.Time      `json:"trained_at"`
	Seed             uint64         `json:"seed"`
	Threshold        float64        `json:"threshold"`
	SubsampleSize    int            `json:"subsample_size"`
	TreeCount        int            `json:"tree_count"`
	Trees            []*Node        `json:"trees,omitempty"`
	TrainingWindows  int            `json:"training_windows"`
	ValidationCount  int            `json:"validation_windows"`
	TestCount        int            `json:"test_windows"`
	TrainingGroups   []string       `json:"training_groups"`
	ValidationGroups []string       `json:"validation_groups"`
	TestGroups       []string       `json:"test_groups"`
	DataHash         string         `json:"data_hash"`
	Metrics          Metrics        `json:"metrics"`
	BaselineMetrics  Metrics        `json:"baseline_metrics"`
	TestScores       []ScoredSample `json:"test_scores"`
	Notes            []string       `json:"notes"`
	DurationMS       int64          `json:"duration_ms"`
}

func averagePathLength(n int) float64 {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}
	harmonic := 0.0
	for i := 1; i < n; i++ {
		harmonic += 1 / float64(i)
	}
	return 2*harmonic - 2*float64(n-1)/float64(n)
}

func tree(rows [][]float64, depth, maxDepth int, rng *rand.Rand) *Node {
	node := &Node{Size: len(rows), Feature: -1}
	if len(rows) <= 1 || depth >= maxDepth {
		return node
	}
	dimensions := len(rows[0])
	available := []int{}
	mins, maxs := make([]float64, dimensions), make([]float64, dimensions)
	for dim := 0; dim < dimensions; dim++ {
		mins[dim], maxs[dim] = rows[0][dim], rows[0][dim]
		for _, row := range rows[1:] {
			mins[dim] = math.Min(mins[dim], row[dim])
			maxs[dim] = math.Max(maxs[dim], row[dim])
		}
		if maxs[dim] > mins[dim] {
			available = append(available, dim)
		}
	}
	if len(available) == 0 {
		return node
	}
	node.Feature = available[rng.IntN(len(available))]
	node.Split = mins[node.Feature] + rng.Float64()*(maxs[node.Feature]-mins[node.Feature])
	left, right := [][]float64{}, [][]float64{}
	for _, row := range rows {
		if row[node.Feature] < node.Split {
			left = append(left, row)
		} else {
			right = append(right, row)
		}
	}
	if len(left) == 0 || len(right) == 0 {
		node.Feature = -1
		return node
	}
	node.Left, node.Right = tree(left, depth+1, maxDepth, rng), tree(right, depth+1, maxDepth, rng)
	return node
}

func pathLength(node *Node, features []float64, depth int) float64 {
	if node == nil {
		return float64(depth)
	}
	if node.Feature < 0 || node.Left == nil || node.Right == nil {
		return float64(depth) + averagePathLength(node.Size)
	}
	if features[node.Feature] < node.Split {
		return pathLength(node.Left, features, depth+1)
	}
	return pathLength(node.Right, features, depth+1)
}

func (m *Model) Score(features []float64) float64 {
	if len(m.Trees) == 0 || len(features) != len(m.FeatureNames) || m.SubsampleSize <= 1 {
		return 0
	}
	for _, value := range features {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return 0
		}
	}
	length := 0.0
	for _, t := range m.Trees {
		length += pathLength(t, features, 0)
	}
	return math.Pow(2, -(length/float64(len(m.Trees)))/averagePathLength(m.SubsampleSize))
}

func BuildSamples(events []domain.Event, kind string) ([]Sample, []string, string, error) {
	if kind != "authentication" && kind != "ics" {
		return nil, nil, "", errors.New("model domain must be authentication or ics")
	}
	type aggregate struct {
		events []domain.Event
		group  string
	}
	windows, seen := map[string]*aggregate{}, map[string]bool{}
	featureNames := []string{"failed_logons", "successful_logons", "distinct_destinations", "remote_logons", "distinct_sources"}
	schema := "authentication-v1"
	if kind == "ics" {
		featureNames, schema = nil, ""
		for _, event := range events {
			if event.Kind != "ics_sample" {
				continue
			}
			if schema != "" && event.Data["schema"] != schema {
				return nil, nil, "", errors.New("multiple ICS schemas found; choose one dataset before training")
			}
			if schema == "" {
				schema = event.Data["schema"]
				for key, text := range event.Data {
					if strings.Contains(strings.ToLower(key), "attack") || strings.Contains(strings.ToLower(key), "label") || key == "event_id" || key == "relative_seconds" {
						continue
					}
					value, err := strconv.ParseFloat(text, 64)
					if err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) {
						featureNames = append(featureNames, key)
					}
				}
				sort.Strings(featureNames)
				if len(featureNames) > 128 {
					featureNames = featureNames[:128]
				}
			}
		}
		if len(featureNames) < 2 {
			return nil, nil, "", errors.New("ICS training needs at least two finite numeric tags")
		}
	}
	for _, event := range events {
		if (kind == "authentication" && event.Kind != "auth_failure" && event.Kind != "auth_success") || (kind == "ics" && event.Kind != "ics_sample") {
			continue
		}
		// This signature intentionally excludes labels, record IDs, and run IDs:
		// copied evidence must not be admitted to another split by renaming it.
		data := map[string]string{}
		for key, value := range event.Data {
			if !strings.HasPrefix(key, "label_") && key != "original_event_id" && key != "ground_truth_origin" {
				data[key] = value
			}
		}
		signature, _ := json.Marshal([]any{event.Source, event.Timestamp, event.Kind, event.Actor, event.Host, event.SourceHost, data})
		digest := sha256.Sum256(signature)
		fingerprint := fmt.Sprintf("%x", digest)
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		group := event.RunID
		if group == "" {
			group = event.Timestamp.UTC().Format("2006-01-02")
		}
		group = event.Source + "/" + group
		key := group + "|" + event.Actor + "|" + event.Timestamp.Truncate(5*time.Minute).Format(time.RFC3339)
		if windows[key] == nil {
			windows[key] = &aggregate{group: group}
		}
		windows[key].events = append(windows[key].events, event)
	}
	samples := []Sample{}
	for _, window := range windows {
		sample := Sample{Features: make([]float64, len(featureNames)), Label: "unknown", Group: window.group, Time: window.events[0].Timestamp, EventIDs: []string{}}
		allBenign, anyMalicious, valid := true, false, true
		hosts, sources := map[string]bool{}, map[string]bool{}
		for _, event := range window.events {
			sample.Time = minTime(sample.Time, event.Timestamp)
			sample.EventIDs = append(sample.EventIDs, event.ID)
			allBenign = allBenign && event.Label == "benign"
			anyMalicious = anyMalicious || event.Label == "malicious"
			if kind == "authentication" {
				if event.Kind == "auth_failure" {
					sample.Features[0]++
				} else {
					sample.Features[1]++
				}
				hosts[event.Host] = true
				if event.SourceHost != "" {
					sources[event.SourceHost] = true
				}
				logonType := strings.ToLower(event.Data["logon_type"])
				if logonType == "3" || logonType == "10" || logonType == "network" || logonType == "remoteinteractive" {
					sample.Features[3]++
				}
			} else {
				for i, key := range featureNames {
					value, err := strconv.ParseFloat(event.Data[key], 64)
					if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
						valid = false
						break
					}
					sample.Features[i] += value / float64(len(window.events))
				}
			}
		}
		if !valid {
			continue
		}
		if kind == "authentication" {
			sample.Features[2], sample.Features[4] = float64(len(hosts)), float64(len(sources))
		}
		if anyMalicious {
			sample.Label = "malicious"
		} else if allBenign {
			sample.Label = "benign"
		}
		sort.Strings(sample.EventIDs)
		samples = append(samples, sample)
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Time.Equal(samples[j].Time) {
			if samples[i].Group != samples[j].Group {
				return samples[i].Group < samples[j].Group
			}
			return strings.Join(samples[i].EventIDs, "|") < strings.Join(samples[j].EventIDs, "|")
		}
		return samples[i].Time.Before(samples[j].Time)
	})
	return samples, featureNames, schema, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Split groups entire scenario runs (or collection days) in time order. No
// event-level random split and no overlapping sliding windows are used.
func Split(samples []Sample) (train, validation, test []Sample, groupSets [3][]string, err error) {
	firstSeen := map[string]time.Time{}
	for _, sample := range samples {
		if old, exists := firstSeen[sample.Group]; !exists || sample.Time.Before(old) {
			firstSeen[sample.Group] = sample.Time
		}
	}
	groups := make([]string, 0, len(firstSeen))
	for group := range firstSeen {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if firstSeen[groups[i]].Equal(firstSeen[groups[j]]) {
			return groups[i] < groups[j]
		}
		return firstSeen[groups[i]].Before(firstSeen[groups[j]])
	})
	if len(groups) < 10 {
		return nil, nil, nil, groupSets, errors.New("training needs at least 10 independent scenario/day groups; import more grouped, reviewed evidence")
	}
	trainEnd, valEnd := len(groups)*60/100, len(groups)*80/100
	groupSets[0], groupSets[1], groupSets[2] = groups[:trainEnd], groups[trainEnd:valEnd], groups[valEnd:]
	assigned := map[string]int{}
	for split, list := range groupSets {
		for _, group := range list {
			assigned[group] = split
		}
	}
	for _, sample := range samples {
		switch assigned[sample.Group] {
		case 0:
			train = append(train, sample)
		case 1:
			validation = append(validation, sample)
		default:
			test = append(test, sample)
		}
	}
	// A run that overlaps a later run can cross a nominal calendar boundary.
	// Reject that collection instead of presenting it as a temporal holdout.
	if len(train) > 0 && len(validation) > 0 && len(test) > 0 {
		maxTrain, minVal, maxVal, minTest := train[0].Time, validation[0].Time, validation[0].Time, test[0].Time
		for _, s := range train {
			if s.Time.After(maxTrain) {
				maxTrain = s.Time
			}
		}
		for _, s := range validation {
			minVal = minTime(minVal, s.Time)
			if s.Time.After(maxVal) {
				maxVal = s.Time
			}
		}
		for _, s := range test {
			minTest = minTime(minTest, s.Time)
		}
		if maxTrain.After(minVal) || maxVal.After(minTest) {
			return nil, nil, nil, groupSets, errors.New("scenario groups overlap across chronological boundaries; use non-overlapping runs or collection-day groups")
		}
	}
	return train, validation, test, groupSets, nil
}

func Train(events []domain.Event, kind, datasetID string) (*Model, error) {
	started := time.Now()
	selected := []domain.Event{}
	for _, event := range events {
		matchesSource := strings.HasPrefix(datasetID, "source:") && event.Source == strings.TrimPrefix(datasetID, "source:")
		if datasetID == "" || event.DatasetID == datasetID || matchesSource {
			selected = append(selected, event)
		}
	}
	samples, names, schema, err := BuildSamples(selected, kind)
	if err != nil {
		return nil, err
	}
	train, validation, test, groups, err := Split(samples)
	if err != nil {
		return nil, err
	}
	rows := [][]float64{}
	for _, sample := range train {
		if sample.Label == "benign" {
			rows = append(rows, sample.Features)
		}
	}
	if len(rows) < 12 {
		return nil, errors.New("at least 12 reviewed benign training windows are required; unknown records are never assumed normal")
	}
	model := &Model{
		ID: "iforest-" + kind, Algorithm: "Isolation Forest", Domain: kind, DatasetID: datasetID,
		FeatureNames: names, Schema: schema, TrainedAt: time.Now().UTC(), Seed: 42,
		TreeCount: 96, SubsampleSize: min(128, len(rows)), TrainingWindows: len(rows),
		ValidationCount: len(validation), TestCount: len(test), TrainingGroups: groups[0],
		ValidationGroups: groups[1], TestGroups: groups[2], TestScores: []ScoredSample{},
		Notes: []string{"Chronological 60/20/20 split by entire run or collection day.", "Only reviewed benign windows fit the forest. Unknown labels are excluded from supervised metrics.", "Threshold is the 95th percentile of benign validation scores; test labels never choose it.", "Transparent comparison: max absolute z-score fitted on the same benign training windows, threshold 3.", "Scores are anomaly rankings, not calibrated probabilities. Synthetic results do not establish production performance."},
	}
	rng := rand.New(rand.NewPCG(model.Seed, 2026))
	maxDepth := int(math.Ceil(math.Log2(float64(model.SubsampleSize))))
	for range model.TreeCount {
		indices := rng.Perm(len(rows))
		subsample := make([][]float64, model.SubsampleSize)
		for i := range subsample {
			subsample[i] = rows[indices[i]]
		}
		model.Trees = append(model.Trees, tree(subsample, 0, maxDepth, rng))
	}
	benignValidation := []float64{}
	for _, sample := range validation {
		if sample.Label == "benign" {
			benignValidation = append(benignValidation, model.Score(sample.Features))
		}
	}
	if len(benignValidation) < 3 {
		return nil, errors.New("validation needs at least three reviewed benign windows to set a threshold")
	}
	sort.Float64s(benignValidation)
	model.Threshold = benignValidation[int(math.Ceil(0.95*float64(len(benignValidation))))-1]
	means, deviations := make([]float64, len(names)), make([]float64, len(names))
	for _, row := range rows {
		for dim, value := range row {
			means[dim] += value / float64(len(rows))
		}
	}
	for _, row := range rows {
		for dim, value := range row {
			deviations[dim] += (value - means[dim]) * (value - means[dim]) / float64(len(rows))
		}
	}
	for dim := range deviations {
		deviations[dim] = math.Sqrt(deviations[dim])
	}
	baselineScores := []ScoredSample{}
	for _, sample := range test {
		model.TestScores = append(model.TestScores, ScoredSample{Score: model.Score(sample.Features), Label: sample.Label, Group: sample.Group, Time: sample.Time, EventIDs: sample.EventIDs})
		baseline := 0.0
		for dim, value := range sample.Features {
			if deviations[dim] > 0 {
				baseline = math.Max(baseline, math.Abs(value-means[dim])/deviations[dim])
			} else if value != means[dim] {
				baseline = 100
			}
		}
		baselineScores = append(baselineScores, ScoredSample{Score: baseline, Label: sample.Label})
	}
	model.Metrics = Evaluate(model.TestScores, model.Threshold)
	model.BaselineMetrics = Evaluate(baselineScores, 3)
	if model.Metrics.Recall == nil {
		model.Notes = append(model.Notes, "The test split has no labelled attack windows; recall and average precision are unavailable.")
	}
	sampleData, _ := json.Marshal(samples)
	hash := sha256.Sum256(sampleData)
	model.DataHash = fmt.Sprintf("%x", hash)
	model.DurationMS = time.Since(started).Milliseconds()
	return model, nil
}

func ratio(n, d int) *float64 {
	if d == 0 {
		return nil
	}
	value := float64(n) / float64(d)
	return &value
}

func Evaluate(scores []ScoredSample, threshold float64) Metrics {
	metrics := Metrics{}
	labeled := []ScoredSample{}
	positives := 0
	for _, item := range scores {
		if item.Label != "benign" && item.Label != "malicious" {
			metrics.Unknown++
			continue
		}
		labeled = append(labeled, item)
		positive := item.Label == "malicious"
		if positive {
			positives++
		}
		predicted := item.Score > threshold
		switch {
		case predicted && positive:
			metrics.TruePositive++
		case predicted && !positive:
			metrics.FalsePositive++
		case !predicted && positive:
			metrics.FalseNegative++
		default:
			metrics.TrueNegative++
		}
	}
	metrics.Precision = ratio(metrics.TruePositive, metrics.TruePositive+metrics.FalsePositive)
	metrics.Recall = ratio(metrics.TruePositive, metrics.TruePositive+metrics.FalseNegative)
	metrics.F1 = ratio(2*metrics.TruePositive, 2*metrics.TruePositive+metrics.FalsePositive+metrics.FalseNegative)
	if positives > 0 {
		sort.Slice(labeled, func(i, j int) bool { return labeled[i].Score > labeled[j].Score })
		tp, seen, averagePrecision := 0, 0, 0.0
		for i := 0; i < len(labeled); {
			j, newPositives := i, 0
			for j < len(labeled) && labeled[j].Score == labeled[i].Score {
				if labeled[j].Label == "malicious" {
					newPositives++
				}
				j++
			}
			tp, seen = tp+newPositives, seen+(j-i)
			averagePrecision += float64(newPositives) / float64(positives) * float64(tp) / float64(seen)
			i = j
		}
		metrics.AP = &averagePrecision
	}
	return metrics
}
