package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// Disclaimer: code is a mess

// Compares two ACS vuln reports

func usage() {
	fmt.Println("Usage:")
	fmt.Printf("  %s <file1> <file2> [grep str]\n", filepath.Base(os.Args[0]))
}

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(1)
	}

	lFile := os.Args[1]
	rFile := os.Args[2]

	var grepStr string
	if len(os.Args) > 3 {
		grepStr = os.Args[3]
	}

	// fmt.Printf("lFile: %q, rFile: %q\n", lFile, rFile)

	l, err := doit(lFile, grepStr)
	if err != nil {
		panic(err)
	}

	r, err := doit(rFile, grepStr)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", "", filepath.Base(lFile), filepath.Base(rFile), "diff")
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", "", "---", "---", "---")
	row(w, "Unique Clusters", l.Clusters, r.Clusters)
	row(w, "Unique Namespaces", l.Namespaces, r.Namespaces)
	row(w, "Unique Deployments", l.Deployments, r.Deployments)
	row(w, "Unique Images", l.Images, r.Images)
	row(w, "Unique Components", l.Components, r.Components)
	row(w, "Unique CVEs", l.CVEs, r.CVEs)
	row(w, "Unique Fixables", l.Fixable, r.Fixable)
	row(w, "Unique CVEFixedIns", l.CVEFixedIn, r.CVEFixedIn)
	row(w, "Unique Severities", l.Severity, r.Severity)
	row(w, "Unique CVSSes", l.CVSS, r.CVSS)
	row(w, "Unique DiscoverAts", l.DiscoverdAt, r.DiscoverdAt)
	row(w, "Unique References", l.Reference, r.Reference)
	row(w, "Unique ClusterNamespaces", l.ClusterNamespace, r.ClusterNamespace)
	row(w, "Unique ClusterNamespacesDeployment", l.ClusterNamespaceDeployment, r.ClusterNamespaceDeployment)
	row(w, "Unique ClusterNamespacesDeploymentImage", l.ClusterNamespaceDeploymentImage, r.ClusterNamespaceDeploymentImage)
	row(w, "Unique ClusterNamespacesDeploymentImageComponent", l.ClusterNamespaceDeploymentImageComponent, r.ClusterNamespaceDeploymentImageComponent)
	row(w, "Unique ClusterNamespacesDeploymentImageComponentCVE", l.ClusterNamespaceDeploymentImageComponentCVE, r.ClusterNamespaceDeploymentImageComponentCVE)
	row(w, "Unique NamespacesDeploymentImageComponentCVE", l.NamespacesDeploymentImageComponentCVE, r.NamespacesDeploymentImageComponentCVE)
	row(w, "Unique DeploymentImageComponentCVE", l.DeploymentImageComponentCVE, r.DeploymentImageComponentCVE)
	row(w, "Unique ImageComponentCVE", l.ImageComponentCVE, r.ImageComponentCVE)
	row(w, "Unique ImageComponent", l.ImageComponent, r.ImageComponent)
	row(w, "Unique ComponentCVE", l.ComponentCVE, r.ComponentCVE)
	row(w, "Unique DeploymentImage", l.DeploymentImage, r.DeploymentImage)
	// row(w, "Unique Things", l.Thing, r.Thing)
	// fmt.Fprintf(w, "%s\t%s\t%s\n", "Total Lines", lLines, rLines)
	row(w, "Total Lines", l.Lines, r.Lines)
	w.Flush()

	dumpUniqImageComponents(lFile, rFile, l, r)
	dumpSameImageComponents(lFile, rFile, l, r)
	dumpAllImageComponentsCVE(lFile, rFile, l, r)
	dumpCountsComponentCVE(lFile, rFile, l, r)
}

// dumpUniqImageComponents creates files that contain the image+component values that differ
// in each of the reports - image+components that are in common are omitted.
func dumpUniqImageComponents(lFile, rFile string, l, r *FileStats) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	lUniqFile, err := os.Create(filepath.Join(wd, fmt.Sprintf("%s%s", filepath.Base(lFile), ".uniq.csv")))
	if err != nil {
		panic(err)
	}
	defer lUniqFile.Close()

	tmp := []string{}
	for k := range l.MapImageComponent {
		_, ok := r.MapImageComponent[k]
		if ok {
			// skip, exists in both
			continue
		}

		tmp = append(tmp, k)
	}
	sort.Strings(tmp)
	for _, k := range tmp {
		lUniqFile.WriteString(fmt.Sprintf("%s\n", k))
	}

	rUniqFile, err := os.Create(filepath.Join(wd, fmt.Sprintf("%s%s", filepath.Base(rFile), ".uniq.csv")))
	if err != nil {
		panic(err)
	}
	defer rUniqFile.Close()

	tmp = []string{}
	for k := range r.MapImageComponent {
		_, ok := l.MapImageComponent[k]
		if ok {
			// skip, exists in both
			continue
		}

		tmp = append(tmp, k)
	}

	sort.Strings(tmp)
	for _, k := range tmp {
		rUniqFile.WriteString(fmt.Sprintf("%s\n", k))
	}
}

// dumpSameImageComponents creates files that contain the image+component values that differ for
// images that are shared between the two reports
func dumpSameImageComponents(lFile, rFile string, l, r *FileStats) {
	suffix := ".same-imgs-uniq-comps.csv"
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	lUniqFile, err := os.Create(filepath.Join(wd, fmt.Sprintf("%s%s", filepath.Base(lFile), suffix)))
	if err != nil {
		panic(err)
	}
	defer lUniqFile.Close()

	rUniqFile, err := os.Create(filepath.Join(wd, fmt.Sprintf("%s%s", filepath.Base(rFile), suffix)))
	if err != nil {
		panic(err)
	}
	defer rUniqFile.Close()

	ltmp := []string{}
	rtmp := []string{}
	for image, lcomps := range l.MapImageToComponents {
		rcomps, ok := r.MapImageToComponents[image]
		if !ok {
			// skip, image doesn't exist in both
			continue
		}

		for lcomp := range lcomps {
			_, ok := rcomps[lcomp]
			if ok {
				// skip if comp exists in both
				continue
			}

			ltmp = append(ltmp, fmt.Sprintf("%s,%s", image, lcomp))
		}

		for rcomp := range rcomps {
			_, ok := lcomps[rcomp]
			if ok {
				// skip if comp exists in both
				continue
			}

			rtmp = append(rtmp, fmt.Sprintf("%s,%s", image, rcomp))
		}
	}
	sort.Strings(ltmp)
	sort.Strings(rtmp)
	for _, k := range ltmp {
		lUniqFile.WriteString(fmt.Sprintf("%s\n", k))
	}
	for _, k := range rtmp {
		rUniqFile.WriteString(fmt.Sprintf("%s\n", k))
	}
}

// dumpAllImageComponentsCVE creates files that contain all the image+component+cve fields from
// each report
func dumpAllImageComponentsCVE(lFile, rFile string, l, r *FileStats) {
	suffix := ".all-img-comp-cve.csv"
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	doit := func(ofile *os.File, fs *FileStats) {
		keys := []string{}
		for k := range fs.MapImageComponentCVE {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ofile.WriteString(fmt.Sprintf("%s\n", k))
		}
	}

	{
		lUniqFile, err := os.Create(filepath.Join(wd, fmt.Sprintf("%s%s", filepath.Base(lFile), suffix)))
		if err != nil {
			panic(err)
		}
		defer lUniqFile.Close()
		doit(lUniqFile, l)
	}

	{
		rUniqFile, err := os.Create(filepath.Join(wd, fmt.Sprintf("%s%s", filepath.Base(rFile), suffix)))
		if err != nil {
			panic(err)
		}
		defer rUniqFile.Close()
		doit(rUniqFile, r)
	}
}

// dumpCountsComponentCVE creates multiple files for each report that counts the occurrences of each
// component+cve, one file is sorted by count, the other sorted by component+cve
func dumpCountsComponentCVE(lFile, rFile string, l, r *FileStats) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	byCount := func(ofile *os.File, fs *FileStats) {
		type compcve struct {
			count int
			key   string
		}
		items := []compcve{}
		for comp, count := range fs.MapComponentCVECount {
			items = append(items, compcve{count: count, key: comp})
		}
		sort.Slice(items, func(i, j int) bool {
			return items[i].count > items[j].count

		})
		for _, k := range items {
			ofile.WriteString(fmt.Sprintf("%d,%s\n", k.count, k.key))
		}
	}
	byName := func(ofile *os.File, fs *FileStats) {
		type compcve struct {
			count int
			key   string
		}
		items := []compcve{}
		for comp, count := range fs.MapComponentCVECount {
			items = append(items, compcve{count: count, key: comp})
		}
		sort.Slice(items, func(i, j int) bool {
			return items[i].key < items[j].key

		})
		for _, k := range items {
			ofile.WriteString(fmt.Sprintf("%s,%d\n", k.key, k.count))
		}
	}

	countSuffix := ".counts-comp-cve-bycount.csv"
	nameSuffix := ".counts-comp-cve-byname.csv"
	{
		countFile, err := os.Create(filepath.Join(wd, fmt.Sprintf("%s%s", filepath.Base(lFile), countSuffix)))
		if err != nil {
			panic(err)
		}
		defer countFile.Close()
		byCount(countFile, l)

		nameFile, err := os.Create(filepath.Join(wd, fmt.Sprintf("%s%s", filepath.Base(lFile), nameSuffix)))
		if err != nil {
			panic(err)
		}
		defer nameFile.Close()
		byName(nameFile, l)
	}

	{
		countFile, err := os.Create(filepath.Join(wd, fmt.Sprintf("%s%s", filepath.Base(rFile), countSuffix)))
		if err != nil {
			panic(err)
		}
		defer countFile.Close()
		byCount(countFile, r)

		nameFile, err := os.Create(filepath.Join(wd, fmt.Sprintf("%s%s", filepath.Base(rFile), nameSuffix)))
		if err != nil {
			panic(err)
		}
		defer nameFile.Close()
		byName(nameFile, r)
	}

	// dump this again, but compare left to right and calculate the diff

}
func row(w io.Writer, heading string, left, right int) {
	prt := message.NewPrinter(language.English)
	fmt.Fprintf(w, "%s\t%v\t%v\t%v\n", heading, prt.Sprintf("%d", left), prt.Sprintf("%d", right), prt.Sprintf("%d", right-left))
}

type FileStats struct {
	Lines                                       int
	Clusters                                    int
	Namespaces                                  int
	Deployments                                 int
	Images                                      int
	Components                                  int
	CVEs                                        int
	Fixable                                     int
	CVEFixedIn                                  int
	Severity                                    int
	CVSS                                        int
	DiscoverdAt                                 int
	Reference                                   int
	ClusterNamespace                            int
	ClusterNamespaceDeployment                  int
	ClusterNamespaceDeploymentImage             int
	ClusterNamespaceDeploymentImageComponent    int
	ClusterNamespaceDeploymentImageComponentCVE int
	NamespacesDeploymentImageComponentCVE       int
	DeploymentImageComponentCVE                 int
	ImageComponentCVE                           int
	ImageComponent                              int
	DeploymentImage                             int
	ComponentCVE                                int
	MapImageComponent                           map[string]bool
	MapImageToComponents                        map[string]map[string]bool
	MapImageComponentCVE                        map[string]bool
	MapComponentCVECount                        map[string]int
}

func doit(path string, grepStr string) (*FileStats, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	recordCount := 0
	clusters := map[string]bool{}
	namespaces := map[string]bool{}
	deployments := map[string]bool{}
	images := map[string]bool{}
	components := map[string]bool{}
	cves := map[string]bool{}
	fixables := map[string]bool{}
	cveFixedIns := map[string]bool{}
	severities := map[string]bool{}
	cvsses := map[string]bool{}
	discoveredAts := map[string]bool{}
	references := map[string]bool{}
	clusterNamespaces := map[string]bool{}
	clusterNamespaceDeployments := map[string]bool{}
	clusterNamespaceDeploymentImage := map[string]bool{}
	clusterNamespaceDeploymentImageComponent := map[string]bool{}
	clusterNamespaceDeploymentImageComponentCVE := map[string]bool{}
	namespacesDeploymentImageComponentCVE := map[string]bool{}
	deploymentImageComponentCVE := map[string]bool{}
	deploymentImage := map[string]bool{}
	imageComponentCVE := map[string]bool{}
	componentCVEs := map[string]bool{}
	imageComponent := map[string]bool{}

	mapImageToComponents := map[string]map[string]bool{}

	_, _ = reader.Read() // eat the header

	stats := &FileStats{
		MapComponentCVECount: map[string]int{},
	}

	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if grepStr != "" && !strings.Contains(strings.Join(record, ","), grepStr) {
			// skip if grepstr not found
			continue
		}

		recordCount++

		cluster := record[0]
		namespace := record[1]
		deployment := record[2]
		image := record[3]
		component := record[4]
		cve := record[5]
		fixable := record[6]
		cveFixedIn := record[7]
		severity := record[8]
		cvss := record[9]
		discoveredAt := record[10]
		reference := record[11]

		clusters[cluster] = true
		namespaces[namespace] = true
		deployments[deployment] = true
		images[image] = true
		components[component] = true
		cves[cve] = true
		fixables[fixable] = true
		cveFixedIns[cveFixedIn] = true
		severities[severity] = true
		cvsses[cvss] = true
		discoveredAts[discoveredAt] = true
		references[reference] = true

		clusterNamespaces[fmt.Sprintf("%s,%s", cluster, namespace)] = true
		clusterNamespaceDeployments[fmt.Sprintf("%s,%s,%s", cluster, namespace, deployment)] = true
		clusterNamespaceDeploymentImage[fmt.Sprintf("%s,%s,%s,%s", cluster, namespace, deployment, image)] = true
		clusterNamespaceDeploymentImageComponent[fmt.Sprintf("%s,%s,%s,%s,%s", cluster, namespace, deployment, image, component)] = true
		clusterNamespaceDeploymentImageComponentCVE[fmt.Sprintf("%s,%s,%s,%s,%s,%s", cluster, namespace, deployment, image, component, cve)] = true
		namespacesDeploymentImageComponentCVE[fmt.Sprintf("%s,%s,%s,%s,%s", namespace, deployment, image, component, cve)] = true
		deploymentImageComponentCVE[fmt.Sprintf("%s,%s,%s,%s", deployment, image, component, cve)] = true
		imageComponentCVE[fmt.Sprintf("%s,%s,%s", image, component, cve)] = true
		imageComponent[fmt.Sprintf("%s,%s", image, component)] = true
		deploymentImage[fmt.Sprintf("%s,%s", deployment, image)] = true

		_, ok := mapImageToComponents[image]
		if !ok {
			mapImageToComponents[image] = map[string]bool{}
		}
		mapImageToComponents[image][component] = true

		k := fmt.Sprintf("%s,%s", component, cve)
		componentCVEs[k] = true
		stats.MapComponentCVECount[k]++
	}

	stats.Lines = recordCount
	stats.Clusters = len(clusters)
	stats.Namespaces = len(namespaces)
	stats.Deployments = len(deployments)
	stats.Images = len(images)
	stats.Components = len(components)
	stats.CVEs = len(cves)
	stats.Fixable = len(fixables)
	stats.CVEFixedIn = len(cveFixedIns)
	stats.Severity = len(severities)
	stats.CVSS = len(cvsses)
	stats.DiscoverdAt = len(discoveredAts)
	stats.Reference = len(references)
	stats.ClusterNamespace = len(clusterNamespaces)
	stats.ClusterNamespaceDeployment = len(clusterNamespaceDeployments)
	stats.ClusterNamespaceDeploymentImage = len(clusterNamespaceDeploymentImage)
	stats.ClusterNamespaceDeploymentImageComponent = len(clusterNamespaceDeploymentImageComponent)
	stats.ClusterNamespaceDeploymentImageComponentCVE = len(clusterNamespaceDeploymentImageComponentCVE)
	stats.DeploymentImageComponentCVE = len(deploymentImageComponentCVE)
	stats.NamespacesDeploymentImageComponentCVE = len(namespacesDeploymentImageComponentCVE)
	stats.DeploymentImage = len(deploymentImage)
	stats.ImageComponentCVE = len(imageComponentCVE)
	stats.ImageComponent = len(imageComponent)
	stats.ComponentCVE = len(componentCVEs)
	stats.MapImageComponent = imageComponent
	stats.MapImageToComponents = mapImageToComponents
	stats.MapImageComponentCVE = imageComponentCVE

	return stats, nil
}
