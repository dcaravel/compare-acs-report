Compares two ACS vuln reports

Usage:

```
go run . <report1> <report2>
```

Sample output:

```
$ go run . AFTER.csv AFTER2.csv 

                                                      AFTER.csv   AFTER2.csv   diff
                                                      ---         ---          ---
Unique Clusters                                       10          10           0
Unique Namespaces                                     185         185          0
Unique Deployments                                    2,179       2,177        -2
Unique Images                                         1,289       1,304        15
Unique Components                                     987         989          2
Unique CVEs                                           2,081       2,076        -5
Unique Fixables                                       2           2            0
Unique CVEFixedIns                                    1,359       1,359        0
Unique Severities                                     4           4            0
Unique CVSSes                                         74          74           0
Unique DiscoverAts                                    226         225          -1
Unique References                                     2,234       2,230        -4
Unique ClusterNamespaces                              820         818          -2
Unique ClusterNamespacesDeployment                    4,710       4,713        3
Unique ClusterNamespacesDeploymentImage               6,087       6,090        3
Unique ClusterNamespacesDeploymentImageComponent      270,671     298,727      28,056
Unique ClusterNamespacesDeploymentImageComponentCVE   648,047     1,079,074    431,027
Unique NamespacesDeploymentImageComponentCVE          484,286     754,530      270,244
Unique DeploymentImageComponentCVE                    384,563     653,915      269,352
Unique ImageComponentCVE                              172,239     201,013      28,774
Unique ImageComponent                                 63,897      66,289       2,392
Unique ComponentCVE                                   5,069       5,068        -1
Unique DeploymentImage                                3,560       3,572        12
Total Lines                                           648,991     1,080,028    431,037


$ ls -1 *.csv
AFTER.csv.all-img-comp-cve.csv
AFTER.csv.counts-comp-cve-bycount.csv
AFTER.csv.counts-comp-cve-byname.csv
AFTER.csv.same-imgs-uniq-comps.csv
AFTER.csv.uniq.csv
AFTER2.csv.all-img-comp-cve.csv
AFTER2.csv.counts-comp-cve-bycount.csv
AFTER2.csv.counts-comp-cve-byname.csv
AFTER2.csv.same-imgs-uniq-comps.csv
AFTER2.csv.uniq.csv

```