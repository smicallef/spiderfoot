## Background

SpiderFoot’s goal is to automate OSINT collection and analysis to the greatest extent possible. Since its inception, SpiderFoot has heavily focused on automating OSINT collection and entity extraction, but the automation of common analysis tasks -- beyond some reporting and visualisations -- has been left entirely to the user. The meant that the strength of SpiderFoot's data collection capabilities has sometimes been its weakness since with so much data collected, users have often needed to export it and use other tools to weed out data of interest.

## Introducing Correlations

We started tackling this analysis gap with the launch of SpiderFoot HX in 2019 through the introduction of the "Correlations" feature. This feature was represented by some 30 "correlation rules" that ran with each scan, analyzing data and presenting results reflecting SpiderFoot's opinionated view on what may be important or interesting. Here are a few of those rules as examples:
* Hosts/IPs reported as malicious by multiple data sources
* Outlier web servers (can be an indication of shadow IT)
* Databases exposed on the Internet
* Open ports revealing software versions
* and many more.

With the release of SpiderFoot 4.0 we wanted to bring this capability from SpiderFoot HX to the community, but also re-imagine it at the same time so that the community might not simply run rules we provide, but also write their own correlation rules and contribute them back. We also hope that just as with modules, we see a long list of contributions made in the years ahead so that all may benefit.

With that said, let's get into what these rules look like and how to write one.

## Key concepts

### YAML
The rules themselves are written in YAML. Why YAML? It’s easy to read, write, allows for comments and is increasingly commonplace in many modern tools.

### Rule structure
The simplest way to think of a SpiderFoot correlation rule is like a simple database query that consists of a few sections:
1. Defining the rule itself (`id`, `version` and `meta` sections).
2. Stating what you'd like to extract from the scan results (`collections` section).
3. Grouping that data in some way (`aggregation` section; optional).
3. Performing some analysis over that data in some way (`analysis` section; optional).
4. Presenting the results (`headline` section).

### Example rule
Here's an example rule that looks at SpiderFoot scan results for data revealing open TCP ports where the banner (the data returned upon connecting to the port) reports a software version. It does so by applying some regular expressions to the content of `TCP_PORT_OPEN_BANNER` data elements, filtering out some false positives and then grouping the results by the banner itself  so that one correlation result is created per banner revealing a version:

```yaml
id: open_port_version
version: 1
meta:
  name: Open TCP port reveals version
  description: >
    A possible software version has been revealed on an open port. Such
    information may reveal the use of old/unpatched software used by
    the target.
  risk: INFO
collections:
  - collect:
      - method: exact
        field: type
        value: TCP_PORT_OPEN_BANNER
      - method: regex
        field: data
        value: .*[0-9]\.[0-9].*
      - method: regex
        field: data
        value: not .*Mime-Version.*
      - method: regex
        field: data
        value: not .*HTTP/1.*
aggregation:
  field: data
headline: "Software version revealed on open port: {data}"
```

### The outcome
To show this in practice, we can run a simple scan against a target, in this case focusing on performing a port scan:

```
-> # python3.9 ./sf.py -s www.binarypool.com -m sfp_dnsresolve,sfp_portscan_tcp            
2022-04-06 08:14:58,476 [INFO] sflib : Scan [94EB5F0B] for 'www.binarypool.com' initiated.
...
sfp_portscan_tcp    Open TCP Port Banner    SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10
...
2022-04-06 08:15:23,110 [INFO] correlation : New correlation [open_port_version]: Software version revealed on open port: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10
2022-04-06 08:15:23,244 [INFO] sflib : Scan [94EB5F0B] completed.
```
We can see above that a port was found to be open by the `sfp_portscan_tcp` module, and it happens to include a version. The correlation rule `open_port_version` picked this up and reported it. This is also visible in the web interface:

<img src="https://www.spiderfoot.net/wp-content/uploads/2022/04/sf4correlations.png" />

**NOTE:** Rules will only succeed if relevant data exists in your scan results in the first place. In other words, correlation rules analyze scan data, they don't collect data from targets.

### How it works
In short, SpiderFoot translates the YAML rules into a combination queries against the backend database of scan results and Python logic to filter and group the results, creating "correlation results" in the SpiderFoot database. These results can be viewed in the SpiderFot web interface or from the SpiderFoot CLI. You can also query them directly out of the SQLite database if you like (they are in the `tbl_scan_correlation_results` table, and the `tbl_scan_correlation_results_events` table maps the events (data elements) to the correlation result).

### The rules

Each rule exists as a YAML file within the `/correlations` folder in the SpiderFoot installation path. Here you can see a list of rules in 4.0, which we hope to grow over time:

```sh
cert_expired.yaml                    host_only_from_certificatetransparency.yaml  outlier_ipaddress.yaml
cloud_bucket_open.yaml               http_errors.yaml                             outlier_registrar.yaml
cloud_bucket_open_related.yaml       human_name_in_whois.yaml                     outlier_webserver.yaml
data_from_base64.yaml                internal_host.yaml                           remote_desktop_exposed.yaml
data_from_docmeta.yaml               multiple_malicious.yaml                      root_path_needs_auth.yaml
database_exposed.yaml                multiple_malicious_affiliate.yaml            stale_host.yaml
dev_or_test_system.yaml              multiple_malicious_cohost.yaml               strong_affiliate_certs.yaml
dns_zone_transfer_possible.yaml      name_only_from_pasteleak_site.yaml           strong_similardomain_crossref.yaml
egress_ip_from_wikipedia.yaml        open_port_version.yaml                       template.yaml
email_in_multiple_breaches.yaml      outlier_cloud.yaml                           vulnerability_critical.yaml
email_in_whois.yaml                  outlier_country.yaml                         vulnerability_high.yaml
email_only_from_pasteleak_site.yaml  outlier_email.yaml                           vulnerability_mediumlow.yaml
host_only_from_bruteforce.yaml       outlier_hostname.yaml
```
### Rule components

The rules themselves are broken down into the following components:

**Meta**: Describes the rule itself so that humans understand what the rule does and the risk level of any results. This information is used mostly in the web interface and CLI.

**Collections**: A collection represents a set of data pulled from scan results, to be used in later aggregation and analysis stages. Each rule can have multiple collections.

**Aggregations**: An aggregation buckets the collected data into groups for analysis in distinct groups of data elements.

**Analysis**: Analysis performs (you guessed it) analysis on the data to whittle down the data elements to what ultimately gets reported. For example, the analysis stage may look only for cases where the data field is repeated in the data set, indicating it was found multiple times and therefore discarding any only appearing once.

**Headline**: The headline represents the actual correlation title that summarizes what was found. You can think of this as equivalent to a meal name (beef stew), and all the data elements as being the ingredients (beef, tomatoes, onions, etc.).

### Creating a rule

To create your own rule, simply copy the `template.yaml` file in the `correlations` folder to a meaningful name that matches the ID you intend to provide it, e.g. `aws_cloud_usage.yaml` and edit the rule to fit your needs. Save it and re-start SpiderFoot for the rule to be loaded. If there are any syntax errors, SpiderFoot will abort at startup and (hopefully) give you enough information to know where the error is.

The `template.yaml` file is also a good next point of reference to better understand the structure of the rules and how to use them. We also recommend taking a look through the actual rules themselves to see the concepts in practice.

## Rule Reference

**id**: The internal ID for this rule, which needs to match the filename.

**version**: The rule syntax version. This must be `1` for now.

**meta**: This section contains a few important fields used to describe the rule.

  * **name**: A short, human readable name for the rule.
  * **description**: A longer (can be multi-paragraph) description of the rule.
  * **risk**: The risk level represented by this rule's findings. Can be `INFO`, `LOW`, `MEDIUM`, `HIGH`.

**collection**: A correlation rule contains one or more `collect` blocks. Each `collect` block contains one or more `method` blocks telling SpiderFoot what criteria to use for extracting data from the database and how to filter it down. 
  * **collect**: Technically, the first `method` block in each `collect` block is what actually pulls data from the database, and each subsequent `method` refines that dataset down to what you’re seeking. You may have multiple `collect` blocks overall but the rule remains that within each `collect`, the first `method` pulls data from the database and subsequent `method` blocks within the `collect` refine that data.

    *  **method**: Each `method` block tells SpiderFoot how to collect and refine data. Each `collect` must contain at least one `method` block. Valid methods are `exact` for performing an exact match of the chosen `field` to the supplied `value`, or `regex` to perform regular expression matching.

    *  **field**: Each `method` block has a `field` upon which the matching should be performed. Valid fields are `type` (e.g. `INTERNET_NAME`), `module` (e.g. `sfp_whois`) and `data`, which would be the value of the data element (e.g. in case of an `INTERNET_NAME`, the `data` would be the hostname). After the first `method` block, you can also prefix the field with `source.`, `child.` or `entity.` to refer to the fields of the source, children or relevant entities of the collected data, respectively (see `multiple_malicious.yaml` and `data_from_docmeta.yaml` as examples of this approach).

    *  **value**: Here you supply the value or values you wish to match against the field you supplied in `field`. If your `method` was `regex`, this would be a regular expression.

**aggregation**: With all the data elements in their collections, you can now aggregate them into buckets for further analysis or immediately generate results from the rule. While the collection phase is about obtaining the data from the database and filtering down to data of interest, the aggregation phase is about grouping that data in different ways in order to support analysis and/or grouping reported results.

Aggregation simply iterates through the data elements in each collection and places them into groups based on the `field` specified. For instance if you pick the `type` field, you’ll end up with data elements with the same `type` field grouped together. The purpose of this grouping is two-fold: to support the analysis stage, or if you don’t have the analysis stage, it’s how your correlation results will be grouped for the user.
  * **field**: The `field` defines how you'd like your data elements grouped together. Just like the `field` option in `method` blocks above, you may prefix the field with `source.`, `child.` or `entity.` to apply the aggregation on those fields of the data element instead. For example, if you intended to look for multiple occurrences of a hostname, you would specify `data` here as that field, since you want to count the number of times the value of the `data` field appears.

**analysis**
The analysis section applies (you guessed it) some analysis to the aggregated results or collections directly if you didn’t perform any aggregation, and drops candidate results if they fail this stage. Various analysis `method` types exist, and each takes different options, described below.

  * **method**:
      * **threshold**: Drop any collection/aggregation of data elements that do not meet the defined thresholds. You would use this analysis rule when wanting to generate a result only when a data element has appeared more or less than a limit specified, for instance reporting when an email address is reported just once, or more than 100 times.
        * **field**: The field you want to apply the threshold too. As per above, you can use `child.`, `source.` and `entity.` field prefixes here too.
        * **count_unique_only**: By default the threshold is applied to the `field` specified on all data elements, but by setting `count_unique_only` to `true`, you can limit the threshold to only unique values in the `field` specified, so as not to also count duplicates.
        * **minimum**: The minimum number of data elements that must appear within the collection or aggregation.
        * **maximum**: The maximum number of data elements that must appear within the collection or aggregation.
      * **outlier**: Only keep outliers within any collection/aggregation of data elements.
        * **maximum_percent**: The maximum percentage of the overall results that an aggregation can represent. This method requires that you have performed an aggregation on a certain field in order to function. For example, if you aggregate on the `data` field of your collections, and one of those buckets contains less than 10% of the overall volume, it will be reported as an outlier.
        * **noisy_percent**: By default this is `10`, meaning that if the average percentage every bucket is below 10%, don't report outliers since the dataset is anomalous.
      * **first_collection_only**: Only keep data elements that appeared in the first collection but not any others. For example, this is handy for finding cases where data was found from one or several data sources but not others.
        * **field**: The field you want to use for looking up between collections.
      * **match_all_to_first_collection**: Only keep data elements that have matched in some way to the first collection. This requires an aggregation to have been performed, as the field used for aggregation is what will be used for checking for a match.
        * **match_method**: How to match between all collections and the first collection. Options are `contains` (simple wildcard match), `exact` and `subnet` which reports a match if the expected field may contain an IP address that is within the first collection field containing a subnet.

**headline**
After all data elements have been collected, filtered down, aggregated and analyzed, if data elements are remaining, these are what we call "correlation results" -> the results of your correlation rule. These need a "headline" to summarize the findings, which you can define here. To place any value from your data into the headline, you must enclose the field in `{}`, e.g. `{entity.data}`. There are two ways to write a `headline` rule. The typical way is to simply have `headline: titletexthere`, or have it as a block, in which case you can be more granular about how the correlation results are published:

* **text**: The headline text, as described above.
* **publish_collections**: The collection you wish to have associated with the correlation result. This is not often needed, but more in combination with the `match_all_to_first_collection` analysis rule in case your first collection is only used as a reference point and not actually contain any data elements you wish to publish with this correlation result. Take a look at the `egress_ip_from_wikipedia.yaml` rule for an example of this used in practice.

### A note about `child.`, `source.` and `entity.` field prefixes

Every data element pulled in the first `match` rule in a collection will also have any children (data resulting from that data element), the source (the data element that this data element was generated from) and entity (the source, or source of source, etc. that was an entity like IP address, domain, etc.). This enables you to prefix subsequent (and only subsequent!) match block field names with `child.`, `source.` and `entity.` if you wish to match based on those fields. These prefixes, as shown above, can also be used in the `aggregation`, `analysis` and `headline` sections too.

It is vital to note that these prefixes **always** are in reference to the first `match` block within each `collect` block, since every subsequent `match` block is always a refinement of the first `match` block.

This can be complicated, so let's use an example to illustrate. Let's say your scan has found a hostname (a data element type of `INTERNET_NAME`) of `foo`, and it found that within some webpage content (a data element type of `TARGET_WEB_CONTENT`) of "This is some web content: foo", which was from a URL (data element type of `LINKED_URL_INTERNAL`) of "https://bar/page.html", which was from another host named `bar`. Here's the data discovery path:

`bar` [`INTERNET_NAME`] -> `https://bar/page.html` [`LINKED_URL_INTERNAL`] -> `This is some web content: foo` [`TARGET_WEB_CONTENT`] -> `foo` [`INTERNET_NAME`]

If we were to look at `This is some web content: foo` in our rule, here are the `data` and `type` fields you would expect to exist (`module` would also exist but has been left out of this example for brevity):
* `data`: `This is some web content: foo`
* `type`: `TARGET_WEB_CONTENT`
* `source.data`: `https://bar/page.html`
* `source.type`: `LINKED_URL_INTERNAL`
* `child.data`: `foo`
* `child.type`: `INTERNET_NAME`
* `entity.type`: `INTERNET_NAME`
* `entity.data`: `bar`

Notice how the `entity.type` and `entity.data` fields for "This is some web content: foo" is **not** the `LINKED_URL_INTERNAL` data element, but actually the `bar` `INTERNET_NAME` data element. This is because an `INTERNET_NAME` is an entity, but a `LINKED_URL_INTERNAL` is not.

You can look in `spiderfoot/db.py` to see which data types are entities and which are not.
