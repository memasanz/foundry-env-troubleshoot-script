## Troublshoot Foundry Connectivity Powershell


Troubleshoots connectivity for a privately deployed Microsoft Foundry (Azure AI
Foundry) account and its private dependencies (Storage, Cosmos DB, AI Search,
Key Vault). Read-only: it never changes anything in Azure.

Output is a console verdict table.


### REQUIREMENTS
---
The script checks all of these itself at startup and reports them under
"Prereq". You do not need to prepare anything in advance.

  * PowerShell 7+          Required. Parallel execution is unavailable on
                           Windows PowerShell 5.1, so the script stops with
                           install instructions rather than running slowly.
  * Azure CLI              Required. If missing, the script stops and prints
                           the winget command and download link.
  * resource-graph ext.    Installed automatically on first run if absent. If
                           the install fails the script continues on a slower
                           fallback path and says so.
  * Signed in to Azure     If you are not signed in, the script starts a
                           DEVICE CODE sign-in: it prints a URL and a code for
                           you to enter in any browser. This works over SSH,
                           in containers, and on servers with no browser -
                           which is typically where private-network
                           diagnostics get run.
  * Permissions            See the next section.


### PERFORMANCE

A full run takes roughly a minute. Three things make that possible, and they
matter if you modify the script:

  * Direct ARM REST with a cached bearer token instead of `az rest`. Every az
    invocation spawns a Python interpreter and costs ~8s; the same call over
    REST costs ~1s.
  * ForEach-Object -Parallel for ARM reads and endpoint probes. Measured 3.5x
    on ARM calls, and more when endpoints are unreachable, because TCP
    timeouts stop stacking up serially.
  * Azure Resource Graph for tenant-wide discovery: private DNS zone lookup
    and every zone-to-VNet link come back in single queries instead of one
    read per zone.

  Note: ARG indexes resources, not child record sets. Private DNS A records
  are NOT queryable through it, so those are still read directly per zone.
  If you try to "optimize" that into ARG, it will silently return nothing.


### PERMISSIONS

The script is strictly read-only. It never creates, modifies, approves, or
deletes anything, and it never reads keys, secrets, or connection strings.

Simplest answer
    The built-in "Reader" role is defined as "*/read", which covers every
    operation the script performs. Reader at the subscription scope is enough:

        az role assignment create `
            --assignee <user-or-spn> `
            --role Reader `
            --scope /subscriptions/<subscription-id>

    If the Foundry account and its dependencies live in one resource group and
    the private DNS zones live in another, grant Reader on both, or on the
    subscription.

Least privilege
    If a subscription-wide Reader is not acceptable, grant Reader at these
    scopes instead. Each maps to a phase of the report:

      Foundry account RG          Microsoft.CognitiveServices/accounts/read
                                  .../accounts/projects/read
                                  .../accounts/projects/connections/read
                                  (topology, control plane, dependency
                                   discovery - phases 1 to 3)

      Dependency resources        Microsoft.Storage/storageAccounts/read
                                  Microsoft.DocumentDB/databaseAccounts/read
                                  Microsoft.Search/searchServices/read
                                  Microsoft.KeyVault/vaults/read
                                  (dependency public-access and private
                                   endpoint state - phase 4)

      Networking RG(s)            Microsoft.Network/privateEndpoints/read
                                  Microsoft.Network/networkInterfaces/read
                                  Microsoft.Network/virtualNetworks/read
                                  Microsoft.Network/networkSecurityGroups/read
                                  Microsoft.Network/routeTables/read
                                  (private endpoint NIC IPs, subnet health,
                                   peering - phases 4 and 5)

      Private DNS zone RG         Microsoft.Network/privateDnsZones/read
                                  .../privateDnsZones/A/read
                                  .../privateDnsZones/virtualNetworkLinks/read
                                  (zone existence, A record vs NIC IP, VNet
                                   links - phase 4)

    "Private DNS Zone Contributor" also works for the DNS scope, but it grants
    write access the script does not need. Prefer Reader.

Cross-subscription note
    Private DNS zones very often live in a hub subscription owned by a
    different team. You need read access there too, or the script will
    correctly but unhelpfully report the zones as "not visible to you". Those
    findings are raised as WARN, not FAIL, precisely because missing
    permissions and a missing zone look identical from the outside - so
    confirm your access before treating a zone warning as a real gap.

What is NOT required
    * No write, contributor, or owner permission anywhere.
    * No data-plane roles (no Cognitive Services User, Storage Blob Data
      Reader, Search Index Data Reader, Key Vault Secrets User). The script
      inspects configuration only, and never calls a data-plane API.
    * No key or secret access. Project connections are listed with a plain GET;
      the script does not call any listKeys or listSecrets action.

Client-side tests
    The DNS and TCP tests in phase 6 need no Azure permission at all - they run
    from your machine. They do need network line of sight to the private
    endpoints (VNet-joined host, VPN, or ExpressRoute) to be meaningful. Use
    -SkipClientTests when running from outside the private network.


### BASIC USE

    `cd "C:\Users\samsmith\OneDrive - Microsoft\Documents\Microsoft Scout"
    .\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup <rg> -AccountName <foundry-account>`

Example:

    .\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup private-foundry -AccountName contosocb73


### PARAMETERS

  -ResourceGroup     (required) Resource group holding the Foundry account.
  -AccountName       (required) Name of the Foundry / Azure AI Services account.
  -SubscriptionId    Optional. Defaults to the current az CLI subscription.
                     Pass it explicitly if other tools may change your CLI
                     context while the script runs.
  -HubVNetId         Optional. Resource ID of your hub / centralized VNet.
                     Supplying it upgrades the "centralized VNet" DNS verdict
                     from a guess to a confirmed match, and adds a peering check.
  -SkipClientTests   Skip the from-this-machine DNS and TCP tests. Use when you
                     are deliberately running from outside the private network
                     and only want the control-plane verdict.
  -Detailed          Print full detail text without truncation.
  -ExportHtml        Write an HTML report without prompting. Use in CI or
                     scheduled runs. Filename is auto-generated in the current
                     directory unless -HtmlPath is given.
  -HtmlPath <path>   Write the HTML report to a specific path (implies
                     -ExportHtml). A .html extension is added if missing.


### HTML REPORT

At the end of an interactive run the script asks:

    Export an HTML report? [y/N]

Answer y and it offers a default filename, writes the report, and offers to
open it. Answer n (or just press Enter) and nothing is written - console output
is unchanged either way.

The report is a single self-contained .html file with no external assets, so it
can be attached to a ticket, emailed, or committed. It contains the same
findings as the console but with full detail text (nothing truncated), grouped
per service, plus a summary banner and a "Fix these first" list when anything
failed. It follows the viewer's light/dark preference.

For unattended runs the prompt is skipped automatically when stdin is
redirected, so the script never blocks in CI. Use -ExportHtml or -HtmlPath to
produce a report in that context:

    .\Test-FoundryPrivateConnectivity.ps1 -ResourceGroup rg-ai `
        -AccountName my-foundry -SkipClientTests `
        -HtmlPath .\reports\foundry-preflight.html

Full example:

    .\Test-FoundryPrivateConnectivity.ps1 `
        -ResourceGroup private-foundry `
        -AccountName contosocb73 `
        -SubscriptionId 20836408-7996-49cf-803b-d479a4041a48 `
        -HubVNetId "/subscriptions/<sub>/resourceGroups/rg-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub" `
        -Detailed


### WHAT IT CHECKS

  1. Topology         Delegated subnet injection vs Microsoft-managed network
                      vs no injection.
  2. Control plane    publicNetworkAccess, network ACLs, custom subdomain.
  3. Dependencies     Auto-discovered from project connections (Storage,
                      Cosmos DB, AI Search, Key Vault).
  4. Private endpoints  Existence, approval state, NIC private IPs, and which
                      sub-resources (groupIds) are linked.
  5. Private DNS      Zone exists, the A record matches the private endpoint
                      NIC IP, VNet links, auto-registration flags.
  6. Subnet health    Delegation to Microsoft.App/environments, /27 minimum
                      size, NSG rules, UDRs, service endpoints, hub peering,
                      VNet DNS servers.
  7. Client side      Which resolver answered, whether the name resolves to
                      the private endpoint or the public frontend, TCP 443
                      reachability, TLS certificate identity, and an
                      unauthenticated HTTP probe confirming the genuine service
                      answered (see "Client-side severity" and the proxy notes
                      below).


### CLIENT-SIDE SEVERITY

Phase 6 labels every resolution with what the client is actually talking to:

  PRIVATE           Resolved to the private endpoint. Correct.
  SPLIT-BRAIN       Both private and public answers returned. Some clients will
                    take the public path. WARN.
  PUBLIC ENDPOINT   Resolved to the public frontend, NOT the private endpoint.

Severity for PUBLIC ENDPOINT is driven by the target resource's own setting,
not by where you happen to be running:

  publicNetworkAccess Disabled  ->  FAIL
        The service refuses public traffic, so that address will reject the
        connection. From this machine the service is genuinely unreachable.

  publicNetworkAccess Enabled   ->  WARN
        Calls will probably succeed, but they are bypassing your private path
        entirely and egressing over the internet.

Running from a laptop on a public resolver against a fully locked-down
deployment therefore produces FAILs. That is accurate - the client really
cannot reach those services - and the "Vantage point" line says so explicitly
and reminds you the control-plane and DNS-zone findings remain authoritative.
Use -SkipClientTests when you only want the configuration verdict.


### READING THE RESULTS

  PASS        Healthy.
  PASS-NOTE   Works, but depends on an assumption you should confirm.
  WARN        Not broken now, but a risk or a gap worth closing.
  FAIL        Actively broken. Listed again under "Fix these first".
  INFO        Context only, no judgement.
  SKIP        Not applicable or skipped by a switch.

Exit code is 1 if there is at least one FAIL, otherwise 0. That makes it safe
to run from a pipeline or a scheduled check.

DNS VNet-link rule (two-tier, by design):
  PASS       zone is linked to the injected / delegated-subnet VNet
  PASS-NOTE  zone is linked to a hub / centralized VNet instead
  FAIL       zone is linked to neither


**IMPORTANT: WHERE YOU RUN IT FROM**

The control-plane and DNS-zone findings are authoritative from anywhere.

The client-side section only means something when run from a host that is
actually on the private network - a VM in the injected VNet, or a machine on
VPN / ExpressRoute using the corporate resolver.

Run it from a laptop on a public resolver (1.1.1.1, 8.8.8.8) against a
locked-down deployment and you will get FAILs on every endpoint. Those are
correct: the services have publicNetworkAccess Disabled, the laptop resolved
the public frontend, and that address will refuse the connection. The report
labels each one "PUBLIC ENDPOINT" and adds a "Vantage point" line making clear
this reflects where you are running from, not necessarily a broken deployment.

If you only want the configuration verdict, use -SkipClientTests.


### COMMON FINDINGS AND WHAT THEY MEAN

  "PE DNS zone group: None"
      Informational, not a fault. It means the A records are managed outside
      the private endpoint - by hand, by IaC, or by your own DNS servers -
      rather than auto-maintained. Resolution works identically either way.
      What actually matters is the A record check immediately below it. If a
      record is missing or stale AND there is no zone group, the finding will
      say so, because then the absent zone group is the reason nothing put the
      record back.

  "Service identity ... carrying apim-request-id=..."
      An unauthenticated HTTP probe reached the endpoint and the reply carried
      an Azure per-request id header. Only the genuine service emits those, so
      the request reached the service itself rather than being absorbed or
      answered by an intermediary. A 401 or 403 here is expected and correct -
      the probe deliberately sends no credentials.

      This is the check that closes the wildcard-certificate gap. A cert with
      SAN *.openai.azure.com is valid for EVERY Azure OpenAI account, so the
      TLS check alone proves only "a genuine Azure frontend answered". The
      per-request id proves the request was actually served.

      Per-service id headers used: apim-request-id (Foundry / Cognitive
      Services), x-ms-request-id (Storage), x-ms-activity-id (Cosmos DB),
      request-id (AI Search).

  "Service identity ... no Azure per-request id header"
      Something replied that is not the real service - a proxy, captive
      portal, or error page. This is the strongest single indicator that an
      intermediary is terminating the request rather than forwarding it.

      Scope limit: because the probe is unauthenticated, a 401/403 cannot be
      attributed to the private-endpoint network ACL rather than to the missing
      credential. The probe answers "who replied", not "was the policy applied".

  "PRIVATE (indirect)" / "Shared VIP detected"
      The name resolved to private address space, but not to any private
      endpoint NIC belonging to this deployment - and often several different
      service FQDNs resolve to that same one address. That is the signature of
      an ADC or proxy (NetScaler, F5) or a DNS forwarder answering on the
      service's behalf, rather than direct private endpoint resolution.

      This is NOT reported as a failure: traffic may be forwarded perfectly
      well, and many enterprises run exactly this design. What the script does
      instead is check the TLS identity, which is the only client-side evidence
      that matters through a proxy - see below.

  "TLS identity ... certificate covers <fqdn>"
      The backend that answered presented a certificate valid for the name you
      asked for, issued by a Microsoft/public CA. Through a proxy VIP this is
      the strongest client-side proof that traffic reached the genuine service,
      because the IP address alone tells you nothing.

  "TLS identity ... certificate does not cover <fqdn>"  -> FAIL
      Whatever answered is not the intended service. A proxy is terminating the
      connection and forwarding to the wrong backend, or not forwarding at all.

  "TLS identity ... issuer is not a known Microsoft/public CA"
      A TLS-intercepting proxy is re-signing the connection. SDKs that pin or
      validate strictly will fail even though the name matches.


WHAT THE SCRIPT CANNOT SEE THROUGH A PROXY / ADC
------------------------------------------------
If a NetScaler, F5, or similar appliance fronts the private endpoints, the
client can verify:

  * that something is listening on the VIP,
  * that it completes a TLS handshake,
  * and that the certificate identity matches the requested FQDN.

It CANNOT verify which backend IP the appliance actually selected, and it
cannot attribute a 401/403 to network policy rather than to the missing
credential (the probe is deliberately unauthenticated). Two different appliance
configurations - one pointing at the correct private endpoint, one pointing at
a stale or wrong address - can look identical from the client if both backends
are genuine Azure endpoints in the same wildcard namespace.

Confirming the backend selection has to be done on the appliance itself, for
example on a NetScaler:

    show server            # backend definitions and their addresses
    show service <name>    # state and the IP each service resolves to
    show lb vserver <name> # which services the VIP is bound to
    show dns addRec        # any static DNS entries overriding resolution

Compare the addresses shown there against the "PE NIC addresses" values in this
report. If they differ, the appliance is sending traffic somewhere other than
your private endpoints regardless of what the client observes.


  "Linked to a centralized/other VNet, not the injected VNet"
      Valid only if that VNet is your resolver and the injected VNet forwards
      to it (peering + custom DNS or Private Resolver). Pass -HubVNetId to have
      the script confirm the peering instead of guessing.

  "Regional shared endpoints ... excluded from pass/fail"
      Speech and Translator regional endpoints are multi-tenant and have no
      per-account private endpoint. They resolve publicly by design. If your
      workload calls them from a locked-down VNet they need firewall or UDR
      allowances, not a private endpoint.

  "Other connections (not checked)"
      App Insights / Log Analytics private access requires an Azure Monitor
      Private Link Scope (AMPLS). This script does not evaluate AMPLS.


NOTES
-----
  * A full run takes several minutes; most of that is private DNS zone
    discovery across subscriptions.
  * The script negotiates Azure API versions automatically. Foundry
    sub-resources (projects, connections) often reject the newest account API
    version, and a failed lookup is reported loudly rather than being silently
    treated as "nothing found".
  * Nothing is written to Azure, and no credentials or secrets are stored.
