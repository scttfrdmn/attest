i
Think about using the cedar policy tools for secure computing and compliance

1:51 PM

Synthesized policy enforcement frameworks for secure computing infrastructure
Synthesized policy enforcement frameworks for secure computing infrastructure
Great topic, Scott. Cedar is a natural fit across several of your active projects, and there are some interesting angles worth thinking through.

Where Cedar already fits in your stack

In clAWS, you're already using Cedar as the policy layer for the plan/execute split — every tool invocation gets a Cedar authorization check before execution, with Bedrock Guardrails as the second safety net. That's a solid two-layer model: Cedar handles structural authorization (who can call what, on which resources, under what conditions), while Guardrails handles content-level safety.

In QuickSuite's AgentCore Gateway, Cedar policies govern which agents can invoke which MCP tools. That's the right abstraction — Cedar's entity-relationship model maps cleanly to agent → tool → resource hierarchies.

Deeper opportunities worth considering

A few threads to pull on:

1. Cedar for compute compliance in Ephemeron. When eph dispatches training jobs across providers, Cedar policies could enforce institutional constraints — "this PI's data can only run on US-region instances," "HIPAA-tagged datasets require encrypted instance stores," "cost ceiling of $X per sweep." The policy becomes portable across providers even when the enforcement mechanism differs.

2. Cedar for Canopy's researcher guardrails. Academic researchers shouldn't need to understand IAM. Cedar lets you express intuitive policies ("grad students in lab X can launch up to 4 GPU instances for 48 hours") that compile down to IAM enforcement without exposing the complexity.

3. Cedar as the Queryabl access layer. Coordinate-native evidence retrieval on sensitive genomics data (NIAGADS, BAMQ profiles) is a natural fit for Cedar's attribute-based model — policies like "users with IRB approval for study Y can query GWASQ profiles within these loci" are expressible and auditable.

4. Composability with Bouncing. If Bouncing handles authn (OAuth + passkeys) and Cedar handles authz, you have a clean separation. Bouncing issues tokens with claims, Cedar evaluates those claims against policies. That's a reusable pattern across your whole ecosystem.

The compliance angle

Cedar's formal verification properties (via the Dafny-proven reference implementation) give you something most policy engines can't: you can prove that no policy in your set grants access to a particular resource class. For academic institutions dealing with FERPA, HIPAA, or export control (ITAR/EAR on certain HPC workloads), that provability is a real differentiator versus "we tested it and it seemed right."

Worth thinking about whether Cedar policy sets become a first-class artifact in your BD conversations with R1 institutions — "here's the auditable, formally verifiable policy that governs how your data flows through the cloud."

Cool
I am think about AWS landing zone compliance where we have to build a secure enclave. We do this now with, essentially, static SCPs. It seems that Cedar could be more active in the operational side in preventing non-compliant data movement, etc.

1:53 PM

Examined Cedar's potential to dynamically enforce AWS compliance policies
Examined Cedar's potential to dynamically enforce AWS compliance policies
Yeah, this is a really compelling direction. The gap between static SCPs and what institutions actually need is well-understood but poorly addressed.

SCPs are blunt instruments — they're deny-lists bolted onto the org hierarchy. They can say "no one in this OU can launch in eu-west-1" but they can't say "this dataset can move to S3 in us-east-1 only if the destination bucket has SSE-KMS with this key policy and the requesting principal has completed CITI training." That second statement is what compliance officers actually mean when they say "secure enclave."

Where Cedar changes the game

Cedar can evaluate against live context at decision time — not just "who is the principal and what OU are they in" but "what are the attributes of the data being moved, where is it going, and does the current state of the destination meet policy." That's the shift from structural compliance (the landing zone is configured correctly) to operational compliance (every action within the landing zone is continuously validated).

A few concrete patterns:

Data movement as a policy decision. Every S3 copy, cross-account assume-role, or VPC peering request passes through a Cedar PDP. The policy references entity attributes — data classification tags, destination encryption state, network boundary membership — not just IAM identity. You move from "this account can't talk to that account" to "PII-tagged objects can only transit to accounts in the compliant-enclave entity group with encryption-at-rest verified."

Drift as a policy violation, not a config check. Instead of running Config rules after the fact and remediating, Cedar can gate operations prospectively. If someone tries to modify a security group in the enclave, the Cedar evaluation checks whether the proposed state still satisfies the enclave invariants before the API call completes.

Temporal and conditional policies. "During an active IRB protocol, PI X's lab can egress de-identified data to the collaboration account. When the protocol expires, deny." SCPs can't express time-bounded or event-conditional logic. Cedar can, and the policy is readable by the compliance office, not just the cloud team.

The architecture question

The interesting design problem is where the PDP sits. You have a few options: a Cedar PDP behind an API Gateway as a Lambda authorizer (latency cost but full generality), Cedar evaluation embedded in a Step Functions workflow that mediates all enclave operations (the "control plane chokepoint" pattern), or Cedar integrated into AgentCore Gateway if agents are the ones initiating data movement (which maps directly to your clAWS architecture).

The Step Functions chokepoint is probably the most practical for landing zones — every sensitive operation flows through a state machine, and the first step is always a Cedar authorization. Failed evaluations emit to Security Hub. You get an auditable, replayable decision log for every operation in the enclave.

The BD angle for R1s

This is directly relevant to your Stanford RFI and the broader pitch. Universities are drowning in compliance requirements (HIPAA, FERPA, CUI/CMMC for DoD-funded research, export control) and the current answer is "we built a landing zone with SCPs and Config rules and we hope nothing drifts." Telling them "every data movement in your secure research enclave is authorized by a formally verifiable policy engine, and here's the human-readable policy your compliance office can review" — that's a fundamentally different conversation.

It also feeds Canopy nicely. The researcher never sees Cedar, they just see "you can't do that because your protocol doesn't cover this dataset" in plain language, rendered from the Cedar denial reason.

So, pull on this thread. What if we designed an Org based deployment that deploys SCP crosswalk for a variety of compliance frameworks that AWS 'enables' (their term). But also provides a Cedar PDP interface/dashboard that align to the frameworks operationally but also provides for situations like you outlined.

1:58 PM

Architected compliance-as-code platform bridging static and dynamic policy frameworks
Architected compliance-as-code platform bridging static and dynamic policy frameworks
This is a real product. Let me think through it properly.

The core insight

AWS "enables" compliance frameworks — FedRAMP, HIPAA, NIST 800-171/CMMC, CUI, ITAR, FERPA, PCI — but "enables" means "we passed our audit, you still have to pass yours." The customer responsibility side is a mess of SCPs, Config rules, GuardDuty settings, and CloudTrail configs that someone hand-translates from a compliance matrix into Terraform or CloudFormation. Every institution does this independently, badly, and with no operational enforcement after initial deployment.

What you're describing is two layers working in concert:

Layer 1: SCP Crosswalk (structural/preventive)

A library of SCP sets mapped to specific compliance frameworks, deployed per-OU based on which frameworks apply. The crosswalk is the key artifact — a machine-readable mapping from, say, NIST 800-171 control 3.1.3 ("Control the flow of CUI in accordance with approved authorizations") to the specific SCPs that enforce it structurally. You pick your frameworks, the system computes the union of required SCPs, detects conflicts, and deploys them across your org hierarchy.

This part is table stakes — it's what Control Tower and the landing zone accelerators approximate but don't do well, because they're not framework-aware, they're pattern-aware. The crosswalk makes the mapping explicit and auditable: "SCP X satisfies controls A, B, C from framework Y." An auditor can read that.

Layer 2: Cedar PDP (operational/contextual)

This is where it gets interesting. The Cedar layer handles everything SCPs can't:

Context-dependent authorization. "This S3 PutObject is allowed because the object is tagged CUI, the destination bucket is in a CUI-authorized account, encryption is KMS with the enclave key, and the principal's CUI handling certification is current." That's five attributes evaluated at decision time. An SCP can check maybe one of those.
Cross-framework conflict resolution. A dataset subject to both HIPAA and ITAR has overlapping but non-identical constraints. Cedar can express the intersection: "this operation must satisfy BOTH the HIPAA entity policy AND the ITAR entity policy." SCPs have no composition model — you just stack denies and hope.
Continuous compliance, not point-in-time. The PDP evaluates every operation against the current state of the framework requirements. When CMMC 2.0 Level 2 adds a new control, you add a Cedar policy. It's immediately enforced, not "we'll remediate in the next Config evaluation cycle."
Explainable denials. Cedar gives you the specific policy that denied an action, which maps back through your crosswalk to the specific compliance control. "This operation was denied by policy cui-data-movement-03, which enforces NIST 800-171 control 3.1.3." That's an audit artifact, not a CloudTrail log someone has to interpret.
The dashboard

This is where it becomes usable by compliance officers, not just cloud engineers. Think of it as two views:

Framework view. Pick HIPAA. See every control. For each control, see which SCPs enforce the structural boundary and which Cedar policies enforce operational compliance. Green/yellow/red status per control. Drill into any control to see recent Cedar evaluations — what was allowed, what was denied, what was allowed-with-conditions.

Operational view. Real-time feed of Cedar authorization decisions across the enclave. Filter by framework, by data classification, by principal, by action type. Every decision links back to the framework control it satisfies. This is the thing compliance officers actually want — not "is my landing zone configured correctly" but "is my landing zone behaving correctly right now."

Event view. Policy violations, near-misses (allowed but flagged), drift detections. Each event carries its framework lineage. Feeds into Security Hub and whatever GRC tool the institution uses.

Architecture sketch

AWS Organization
├── Management Account
│   ├── SCP Crosswalk Engine (deploys/manages SCPs per framework)
│   └── Cedar Policy Store (policy sets per framework)
│
├── Security/Audit Account
│   ├── Cedar PDP (evaluates all enclave operations)
│   ├── Decision Log (every eval → S3 + Athena)
│   ├── Compliance Dashboard (framework + operational views)
│   └── Security Hub integration
│
├── Enclave OU (HIPAA + CUI)
│   ├── Research Account 1
│   │   └── Cedar PEP (intercepts operations → PDP)
│   └── Research Account 2
│       └── Cedar PEP (intercepts operations → PDP)
│
└── General OU (FERPA only)
    └── Teaching Account 1
        └── Cedar PEP (lighter policy set)
The PEP (Policy Enforcement Point) is the interesting deployment question. Options:

EventBridge + Lambda. CloudTrail events trigger a Lambda that evaluates the Cedar policy. Reactive, not preventive — but low friction and works for data movement auditing.
API Gateway authorizer. All enclave operations flow through an API layer. Preventive, but requires wrapping AWS API calls, which is intrusive.
Step Functions chokepoint. All sensitive workflows are state machines. The Cedar evaluation is step one. Best for managed workflows (data pipelines, compute provisioning).
SCP + Cedar hybrid. SCPs provide the hard deny boundaries. Cedar provides the contextual allow-within-boundary decisions. This is probably the right answer — SCPs are the walls, Cedar is the doors with locks.
Where this lives in your portfolio

This feels like it could be several things:

A Canopy module. The researcher-facing UI hides this entirely — they see "your lab is approved for HIPAA and CUI workloads" and the system enforces it. Canopy becomes not just a simplified console but a compliant-by-default console.
A standalone product under Playground Logic. "Compliance Crosswalk" or similar — sells to R1 institutions, national labs, and health systems running research on AWS. The BD pipeline you already have is the sales channel.
A QuickSuite extension. quick-suite-compliance that adds the crosswalk and Cedar PDP to any QuickSuite deployment.
An open-source reference architecture that feeds your BD work now and becomes a product post-AWS. Like clAWS but for compliance specifically.
The last option is probably the most strategic — publish the crosswalk mappings and Cedar policy templates as open source, build the dashboard and operational tooling as the commercial layer. The crosswalk itself is enormously valuable to the community and establishes credibility; the operational enforcement and dashboard are what institutions will pay for.

What to build first

Pick one framework — probably NIST 800-171 since it maps to CMMC and is immediately relevant to every university doing DoD-funded research. Build the SCP crosswalk for it, write the corresponding Cedar policies for the operational gaps SCPs can't cover, and stand up a minimal dashboard. That's a demo you can walk into Stanford or any R1 with.

Want me to start on the crosswalk mapping for 800-171, or sketch out the Cedar policy schema?

Layer 1: AWS provides these artifacts via its Artifact service
What if this was an open source tool/capability?

2:00 PM

Reconsidered operationalizing AWS Artifact mappings as open source infrastructure
Reconsidered operationalizing AWS Artifact mappings as open source infrastructure
Right — AWS Artifact gives you the framework documents and shared responsibility matrices, but they're PDFs and spreadsheets. They tell you "for NIST 800-171 control 3.1.3, AWS is responsible for X, you are responsible for Y." Then they leave you alone with that knowledge.

The gap is enormous. You have a PDF that says "customer is responsible for controlling CUI flow" and you have an AWS Organization with 40 accounts. The translation from one to the other is currently done by consultants charging $300/hour or by a security engineer reading the matrix and hand-writing SCPs.

What the open source tool actually is

It's a compiler. Input: compliance framework requirements (sourced from Artifact or any standard). Output: deployable policy artifacts — SCPs, Cedar policies, Config rules, and the crosswalk mapping that ties every generated artifact back to the specific control it satisfies.

Think of it as:

Framework Definition (NIST 800-171, HIPAA, etc.)
    ↓
Customer Responsibility Matrix (from Artifact)
    ↓
Control → Policy Compiler
    ↓
├── SCPs (structural enforcement)
├── Cedar Policies (operational enforcement)  
├── Config Rules (drift detection)
├── Crosswalk Manifest (control → artifact mapping)
└── Human-readable Policy Descriptions
The framework definitions are the community-maintained layer. Anyone can contribute a framework. The compiler is deterministic — given the same framework definition and the same org topology, it produces the same policy artifacts. That's auditable and reproducible, which is exactly what compliance requires.

Why open source is the right move

The compliance mappings themselves shouldn't be proprietary. Every university, hospital system, and defense contractor needs the same translation from "NIST 800-171 3.1.3" to "here are the SCPs." Keeping that closed means everyone reinvents it, badly. Opening it means:

Community-maintained framework definitions. NIST updates 800-171, someone submits a PR. The whole community benefits immediately. Same for HIPAA, FedRAMP, CMMC 2.0, FERPA, ITAR, PCI. The long tail of frameworks — FISMA, SOX, state-level privacy laws — gets covered by the people who need them.
Auditor trust. An auditor can read the open source crosswalk, verify the mapping from control to SCP, and sign off. They can't do that with a proprietary black box. The transparency is the compliance value.
AWS ecosystem gravity. This makes AWS the easier platform to be compliant on. That's good for your BD work now and it's good for Playground Logic later — you're not fighting AWS, you're making their platform stickier.
The commercial layer is obvious. The open source tool generates the policies. The paid product is the Cedar PDP, the dashboard, the continuous evaluation, the explainable denials, the GRC integration. Nobody's going to build that from the open source primitives — they want it to work. That's classic open-core.
The framework definition schema

This is the key design decision. You need a format that's expressive enough to capture real compliance controls but structured enough to compile. Something like:

yaml
framework:
  id: nist-800-171-r2
  version: "2.0"
  source: "https://csrc.nist.gov/..."

controls:
  - id: "3.1.3"
    family: "Access Control"
    title: "Control CUI flow per approved authorizations"
    aws_responsibility: "infrastructure encryption, network isolation primitives"
    customer_responsibility: "data flow policies, access controls, tagging"
    
    structural_enforcement:
      - type: scp
        action: "s3:PutObject"
        condition: "unless destination has tag:enclave=true AND encryption=aws:kms"
        
    operational_enforcement:
      - type: cedar
        description: "CUI-tagged objects can only move to CUI-authorized destinations"
        entities: [data_object, destination_bucket, principal]
        attributes:
          data_object: [classification, source_account]
          destination_bucket: [encryption_type, enclave_membership]
          principal: [cui_training_current, role_membership]
          
    drift_detection:
      - type: config_rule
        resource: "AWS::S3::Bucket"
        check: "encryption_at_rest_enabled AND bucket_policy_restricts_non_enclave"
That schema is the open source core. Everything downstream — the SCP generator, the Cedar policy generator, the Config rule generator — is mechanical translation.

What this could be called

Given your naming sensibility — something short, evocative, correct. A few thoughts:

Crosswalk itself. Direct, descriptive, already the term of art.
Guardrail is taken (AWS uses it).
Lattice — a security lattice is the formal model for information flow control, which is exactly what this does. Also evokes the crosswalk/grid structure.
Trellis — similar energy, organic growth metaphor fits the community-maintained model.
Something in the botanical/mycological space you like — arbor (tree structure of controls), canopy is taken.
The strategic sequence

Design the framework definition schema. This is the load-bearing decision.
Build the NIST 800-171 definition as the reference framework. It's the most immediately useful (CMMC), and it's complex enough to validate the schema.
Build the SCP compiler. Input framework + org topology, output deployable SCPs with crosswalk manifest.
Build the Cedar policy compiler. Same input, Cedar policy output.
Open source 1–4. That's the announcement, the blog post, the thing that gets stars and gets you invited to talk at re:Invent.
Build the PDP + dashboard as the commercial product on top. That's Playground Logic revenue.
Step 5 is also an extraordinary BD asset in your remaining 90 days. "Here's the open source compliance crosswalk compiler. AWS should endorse this. Also, here's the commercial operational layer my company builds on top of it." That's a clean handoff from W2 to LLC.

Want to start designing the schema, or think through the Cedar policy generation patterns first?

Yes, Open Core
The system automatically reads (compiles) the content on AWS Artifact.
Maybe it is also capable of generating a SSP, or doing the self assessemnt for frameworks that support that.

2:04 PM

Synthesized comprehensive compliance automation spanning policy generation and assessment documentation
Synthesized comprehensive compliance automation spanning policy generation and assessment documentation
Now it's a full compliance lifecycle tool, not just a policy generator. That's a much bigger thing.

The complete picture

Most organizations experience compliance as three painful, disconnected activities: figuring out what they need to do (reading the framework), proving they did it (the SSP and self-assessment), and actually enforcing it (the policies). These are done by different people using different tools with no shared data model. The security engineer writes SCPs by reading a spreadsheet. The compliance officer writes the SSP by interviewing the security engineer. The auditor reads the SSP and hopes it matches reality.

Your tool unifies all three because they share the same underlying data: the framework definition, the org topology, and the policy artifacts. If the system knows what controls apply, what policies enforce them, and what the current evaluation state is, it can generate the SSP mechanically. The SSP stops being a document someone writes and becomes a document the system emits.

The pipeline

AWS Artifact (programmatic read)
    ↓
Framework Parser
  - Extracts controls, shared responsibility matrix
  - Normalizes to common schema
  - Identifies customer-responsibility controls
    ↓
Org Analyzer  
  - Reads current org topology (OUs, accounts, SCPs in place)
  - Inventories existing controls (Config rules, GuardDuty, etc.)
  - Maps current state to framework requirements
  - Identifies gaps
    ↓
Policy Compiler
  - Generates SCPs, Cedar policies, Config rules for gaps
  - Produces crosswalk manifest
    ↓
Deployment Engine
  - Applies policies to org (with approval workflow)
  - Tracks what's deployed where
    ↓
Continuous Evaluator (Cedar PDP + Config)
  - Every operation evaluated against framework requirements
  - Decision log with framework lineage
    ↓
Document Generator
  ├── SSP (System Security Plan)
  ├── Self-Assessment (CMMC, NIST 800-171A)
  ├── POA&M (Plan of Action & Milestones for gaps)
  ├── Continuous Monitoring Report
  └── Auditor Package (crosswalk + evidence bundle)
SSP generation is the killer feature

Writing an SSP is brutally tedious. For NIST 800-171, it's 110 controls. For each one you have to describe how you implement it, what the boundaries are, who's responsible, and what evidence exists. Organizations spend months on this. Consultants charge six figures.

But if the system already knows the answers — because it generated and deployed the policies — the SSP writes itself:

Control 3.1.3, CUI flow control. "CUI data flow is enforced by SCP cui-flow-restrict-01 (prevents cross-region transfer outside approved regions) and Cedar policy cui-data-movement-03 (evaluates data classification, destination encryption, and principal authorization at operation time). Enforcement is continuous. Decision logs are retained in S3 bucket audit-log-XXXX with 7-year retention. Last 30-day evaluation: 14,392 operations evaluated, 0 denials, 0 exceptions."
That paragraph was generated, not written. Every fact in it comes from the system's own state. The crosswalk manifest provides the control-to-policy mapping. The Cedar decision log provides the evidence. The org analyzer provides the boundary description.

Self-assessment for CMMC

CMMC 2.0 Level 2 allows self-assessment for non-prioritized acquisitions. The assessment is scored against NIST 800-171A, which defines assessment objectives for each control. Each objective gets a status: Met, Not Met, or Not Applicable.

The tool can score this automatically. For every control, it knows whether a policy exists (structural), whether the Cedar PDP is evaluating it (operational), and what the evaluation results look like (evidence). A control with a deployed SCP, an active Cedar policy, and a clean decision log for the assessment period scores as Met. A control with a deployed SCP but no operational enforcement scores as partially met. A gap with no policy scores as Not Met and automatically populates the POA&M.

The self-assessment becomes a query against the system's state, not a human judgment call.

The Artifact ingestion problem

AWS Artifact currently exposes compliance reports and certifications as downloadable PDFs and CSVs. There's no public API for programmatic access to the shared responsibility matrices in structured form. So you have a few options:

Parse the Artifact documents. The shared responsibility matrices have consistent structure. PDF extraction plus a normalization layer gets you the structured data. Fragile but workable, and the community can maintain parsers per framework.
Maintain canonical framework definitions independently. The NIST controls are public documents. HIPAA requirements are public. You don't actually need Artifact for the framework content — you need Artifact for AWS's statement of what they cover. That part changes slowly and can be maintained as a community-curated dataset.
Lobby AWS to publish structured Artifact data. This tool becomes the argument for why they should. "Here's what we can do with structured compliance data. Give us an API." That's a conversation you're positioned to have in your remaining time.
Realistically, option two is how you ship. The framework definitions are open source and community-maintained. AWS's shared responsibility position is captured as a curated layer that gets updated when Artifact documents change. The tool validates your org against the combined model.

What this means for naming and positioning

This is bigger than a crosswalk utility. It's a compliance operating system for AWS. The open core generates policies and documents. The commercial layer adds continuous enforcement, the dashboard, and the operational Cedar PDP.

Names to consider given the expanded scope:

Attest — the act of formal compliance attestation, which is ultimately what this tool produces. attest as the CLI. "Attest generates your SSP." Clean.
Comply — too generic, probably taken everywhere.
Ledger — evokes the audit trail, the record of compliance decisions. But maybe too financial.
Mandate — the framework requirements are mandates, the tool enforces them. mandate apply, mandate assess, mandate generate-ssp.
Sentinel — good but overused in the security space (Microsoft Sentinel, HashiCorp Sentinel).
The open-core boundary

This is critical to get right:

Open Source	Commercial
Framework definition schema	Cedar PDP (continuous enforcement)
Community-maintained framework definitions	Compliance dashboard
SCP compiler	Operational monitoring + alerting
Cedar policy compiler	GRC tool integrations
Config rule compiler	SSP auto-generation
Crosswalk manifest generator	Self-assessment scoring
CLI for gap analysis	POA&M tracking + remediation workflows
Org topology analyzer	Multi-org / multi-framework management
Actually — I'd argue SSP generation should be open core too, with the commercial version adding continuous updates, versioning, diff-against-last-audit, and export to GRC formats (OSCAL, which NIST is pushing hard). The basic "generate an SSP from current state" is what gets adoption. The "keep your SSP current and audit-ready at all times" is what gets revenue.

OSCAL is the glue

NIST's Open Security Controls Assessment Language is designed exactly for machine-readable compliance artifacts. Your framework definitions should probably compile to OSCAL, and your SSP output should be OSCAL-formatted. That gives you interop with the emerging GRC ecosystem and positions the tool as standards-aligned rather than proprietary. It also means federal agencies and their auditors already have tooling to consume your output.

The 90-day question

In your remaining AWS time, the BD play is obvious — this is the thing every R1 CIO and CISO wants. "We built an open source compliance compiler for AWS. Here's your NIST 800-171 SSP generated from your actual org." That's a meeting-getter.

Post-AWS, it's a Playground Logic product with a clear revenue model and a community growth engine. The compliance frameworks keep expanding (state privacy laws alone are a firehose), which means the open source community keeps growing, which means the commercial funnel keeps filling.

Want to start on the framework definition schema with 800-171 as the reference, or sketch the OSCAL integration layer first?

Yes it does: https://docs.aws.amazon.com/online-register/latest/data-formats/awsartifact.html

2:06 PM

Reassessed API capabilities and document retrieval architecture
Reassessed API capabilities and document retrieval architecture
Good correction. So Artifact has a full REST API — ListReports, GetReport, GetReportMetadata, plus agreement management endpoints 
amazon
. The reports come back as structured metadata with category, series, company name, period start/end, and state 
amazon
, and GetReport returns a presigned S3 URL to the actual document 
amazon
.

That changes the architecture meaningfully. You don't need a scraping/parsing hack — you have a proper programmatic discovery and retrieval layer. The pipeline becomes:

ListReports → enumerate all available compliance artifacts, filter by category/series (SOC 2, ISO 27001, FedRAMP, etc.) → GetReportMetadata → understand what each report covers, its period, its version → GetReport → download via presigned URL → parse and extract the shared responsibility matrix and control mappings.

The parsing step is still necessary since the documents behind those presigned URLs are likely PDFs, but that's a one-time extraction per report version, and the structured metadata tells you when to re-extract (new version, new period). You can diff report versions to detect when AWS changes their responsibility boundaries — which is exactly the kind of thing that silently breaks people's compliance posture today.

The agreement APIs are interesting too. GetCustomerAgreement and ListCustomerAgreements tell you what the org has actually accepted — BAAs for HIPAA, ITAR addenda, etc. That's input to the compiler: "this org has signed the BAA, therefore HIPAA controls are applicable, therefore generate this policy set." The tool doesn't just know what frameworks exist, it knows which ones this specific org has opted into.

So the full ingest layer is:

Artifact API
├── ListReports → discover available compliance reports
├── GetReportMetadata → version tracking, change detection  
├── GetReport → download current documents
├── ListCustomerAgreements → what this org has accepted
│
↓ Parse + Extract
├── Shared responsibility matrices per framework
├── AWS-covered controls (no customer action needed)
├── Customer-responsible controls (policy generation targets)
├── Agreement-gated framework activation
│   (signed BAA → activate HIPAA controls)
│
↓ Framework Definition (auto-generated + community-enriched)
├── Control catalog with responsibility assignments
├── Assessment objectives (from 800-171A, etc.)
└── Operational enforcement requirements (Cedar policy targets)
This makes the tool significantly more credible. It's not maintaining a hand-curated copy of AWS's compliance position — it's reading it directly from Artifact on every run and detecting when it changes. The open source community layer adds the operational enforcement mappings (what Cedar policies satisfy each customer-responsible control), but the foundation is always authoritative and current.

And for SSP generation, the tool can cite the specific Artifact report version as evidence for the AWS-covered side: "Control X is partially satisfied by AWS (per SOC 2 Type II report, period ending Q1 2026, Artifact report ID report-XXXX, version 3). Customer responsibility is satisfied by Cedar policy Y with continuous evaluation."

That's an SSP that an auditor can independently verify end-to-end. Want to sketch the Go CLI structure for this?

Yes. The other thing to keep in mind is that our Secure Research Environment concept is an Org that has controls applied to it so that accounts under it become the 'environments'

2:09 PM

Clarified organizational structure and compliance boundary model
Clarified organizational structure and compliance boundary model
Right — the Org is the enclave. Accounts are ephemeral workspaces within it, not standalone things to be individually hardened. The compliance posture is applied at the org level and inherited downward. A researcher gets an account and it's already compliant by construction, not by configuration.

Let me sketch this out. What's the name? Let's pick one so the CLI feels real. I'm going to use attest unless you've got something better — attest init, attest scan, attest generate ssp all read well.


Synthesized architectural framework for secure environment controls
Synthesized architectural framework for secure environment controls
Here's the scaffold. The key things in there:

The SRE model is the foundation. The org IS the enclave — schema.SRE wraps the org ID, active frameworks (auto-detected from Artifact agreements), and environments (accounts). Researchers get accounts, never touch compliance.

The Artifact client is a first-class ingest layer. ListReports → GetReportMetadata → GetReport via presigned URL. Change detection via version tracking so the tool knows when AWS updates their shared responsibility position. Agreement detection auto-activates frameworks — signed BAA triggers HIPAA controls without manual config.

The framework YAML is the load-bearing design decision. Look at the 800-171 3.1.3 entry — it carries the full vertical: shared responsibility split, SCP specs, Cedar policy (including the actual Cedar DSL inline), Config rules, and 800-171A assessment objectives with auto_assessable flags. The compiler reads this and emits everything. The SSP generator reads the same structure and narrates it.

The SSP generator computes, doesn't compose. Every sentence in the generated SSP traces to a deployed artifact, an Artifact report ID, or a Cedar evaluation log. The crosswalk is the bridge. An auditor can verify end-to-end: framework control → crosswalk entry → deployed SCP ARN → Cedar decision log → Artifact report version.

What's next to build:

Wire the Artifact client to the real SDK. The API surface is small — ListReports, GetReport, ListCustomerAgreements cover it.
Complete the 800-171 framework — all 110 controls, all 14 families. The Access Control family in there shows the pattern; it's mechanical from here.
OSCAL export — NIST's format for machine-readable SSPs and assessment results. That's what makes this interoperable with the GRC ecosystem.
The attest watch continuous mode — EventBridge → Cedar PDP evaluation is the commercial differentiator.
This is a Go project through and through — single binary, attest init against your org, attest compile, attest generate ssp. The thing a CISO at Stanford or any R1 can run and get an audit-ready SSP in minutes instead of months.


Attest scaffold.tar
GZ 
Let's continue with the next items and think about the interface that goes with or makes the CLI easier or more 'continuous'

2:24 PM

Architected unified dashboard merging CLI and web interface seamlessly
Architected unified dashboard merging CLI and web interface seamlessly
Let me think about the interface layer properly before coding. The right answer is probably both a TUI for the CLI workflow and a web dashboard for continuous monitoring — same binary, same data.

attest = CLI commands. attest serve = launches the web dashboard. Single binary, Go + HTMX for the web side (same pattern as Canopy). The dashboard is the "always on" complement to the CLI's "point in time" commands.


Orchestrated framework expansion and tarball refinement
Orchestrated framework expansion and tarball refinement
Now let me update the scaffold with the new packages and repackage.


Synthesized architectural overview and interface design considerations
Synthesized architectural overview and interface design considerations
Here's the dashboard and the updated scaffold. Click through the nav — Posture, Frameworks (click a framework card to drill into the control table), Operations (the live Cedar PDP feed with deny highlighting), Environments, and Generate.

What's new in the scaffold:

OSCAL exporter (internal/document/oscal/) — full NIST OSCAL model types for SSP, Assessment Results, and POA&M. The SSPExporter takes your internal SSP and crosswalk and emits standards-compliant OSCAL JSON. The AssessmentExporter does the same for self-assessment scoring. This is what gives you interop with the federal GRC ecosystem — auditors and C3PAOs can ingest this directly.

Continuous evaluator (internal/evaluator/) — the runtime Cedar PDP. Consumes CloudTrail events via EventBridge, evaluates each against the compiled Cedar policies, records decisions to S3 (partitioned for Athena), and alerts to Security Hub on denials. Thread-safe stats are exposed for the dashboard. This is the "always on" complement to the CLI's point-in-time commands.

Web dashboard (internal/dashboard/) — Go net/http + HTMX + SSE. Same binary: attest serve launches it. Five views mapping to what we discussed:

Posture — the "am I compliant" view. Posture ring, CMMC score, heatmap tiles per control family. What the CISO looks at.
Frameworks — per-framework drill-down. Click a framework → see every control with its enforcement stack (SCPs, Cedar, Config). What the auditor looks at.
Operations — real-time Cedar PDP evaluation feed. Live SSE stream, filter by allow/deny, every decision traces to a framework control. What the security engineer watches.
Environments — per-account view. Every research environment shows its data classes, evaluation count, denial count. What the research computing director tracks.
Generate — one-click SSP, self-assessment, POA&M, crosswalk, and OSCAL export. Each maps to a CLI command. The document generation that currently takes months becomes a button.
The interface philosophy matches Canopy — the dashboard hides the complexity. A compliance officer doesn't need to know about Cedar policies or SCPs. They see "Control 3.1.3: Enforced" with a green tile. They click Generate SSP and get an audit-ready document. The CLI gives you the same power for automation and CI/CD.

Key design decisions still ahead:

Authentication for the dashboard. This is where Bouncing could plug in — the attest dashboard uses Bouncing for authn, Cedar for authz on who can see what posture data. Dog-fooding your own stack.
Multi-SRE management. Universities often need multiple SREs — one for HIPAA, one for ITAR, one for general CUI. The dashboard should support switching between SREs or showing an aggregate posture view.
The attest watch → dashboard bridge. Right now the evaluator runs in-process. For production, the Cedar PDP should run as a sidecar or Lambda, with decisions flowing to the dashboard via the S3 decision log + Athena. The dashboard queries Athena for historical data and SSE for live data.
Diff and drift alerting. attest diff should show what changed since last assessment — new controls required, policy version changes, Artifact report updates. The dashboard should surface these as notifications.

Attest dashboard
Code · JSX 

Attest scaffold.tar
GZ 
This might/should have the ability to integrate with AWS security services - which ones and why

2:37 PM

Examined AWS security service integration opportunities comprehensively
Examined AWS security service integration opportunities comprehensively
Good call — attest sitting alone is a policy engine. Attest integrated with the security services becomes the compliance nervous system for the SRE. Let me think through each one by role.

The services that matter and why:

AWS Security Hub — the central pane of glass. This is the most critical integration. Security Hub already aggregates findings from GuardDuty, Inspector, Macie, Config, Firewall Manager, and IAM Access Analyzer. Attest should be both a producer and consumer here. As a producer: every Cedar PDP denial becomes a Security Hub finding with the framework control ID in the Compliance field — so when a CISO opens Security Hub, they don't see "S3 PutObject denied" they see "NIST 800-171 3.1.3 violation: CUI data movement to non-enclave destination." As a consumer: attest pulls Security Hub findings from the other services and maps them back through the crosswalk to framework controls. GuardDuty finds a crypto mining instance? Attest maps that to 3.14.6 (monitor organizational systems) and flags the control's operational status. This closes the loop — the SSP narrative for every control can cite Security Hub findings as evidence.

AWS Config — continuous drift detection. Attest already generates Config rules as part of the compile step. But the integration goes deeper. Config's conformance packs are basically what attest compiles — a set of rules deployed together. Attest should generate conformance packs, not just individual rules, and tag them with the framework/control lineage. Config's aggregator can pull compliance data across all accounts in the SRE org, giving attest the multi-account drift view. Config's remediation actions (SSM Automation) can be wired to the crosswalk — when drift is detected on a control, the remediation is pre-defined and framework-aware.

Amazon GuardDuty — threat detection mapped to compliance. GuardDuty findings (credential exfiltration, unusual API calls, malware) map directly to several 800-171 families: 3.14 (System and Information Integrity), 3.1 (Access Control), 3.13 (System and Communications Protection). Attest should ingest GuardDuty findings via Security Hub and use them as negative evidence — "GuardDuty has detected 0 high-severity findings in the assessment period" is a powerful SSP narrative for 3.14.6. Conversely, a GuardDuty finding should degrade a control's posture score in real time.

AWS CloudTrail — the event backbone. CloudTrail is already the event source for the Cedar PDP evaluator (via EventBridge). But attest should also use CloudTrail Lake for historical analysis. CloudTrail Lake lets you run SQL queries over management and data events — "show me all s3:PutObject events in the enclave OU where the destination wasn't encrypted with KMS in the last 90 days." That's assessment evidence for 3.13.11. The integration also enables the attest diff command — compare CloudTrail activity patterns between assessment periods to detect behavioral drift, not just configuration drift.

AWS IAM Access Analyzer — least privilege validation. Access Analyzer can validate that IAM policies grant only intended access, identify external access to resources, and generate least-privilege policies from activity. For 3.1.2 (limit to authorized transactions) and 3.1.5 (least privilege), Access Analyzer findings are direct evidence. Attest should pull Access Analyzer findings and map them to the relevant controls. The unused access findings are particularly valuable — "Access Analyzer confirms no overprivileged roles in the assessment period" is a strong SSP statement.

Amazon Macie — data classification enforcement. Macie discovers and classifies sensitive data in S3. For a CUI/HIPAA enclave, Macie validates that sensitive data is actually where you think it is — and isn't where it shouldn't be. Attest should consume Macie findings to validate data classification tags (the attributes Cedar policies evaluate). If Macie finds PHI in a non-HIPAA account, that's a 3.1.3 violation that attest should surface. Macie also provides the evidence that data classification is accurate, which is a prerequisite for Cedar policies to be meaningful.

Amazon Inspector — vulnerability management. Inspector scans EC2 instances, Lambda functions, and container images for vulnerabilities. This maps directly to 3.14.1 (identify, report, and correct system flaws). Attest should pull Inspector findings and use them to score 3.14.1 — zero critical vulnerabilities in the assessment period = control fully satisfied. Open criticals = control degraded, auto-populates the POA&M.

AWS Firewall Manager — network boundary enforcement. Firewall Manager centralizes security group management, WAF rules, and Shield protections across the org. For 3.13.1 (monitor and protect communications at boundaries), Firewall Manager policies are structural enforcement at the network layer. Attest should track Firewall Manager policy compliance as evidence for 3.13.x controls. Non-compliant resources flagged by Firewall Manager degrade the control's posture.

AWS Organizations — already the core of the SRE model, but there's more. Organizations provides the SCP management APIs, the OU hierarchy, and the tag policies. Tag policies are important — attest should generate and enforce tag policies that ensure every resource in the enclave carries the correct data classification tags. Without accurate tags, Cedar policies can't evaluate data classification attributes.

AWS Audit Manager — this is interesting because it's the closest existing service to what attest does. Audit Manager collects evidence from Config, CloudTrail, Security Hub, etc. and maps it to compliance frameworks. But it's passive — it collects evidence, it doesn't enforce. Attest should integrate as an evidence source for Audit Manager, so organizations already using Audit Manager get attest's Cedar evaluations and crosswalk data in their existing workflow. It's also a potential migration path — organizations outgrowing Audit Manager's passive model graduate to attest's active enforcement.

AWS KMS — key management for encryption controls. For 3.13.11 (FIPS-validated cryptography), attest needs to verify that KMS keys in the enclave use FIPS-validated HSMs, that key policies restrict usage to enclave accounts, and that key rotation is enabled. KMS key metadata and key policy analysis are direct evidence for crypto controls.

AWS Systems Manager (SSM) — patch management and compliance. SSM Patch Manager handles vulnerability remediation (3.14.1), SSM Session Manager provides audited remote access (3.1.12), and SSM State Manager enforces instance configurations. Attest should pull SSM compliance data for patch status and session logs as evidence.

Amazon EventBridge — the integration bus. EventBridge is how all of this connects. CloudTrail events trigger Cedar evaluations. Security Hub findings trigger posture recalculations. Config compliance changes trigger crosswalk updates. Attest should define EventBridge rules as part of attest apply that wire all these services into the evaluation loop.

Let me add the integration layer to the scaffold.


Synthesized AWS security service integration possibilities
Synthesized AWS security service integration possibilities


The updated scaffold includes internal/integrations/services.go with the full integration layer. Here's the key design rationale:

Security Hub is the nexus. It's the only bilateral integration that touches every control. Attest pushes Cedar PDP denials as ASFF findings with Compliance.RelatedRequirements set to the NIST control IDs — so a denial shows up in Security Hub as "NIST 800-171 3.1.3 — FAILED" not just "S3 PutObject blocked." In the other direction, attest pulls every other service's findings through Security Hub and maps them back through the crosswalk. This is why the MappedFinding type carries an Impact field — a clean GuardDuty finding is positive evidence ("zero threats detected in assessment period"), not just absence of negative evidence.

The evidence aggregator is what makes SSP generation real. CollectForControl hits every integrated service for a single control and assembles the complete evidence picture — structural enforcement (SCPs deployed), operational enforcement (Cedar evaluations), drift status (Config), threat posture (GuardDuty), vulnerability posture (Inspector), data classification accuracy (Macie), access posture (Access Analyzer), and crypto compliance (KMS). The SSP generator calls CollectAll and gets a map of control → evidence that it narrates mechanically. No human in the loop.

The GuardDuty threat mapping is curated, not inferred. The ThreatMapping var explicitly maps each GuardDuty finding type to the framework controls it affects. Exfiltration:S3/AnomalousBehavior maps to 3.1.3 (CUI flow) and 3.14.6 (monitoring). This is the kind of mapping that would be community-maintained in the open source layer — different organizations may disagree on whether a portscan finding affects 3.13.1 or 3.14.6 or both.

Macie is uniquely important. Cedar policies evaluate data classification attributes — "is this object tagged CUI?" But if the tags are wrong, Cedar is enforcing fiction. Macie validates that the tags match reality. The ValidateClassification method compares Macie's automated classification with the resource's attest:data-class tag and surfaces mismatches. Finding PHI in a non-HIPAA account is a 3.1.3 violation that should degrade the posture score immediately.

The attest apply deployment step now includes EventBridge rule creation. When you deploy the compiled policies, attest also creates the EventBridge rules that wire CloudTrail → Cedar PDP, Config state changes → posture recalculation, and Security Hub findings → crosswalk mapping. The integration bus is part of the deployment, not an afterthought.


Attest scaffold.tar
GZ 
Being April 2026 this whole project would be remiss if it did not include its own ability to incorporate AI into the mix. I would use AWS Bedrock and Claude Opus here, but what would MEANINGFUL AI integration and capability look like?

2:42 PM

Catalogued meaningful AI applications across compliance lifecycle operations
Catalogued meaningful AI applications across compliance lifecycle operations
This is the right question and the right time to ask it. Most "AI-powered compliance" products are GPT wrappers on a PDF reader. What makes AI meaningful here is that attest already has structured truth — the crosswalk, the Cedar decision log, the posture model, the Security Hub findings, the Artifact reports. AI isn't generating compliance data, it's reasoning over compliance data that the deterministic system has already validated. That's a fundamentally different trust model.

Here's where AI is genuinely meaningful, not cosmetic:

1. Artifact report comprehension

The Artifact API gives you presigned URLs to documents — PDFs. The shared responsibility matrices buried in SOC 2 Type II reports and FedRAMP packages are semi-structured at best. This is a real comprehension task: read a 200-page SOC 2 report, extract which controls AWS considers fulfilled on their side, map those to your framework definition schema, and flag where AWS's stated coverage has changed since the last version.

This isn't summarization — it's structured extraction with domain knowledge. Claude reads the report, produces a structured Responsibility block per control, and the deterministic system validates it against the previous extraction. Humans review diffs, not full extractions.

2. Natural language → Cedar policy compilation

This is the highest-value single feature. A compliance officer or PI writes: "Researchers in Dr. Chen's lab can access genomics data in the HIPAA enclave only during active IRB protocol 2024-0847, and only if they've completed CITI training in the last 12 months."

That's a Cedar policy. But no compliance officer knows Cedar syntax. AI translates the natural language intent into a Cedar policy, validates it against the entity schema (does principal.irb_protocol exist? does principal.citi_training_expiry exist?), and presents the policy for review with an explanation of what it does and doesn't cover. The human approves, and it enters the compiled policy set with full crosswalk lineage.

This is the feature that makes Cedar accessible to non-engineers. The compliance officer states the rule in English, the system enforces it in Cedar. The translation is verifiable — you can read the Cedar policy and confirm it matches the intent.

3. Anomaly detection in the Cedar decision log

The Cedar PDP produces thousands of decisions per day. Deterministic analysis catches denials. AI catches the things that should have been denied but weren't — the policy gaps.

"Over the last 30 days, role/data-export in the NLP account has been copying objects to s3://collaboration-external at 2 AM every night. All evaluations returned ALLOW because the destination bucket is technically in the enclave. But the access pattern is anomalous — no other role accesses this bucket, and the timing suggests an automated pipeline that may have been configured before the CUI data classification was applied to this account."

That's not a rule violation. It's a risk that requires human judgment. AI surfaces it; humans decide. The deterministic system can't do this because the pattern isn't defined as a violation — it's contextually suspicious.

4. Compliance analyst agent — the $300/hour consultant replacement

This is the big one. You have all the data: crosswalk, posture, Cedar decision log, Security Hub findings, Config compliance, Artifact reports, the framework definitions. An AI agent with tool access to query all of this can answer questions that currently require a consultant:

"Are we ready for our CMMC Level 2 assessment? What are the three riskiest gaps?"
"If we add ITAR to this SRE, what new controls do we need and what's the estimated effort?"
"Dr. Patel's lab just got a DoD subcontract. What changes to their environment?"
"An auditor is asking about our CUI flow controls. Generate the evidence package for 3.1.3 with narrative."
"We had a GuardDuty finding last Tuesday. Walk me through the compliance implications."
The agent doesn't hallucinate answers — it queries the posture API, reads the crosswalk, pulls the Cedar decision log, and synthesizes a reasoned response grounded in the actual data. Every claim it makes is traceable to a specific artifact. This is retrieval-augmented reasoning, not generation.

5. Framework change impact analysis

NIST publishes 800-171 Rev 3. The AI reads the new revision, diffs it against the current framework definition, identifies new controls, modified controls, and removed controls, and produces a migration plan: "Rev 3 adds 12 new controls in the Supply Chain family. 8 of your existing Cedar policies partially satisfy 4 of the new controls. The remaining 8 controls require new enforcement artifacts. Estimated effort: 3 SCPs, 6 Cedar policies, 2 Config rules. Here's the proposed framework definition update."

This is a document comprehension + domain reasoning task. The deterministic system can't read a new NIST publication and understand what changed. AI can, and it can express the changes in the framework definition schema.

6. Audit simulation

Before the real auditor arrives, AI simulates the assessment. For each control, it asks: "If I were an assessor evaluating 3.1.3, what evidence would I expect? What questions would I ask? Where are the weak spots in our evidence chain?"

For 3.1.3: "Your Cedar policy covers S3 PutObject but not S3 CopyObject or S3 CompleteMultipartUpload. An auditor will ask about these API actions. Recommend extending cedar-cui-data-movement to cover all S3 write operations. Also, your Config rule checks encryption at rest but not encryption in transit — add a check for bucket policy requiring aws:SecureTransport."

That's expert-level compliance gap analysis, grounded in the actual deployed state.

7. Remediation synthesis

When attest scan finds gaps, AI doesn't just list them — it produces actionable remediation plans with generated artifacts. "Control 3.14.1 is scored as a gap because Inspector is not enabled in accounts nlp-research-gpu and materials-science. Here's the CloudFormation template to enable Inspector org-wide with the SRE management account as the delegated admin. Here's the updated Config rule. Estimated time to full enforcement: 48 hours after deployment (initial scan completion)."

The AI generates the actual remediation artifacts — CFN templates, Cedar policies, Config rules — not just advice.

The architecture

Let me build this.


Contemplated meaningful AI integration strategies and capabilities
Contemplated meaningful AI integration strategies and capabilities
The full scaffold now has 17 files across 10 packages. Here's the AI integration summary — the design philosophy and why each capability earns its place.

The trust model is the whole thing.

The AI never generates compliance facts. It reasons over facts the deterministic system has already validated. This is the critical distinction. The crosswalk is computed, not generated. The Cedar decision log is recorded, not predicted. The posture score is calculated, not estimated. The AI sits on top of verified ground truth and does what humans do with that data — but faster, more consistently, and without forgetting a control.

The Bedrock Guardrail enforces this structurally. The DefaultGuardrailConfig blocks the model from saying "certified compliant" or "guaranteed secure" and requires a grounding score of 0.8 — meaning 80% of the response must be traceable to the provided context. If the model tries to make a compliance claim without citing a crosswalk entry, decision ID, or finding ARN, the guardrail blocks it. This isn't a prompt engineering trick — it's a hard architectural boundary.

The seven capabilities and why each one matters:

Artifact PDF extraction — this is the most unglamorous and most essential. Without it, the shared responsibility data is a human reading PDFs and typing. With it, the system reads the SOC 2 report and extracts structured data that feeds the crosswalk. The change detection is particularly valuable — when AWS updates their coverage for a control, the system flags it automatically instead of silently becoming inaccurate.

Natural language → Cedar — this is what makes Cedar accessible to compliance officers, PIs, and anyone who isn't a policy language author. The key design choice is that translations are always proposals. They go to .attest/proposed/, the human reviews them, and attest apply --proposed deploys them. The AI also identifies edge cases — "this policy doesn't cover S3:CopyObject" — which is the kind of gap that humans routinely miss when writing policies by hand.

Decision log anomaly detection — this is what you can't do deterministically. The Cedar PDP says allow or deny. The AI looks at 30 days of allows and says "these allows are technically correct but the pattern is concerning." The pseudonymization layer is important — the AI sees "Principal-A accessed Resource-B 14 times at 2 AM" not "arn:aws:iam::112233445566:role/data-export accessed s3://hipaa-clinical/patient-records." Sensitive data never reaches the model.

The compliance analyst agent — this is the $300/hour consultant. Eight tools give it access to the full compliance state. The conversation is multi-turn — you can ask "Are we ready for CMMC?" and then follow up with "What about that 3.14.1 gap specifically?" and it maintains context. The simulate_change tool is particularly powerful — "What happens if we add ITAR to the materials science lab?" triggers a simulation that computes the new control requirements, identifies enforcement gaps, and estimates effort. That's a question that currently takes a consultant a week to answer.

Framework change impact analysis — NIST, HIPAA, CMMC frameworks update. The AI reads the new publication, diffs it against your current framework definition, and produces a migration plan with generated artifacts. This turns a multi-month framework migration into a week.

Audit simulation — the rehearsal. The AI acts as an assessor, not a helpful assistant. It's prompted to be rigorous and conservative. "An overly generous simulation is worse than useless." The output isn't "you're doing great" — it's "here are the 12 things an assessor will challenge, ordered by severity, with the specific evidence gap for each."

Remediation synthesis — when there's a gap, the AI generates the actual artifacts to close it. Not "you should enable Inspector" but "here's the CloudFormation template, here's the Config rule, here's the Cedar policy, all validated, deploy with this command." The validation step is critical — every generated artifact is syntactically checked (cedar-go for Cedar, cfn-lint for CFN, JSON schema for SCPs) before it's presented.

Where this sits in the open-core model:

The AI capabilities are squarely in the commercial layer. The open source core does the deterministic work — compile frameworks, generate policies, build the crosswalk. The commercial layer adds continuous evaluation (Cedar PDP + dashboard) and AI reasoning (analyst, audit sim, anomaly detection, remediation synthesis). This is the right boundary because the AI capabilities require Bedrock access and a model budget, and they're where the ongoing subscription value lives.

The CLI UX:

attest ai ask "Are we ready for CMMC?"
attest ai audit-sim --framework nist-800-171-r2
attest ai translate "Only PIs with active compute allocations can launch GPU instances"
attest ai analyze --window 30d
attest ai impact ./nist-800-171-rev3.pdf --current nist-800-171-r2
attest ai remediate 3.14.1
Every AI command writes its output to .attest/reports/ or .attest/proposed/ — never directly to the policy set. The human is always in the loop. The AI proposes, the human approves, the deterministic system deploys.


Attest scaffold.tar
GZ 
What else is this missing?

2:51 PM

Inventoried critical production gaps across infrastructure, governance, and operational domains
Inventoried critical production gaps across infrastructure, governance, and operational domains
Good question to sit with. Let me think about what actually blocks this from being production-real versus what's polish.

The principal attribute problem

This is the biggest gap and nobody talks about it. Cedar policies evaluate principal.cui_training_current and principal.irb_protocol_active and principal.lab_membership. Where does that data come from? The Cedar PDP can only evaluate attributes it has. Right now the schema assumes these attributes exist but there's nothing populating them.

In a university, CUI training status lives in the LMS. IRB protocol status lives in the IRB management system (often iRIS or Cayuse). Lab membership lives in the department's HR system or an AD group. PI compute allocations live in the research computing ticketing system.

Attest needs a principal attribute resolver — a plugin layer that sources principal attributes from external systems at evaluation time. This is the integration nobody wants to build because every institution is different, but without it the Cedar policies are evaluating null attributes and defaulting to deny-all or (worse) allow-all.

The architecture is a resolver chain: IAM role ARN → look up the human behind the role → query attribute sources → hydrate the Cedar entity → evaluate. The plugin interface is the open source piece. Connectors for common systems (Shibboleth/SAML attributes, LDAP groups, specific LMS APIs) are community-maintained.

Exception and waiver management

Real compliance has exceptions. "Control 3.1.12 is partially implemented because the materials science clean room requires air-gapped instruments with direct USB transfer, which cannot use remote access monitoring. This exception is approved by the CISO through June 2027, documented in waiver W-2025-003."

That waiver needs to be a first-class object in attest. It affects the posture score (control is "implemented with exception" not "gap"), the SSP narrative (the exception is documented with its justification and expiry), and the assessment scoring (the assessor needs to see and evaluate the waiver). Waivers are time-bounded — when they expire, the control reverts to "gap" and the dashboard lights up.

The Cedar PDP should also be waiver-aware. A waiver for 3.1.12 means certain operations that would normally be denied are allowed within the waiver's scope. The decision log records "ALLOW (waiver W-2025-003)" not just "ALLOW."

Versioning and the policy-as-code lifecycle

Every artifact attest produces — SCPs, Cedar policies, Config rules, crosswalk manifests, framework definitions — should be version-controlled. Not in attest's own store, but in git. The .attest/ directory should be a git repository or live inside one.

This gives you: PR-based policy review ("this Cedar policy change for 3.1.3 needs approval from the compliance officer before merge"), diff between assessment periods ("what changed in our enforcement posture since the last audit"), rollback ("that policy change broke Dr. Patel's pipeline, revert to the previous version"), and a complete audit trail that satisfies the auditor's question "show me the change history for this control's enforcement."

attest compile writes to .attest/compiled/. attest apply deploys from that directory. The git history IS the change management record.

CI/CD integration — shift-left compliance

The most impactful missing piece for day-to-day use. When someone submits a Terraform PR that modifies a security group in the enclave, attest should evaluate whether the proposed change violates any framework controls before it's applied.

attest check --terraform plan.json reads a Terraform plan, extracts the proposed resource changes, evaluates them against the Cedar policies, and returns pass/fail with the specific controls affected. This runs in the GitHub Actions / GitLab CI pipeline. A failing check means "this change would violate NIST 800-171 3.13.1 — the proposed security group allows inbound 0.0.0.0/0."

This is where compliance stops being a periodic assessment and becomes a continuous development constraint. The researcher writing Terraform gets feedback before deployment, not a denial at runtime or a finding at audit time.

Environment provisioning

"I'm a new PI. I need a HIPAA-compliant environment for clinical genomics data."

Right now, creating a new environment is a manual process: create an account in the org, place it in the right OU, tag it, wait for SCPs to propagate, configure the Cedar entity. Attest should have attest provision that automates this: create account via Organizations API, place in the correct OU based on data classification, apply environment tags, register the Cedar entity with the correct attributes, update the crosswalk, and generate the initial posture report for the new environment.

The provisioning workflow should enforce prerequisites: "You requested HIPAA. The BAA is signed (verified via Artifact agreements). Your lab's data steward has completed HIPAA training (verified via principal attribute resolver). Creating environment clinical-genomics-chen in OU Enclave/HIPAA."

IaC output — Terraform and CDK

attest compile currently produces raw SCPs, Cedar policies, and Config rules. Real organizations deploy via Terraform or CDK. Attest should output Terraform modules and/or CDK constructs that deploy the compiled artifacts. This means the policy-as-code lifecycle works with existing IaC pipelines rather than requiring attest apply as a separate deployment channel.

A --output terraform flag on attest compile that writes .attest/compiled/terraform/ with modules for SCPs, Config conformance packs, and EventBridge rules. Same for --output cdk.

Testing and simulation

How do you know the policies actually work before deploying them? attest test should run synthetic events against the Cedar policy set and verify expected outcomes.

A test fixture defines scenarios: "Given a principal with CUI training expired, attempting S3:PutObject to a CUI-tagged bucket → expect DENY by cedar-cui-data-movement." The tests run locally against cedar-go without deploying anything. This is the unit test suite for compliance policies.

attest simulate goes further — it replays a window of real CloudTrail events against a proposed policy set and shows what would change: "14 operations that were previously ALLOW would become DENY under the proposed policy. 3 of those affect production pipelines in the genomics lab."

Incident response integration

When there's a security incident, the compliance posture is affected. A data breach degrades controls in the 3.1 and 3.13 families. A compromised credential degrades 3.5 controls. Attest should consume incident data (from Security Hub or a dedicated incident management tool) and automatically: degrade affected control posture scores, generate an incident-specific POA&M entry, track remediation progress, and restore posture scores when remediation is confirmed.

The SSP should include an incident history section: "One security incident occurred during the assessment period. Control 3.1.1 was temporarily degraded from 'Implemented' to 'Partially Implemented' for 72 hours. Full enforcement was restored on [date] via [remediation]. Cedar decision log confirms no CUI exposure during the incident window."

Reporting and trend analysis

The dashboard shows current state. What's missing is trend — "Our posture improved from 82% to 88.5% over the last quarter. The remaining gaps are concentrated in the System & Info Integrity family." The CISO wants to show the board a trend line, not a snapshot.

attest report should generate periodic posture reports with trend data, framework-by-framework progress, remediation velocity (how fast gaps are being closed), and comparison across SREs for multi-org deployments.

Let me add the critical missing packages.


Assessed completeness and identified gaps
Assessed completeness and identified gaps
21 files, 5,162 lines. Here's what was missing and why each piece is load-bearing:

Principal attribute resolver — this was the biggest gap. Cedar policies are only as good as the entity attributes they evaluate. principal.cui_training_current has to come from somewhere. The resolver chain maps IAM ARN → human identity → attribute sources (SAML session tags, LDAP, LMS, IRB system, compute allocation system). The plugin interface is the open source piece; connectors for specific institutional systems are community-maintained. Without this, Cedar evaluates nulls and compliance is theater.

Waiver management — compliance without exceptions is fiction. The waiver is a first-class object: time-bounded, scoped, approved, documented. It affects posture scoring ("implemented with exception" not "gap"), SSP narratives (the exception and its compensating controls are documented), Cedar evaluation (waived operations record the waiver ID), and the dashboard (waivers show differently, expiring waivers alert). attest waiver create, attest waiver list --expiring 30d.

Policy testing — three modes. Unit tests define scenarios in YAML ("given this principal with expired CUI training, attempting S3:PutObject → expect DENY") and run locally against cedar-go. Simulation replays real CloudTrail events against a proposed policy set and diffs the results — "14 operations that were ALLOW would become DENY, 3 affect production pipelines." CI/CD checks evaluate a Terraform plan for compliance violations and output GitHub annotations or SARIF so violations appear inline in the PR diff. This is shift-left compliance.

Environment provisioning — "I need a HIPAA environment for clinical genomics" becomes attest provision. Computes the target OU from data classes, checks prerequisites (BAA signed? training current?), presents a plan for approval, executes with rollback on failure. The researcher gets a compliant environment in 20 minutes. They never touch compliance configuration.

What the full attest system looks like now:

Layer	Package	What it does
Ingest	artifact	Reads AWS Artifact API, extracts shared responsibility data
org	Reads AWS Organization topology, inventories existing controls
framework	Loads YAML framework definitions, resolves cross-framework overlap
principal	Sources entity attributes from institutional systems
Compile	compiler/scp	Generates SCPs from framework controls
compiler/cedar	Generates Cedar policies from framework controls
compiler/config	Generates Config rules from framework controls
Enforce	evaluator	Continuous Cedar PDP, EventBridge-driven, Security Hub integration
integrations	12 AWS security service integrations, evidence aggregation
Govern	waiver	Exception management, time-bounded, auditable
testing	Unit tests, simulation, CI/CD Terraform checks
provision	Automated environment creation with compliance by construction
Report	document/ssp	SSP generation from live state
document/oscal	OSCAL export (SSP, AR, POA&M)
Reason	ai	7 Bedrock+Claude capabilities, grounded in system truth
Present	dashboard	Go+HTMX web dashboard, SSE live feed, 5 views
What's still not built but matters for v1:

Git-backed policy store (.attest/ as a git repo, PR-based policy review), IaC output (--output terraform and --output cdk on attest compile), multi-SRE aggregate view (central compliance office across multiple orgs), trend reporting (posture over time, remediation velocity), incident response lifecycle integration (incident → posture degradation → remediation → recovery), and the Bouncing integration for dashboard authn (dog-food your own auth service).

The IaC output and git-backed store are probably the most important for v1 adoption — they meet organizations where they already work.


Attest scaffold.tar
GZ 
Cover those items that matter for a v1

4:21 PM

Synthesized essential v1 requirements and priorities
Synthesized essential v1 requirements and priorities
25 files, 21 packages, 6,938 lines. Here's the final v1 architecture:

attest/
├── cmd/attest/
│   ├── main.go              # CLI: init, scan, compile, apply, generate, watch, diff
│   └── ai.go                # CLI: ask, audit-sim, translate, analyze, impact, remediate
├── frameworks/
│   └── nist-800-171-r2/     # Reference framework definition (YAML)
├── internal/
│   ├── artifact/             # AWS Artifact API ingest
│   ├── auth/                 # Bouncing authn + Cedar authz for dashboard
│   ├── ai/                   # 7 Bedrock+Claude capabilities
│   ├── compiler/scp/         # SCP generation
│   ├── compiler/cedar/       # Cedar policy generation
│   ├── dashboard/            # Go+HTMX web dashboard + SSE + JSON API
│   ├── document/ssp/         # SSP generation from live state
│   ├── document/oscal/       # OSCAL export (SSP, AR, POA&M)
│   ├── evaluator/            # Continuous Cedar PDP + EventBridge
│   ├── framework/            # Framework loader + cross-framework resolution
│   ├── iac/                  # Terraform + CDK output from compiled policies
│   ├── integrations/         # 12 AWS security service integrations
│   ├── org/                  # AWS Organization topology analyzer
│   ├── principal/            # Entity attribute resolver (SAML, LDAP, LMS, IRB)
│   ├── provision/            # Automated environment creation
│   ├── reporting/            # Trend analysis, multi-SRE, incident lifecycle
│   ├── store/                # Git-backed policy store + versioning
│   ├── testing/              # Unit tests, simulation, Terraform CI checks
│   └── waiver/               # Exception management, time-bounded
└── pkg/schema/               # Core types: SRE, Framework, Control, Crosswalk, Posture
What the four new packages solve:

Git-backed store — .attest/ has a defined layout. Every attest compile commits. Every attest apply can tag. attest diff assessment-2025-q1..assessment-2025-q2 shows exactly what changed between audits. Proposed AI artifacts live in .attest/proposed/ until a human accepts them. The git log is the change management record an auditor can independently verify. Rollback is git revert + attest apply.

IaC output — attest compile --output terraform writes a full Terraform module tree: SCPs, Config conformance packs, EventBridge rules wiring CloudTrail to the Cedar PDP, and security service enablement (GuardDuty, Inspector, Macie, Security Hub). --output cdk writes a Python CDK stack (matching your quick-suite convention). Every resource is tagged with managed_by=attest and the specific framework controls it satisfies. This is the critical integration point — organizations deploy through their existing Terraform/CDK pipelines, not through a separate attest apply channel.

Reporting — three dimensions. Trend analysis loads posture snapshots from .attest/history/ (saved after every attest scan) and computes score trajectory, gaps closed/opened, remediation velocity, and milestones. Multi-SRE aggregation queries the dashboard API of each registered SRE and produces a cross-org risk ranking — the central compliance office view. Incident lifecycle tracks security incidents from detection through remediation, automatically degrades affected control postures, and generates the incident history section for SSP inclusion ("1 incident during assessment period, mean time to remediation 72 hours, Cedar decision logs confirm no CUI exposure").

Bouncing auth — the dashboard uses Bouncing for authn (OAuth + passkeys, no passwords) and the same Cedar PDP for authz. Five dashboard roles — admin, compliance_officer, security_engineer, pi_researcher, auditor — are enforced by Cedar policies, not application logic. The PI can only see their own environments. The auditor sees everything but can't deploy. The Cedar policies governing dashboard access are included inline. This dog-foods the full Playground Logic stack: Bouncing for identity, Cedar for authorization, and the same evaluation engine that runs compliance also runs access control.

The complete v1 CLI surface:

attest init                              # Build SRE from existing org
attest scan                              # Evaluate posture, save snapshot
attest frameworks list|add|remove        # Manage active frameworks
attest compile [--output terraform|cdk]  # Generate all policy artifacts
attest apply [--dry-run] [--proposed X]  # Deploy to org (or accept AI proposal)
attest evaluate                          # One-shot Cedar evaluation
attest watch                             # Continuous Cedar PDP
attest serve                             # Launch web dashboard
attest generate ssp|poam|assess|oscal    # Generate compliance documents
attest diff [ref1..ref2]                 # Compare posture between points
attest test                              # Run policy unit tests
attest check --terraform plan.json       # CI/CD compliance gate
attest simulate --proposed ./new-policy  # Replay events against proposed changes
attest provision                         # Create compliant environment
attest waiver create|list|expire         # Manage compliance exceptions
attest report --window 90d              # Generate trend report
attest ai ask|audit-sim|translate|analyze|impact|remediate  # AI capabilities
This is a real product. The open source core (compile, framework definitions, crosswalk, IaC output, testing, git store) gets adoption. The commercial layer (continuous Cedar PDP, dashboard, AI capabilities, multi-SRE, Bouncing auth) gets revenue. The BD pipeline you already have at R1 institutions is the sales channel. The 90-day clock is the strategic constraint — publish the open source core before you leave AWS, let the commercial layer be the Playground Logic launch.


Attest scaffold.tar
GZ 
do you want to update the dashboard or is that already in the tar file

5:04 PM

Recognized dashboard lacked new features and required updating
Recognized dashboard lacked new features and required updating
The dashboard artifact is separate from the tar — and it's missing everything we added: waivers, trend charts, incidents, AI analyst, multi-SRE, auth-aware role display, Terraform/test status, and the provisioning flow. Let me rebuild it.


Synthesized summary for dashboard update inquiry
Synthesized summary for dashboard update inquiry
Dashboard now has all 9 views matching the full v1 architecture. Click through them:

Posture — trend bar chart (6 months of score history), waiver count with expiring-soon warning, heatmap tiles now show blue for waived controls with the waiver ID in the tooltip.

Frameworks — same drill-down, but the control table now shows waived status for controls with active waivers.

Operations — unchanged, this was already complete.

Environments — unchanged.

Waivers — new. Shows each waiver with its control, scope, approver, expiry date (highlighted if expiring soon), and compensating controls. The red dot on the nav item alerts when a waiver is approaching expiry.

Incidents — new. Full incident lifecycle: ID, severity badge, detection/resolution dates, affected controls, and remediation narrative. The SSP narrative is computed at the bottom — "2 incidents, all remediated, Cedar logs confirm no CUI exposure."

Tests & deploy — new. Three sections: proposed artifacts awaiting review (with accept/reject buttons), policy test suite results (green/red dots per suite), and the git store + IaC output status panels showing HEAD commit, last tag, Terraform sync state, and CI/CD deployment status.

Generate — now includes trend report alongside SSP, self-assessment, POA&M, OSCAL, and crosswalk.

AI analyst — new. Interactive chat with the compliance analyst agent. Suggested questions as tappable buttons. The mock response demonstrates the grounding model — every claim cites a specific artifact (posture snapshot, crosswalk entry, waiver ID, test suite name). CLI commands shown at the bottom for the full attest ai surface.

Auth-aware — bottom of the nav shows the logged-in user (Dr. Park), their Cedar-enforced role (compliance_officer), and their auth method (passkey via Bouncing).


Attest dashboard
Code · JSX 

Attest scaffold.tar
GZ 




Claude is AI and can make mistakes. Please double-check responses.
1Password menu is available. Press down arrow to select.
