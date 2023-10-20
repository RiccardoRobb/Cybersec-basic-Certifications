# Network defense Essentials (NDE)

### Information assurance (IA) Principles

**Confidentiality**, **Integrity** and **Availability**.

**Non-repudiation**: A party in a communication cannot deny sending a message.

**Authentication**: The identity of an individual is verified by the service / system.

---

### Administrative security controls

**Regulatory framework compliance**: security controls to manage sensitive data.

**Security policies**: all the internal "laws" that help preventing security errors.

**Employee monitoring and supervising**: monitor access and uses.

**Information classification**: different roles, different information.

**Security awareness and training**: no training = no security.

---

## PROTOCOLS

### RADIUS

Is an **authentication protocol** which provides centralized *authentication*, *authorization* and *accounting* for remote access to communicate with central server.

**Steps:**

1. A client initiates a connection by sending the *access-request packet* to the server

2. The server receives the access request from the client and compares the credentials with ones stored in the db.
   
   - [SUCCESS] server sends *access-accept message* with an *access-challenge*
   
   - [FAIL] server sends *accept-reject*

3. Client sends the *accounting-request* to the server to specify the accounting information for a connection that was accepted.

4. Server sends *accounting-response message* which states the successful establishment of the network.

### TACACS+  (Terminal access controller access control system)

Is a **network security protocol** used for *AAA* of the **network devices**, TACACS+ **encrypts** the entire communication between client and server in order to protect from *sniffing attacks*.

**Steps:**

1. The already authenticated client requests for a resource directly to the TACACS+ server.

2. The server receives the *REQUEST* and prepares the **service shell**

3. *RESPONSE* is sent to the client including *pass* of *fail*

4. The client will be *granted* or *denied*

### KERBEROS

Is an **authenticating method** for accessing the network.

**Steps:**

1. A users sends its credentials to an **authentication server (AS)**

2. The **AS** *hashes* the password of the user and verifies the credentials in the active directory db.
   
   * [SUCCESS] The **AS** consisting of the **ticket granting service (TGS)** *sends back* the TGS *session key* and the **ticket granting ticket (TGT)** to the user, in order to create a *session*

3. Once the user is authenticated, it sends the *TGT* to request a server ticket to the server or *TGS* for accessing the services

4. The *TGS* authenticates the *TGT* and grants a ***service ticket*** to the user, consisting of the **ticket and a session key**

5. The client send the *service ticket* to the server

6. The server uses its key to *decrypt* the information from the *TGS* and the client is authenticated to the server

### PGP (Pretty good privacy)

Is an **application layer protocol** which provides **cryptographic privacy** and authentication for network communications.

It *encrypts* and *decrypts* email communications as well as authenticates messages with **digital signatures** and *encrypts* stored files.

### S/MIME (Secure/Multipurpose internet mail extensions)

Is an application layer protocol which is used for *sending* **digitally signed** and **encrypted email messages**.

It uses **RSA** system to email encryption and network defenders needs to enable S/MIME-based security for mailboxes in their organization.encrypted email messages

### S-HTTP [deprecated]

Is an application layer protocol that is used to **encrypt web communications** carried over HTTP.  

Problem is that we have some not encrypted communications.

### HTTP (Hypertext transfer protocol secure)

Ensures **secure communication** between two computers over HTTP. The connection is *encrypted* using a **transport layer security (TLS)** or rarely **SSL**. Protects against *man-in-the-middle attack* because of the encrypted channel.

### TLS (Transport layer security)

Ensures a *secure communication* between client-server applications, it prevents the network communication from being eavesdropped or tamped.

* **TLS Record Protocol** ensures *connection security* with encryption

* **TLS Handshake Protocol** ensures client and server *authentication*

### SSL (Secure socket layer)

*Manages the security* of a message transmission on the internet, it uses **RSA asymmetric (public key) encryption** to encrypt data transferred over *SSL* connections.

### IPsec (Internet protocol security)

Is a **network layer protocol** that ensures a secure IP level communication. It provides *end-to-end security* at the internet layer of the internet protocol suite.

It **encrypts** and **authenticates** each IP packet communication.

Supports *network-level peer authentication*, data origin authentication, data integrity, data confidentiality (encryption) and *replay protection*.

---

---

## Access Control

The *Access control* is the selective restriction of access to an asset or a system/network resource. It protects the information assets by determining who can access what.

**Components:**

* **subject**, a particular *user* or *process* that access a resource

* **object**, a *specific resource*

* **reference monitor**, *checks* the **access control rule** for specific restrictions

* **operation**, represents an *action* taken by a subject on an object

---

## Principles:

### Separation of Duties [SoD]

The authorization process is divided in steps, different privileges are assigned at each step to the individual subjects requesting for a resource.

Ensures that no single individual has the authorization rights to perform all functions and simultaneously denies access of all the objects to a single individual.

### Need-to-know

Access is provided only to the information that is required for performing a specific task.

### Principle of Least Privilege [POLP]

Extends the *need-to-know* principle providing only needed rights for each user.

---

## Access Control Models

Are the standards which provide a predefined framework for implementing the necessary level of access control.

### Mandatory Access Control [MAC]

Only the **Admin/Sys owner** has the rights to *assign privileges*, the end user cannot decide who can access the information.

### Discretionary Access Control [DAC]

End user has complete access to the information they **own**

### Role-based Access Control [RBAC]

Permission are assigned based on **user roles**

### Rule-based Access Control [RB-RBAC]

**Permissions are assigned to a user role** dynamically based on a set of rules defined by the administrator

---

### Logical implementation

Is performed using **access control lists (ACLs)**, **group policies**, passwords and account restrictions.

---

## Identity and Access Management [IAM]

Is responsible for providing the **right individual with right access at the right time**

![IAM](IAM.png)

* **Identity Management [IDM]**
  
  User identification involves a method to ensure that *individual holds a valid identity*. Identity management involves **storing** user attributes in their **repositories**.

* **Identity Repositories**
  
  The user repository is a db where attributes related to users' identities are stored.

---

## Authorization systems

### Centralized

It maintains a **single db**  for authorizing all the network resources or applications.

### Decentralized

Each network resource maintains its **authorization unit** and performs authorization locally. It maintains its own **db**

### Implicit

Users can access the required resource **on behalf** of others. The access request goes through a primary resource to access the requested resource.

### Explicit

Requires **separate authorization** for each requested resource, it maintains authorization for each *requested* object.

---

---

## Administrator controls

### Regulatory frameworks compliance

It is often required for the organization to comply with some type of *security regulation*, it is a collaborative effort between governments and privates.

IT security regulatory frameworks contain a set of **guidelines** and **best practices**.

**Why organizations need compliance?**

* **improves security**
  
  IT security *regulation* and *standards* improve overall security by meeting regulatory requirements

* **Minimize losses**
  
  Improved security, in turn, *prevents* security breaches

* **Maintain trust**
  
  Customer trusts the organization in belief that their information is *safe*

---

![](frameworks.png)

Based on those regulatory requirements (interpreted from the regulatory framework), an organization needs to establish *policies*, *procedures* and *security controls* to manage and maintain compliance.

---

## Payment Card Industry Data Security standard [PCI-DSS]

Is a proprietary **information security standard for organizations** that handle cardholder information. **PCI-DSS** applies to *all entities involved in payment card processing*.

* **Build and Maintain a Secure Network**

* **Maintain a Vulnerability Management Program**

* **Regulatory Monitor and test networks**

* **Protect Cardholder Data**

* **Implement Strong Access Control Measures**

* **Maintain an information Security Policy**

## Health Insurance Portability and Accountability Act [HIPAA]

* **Electronic transaction and code set standards**
  
  Every provider must use *the same health care transactions, code sets and identifiers*

* **Privacy rule**
  
  *Federal protections for the personal health information*

* **Security role**
  
  Safeguards to ensure the *confidentiality, integrity and availability of electronically protected health information*

* **National identifier requirements**
  
  Every employee must have *national numbers that identify them attached to standard transactions*

* **Enforcement rule**
  
  Standards for enforcing all the *Administration Simplification Rules*

---

## [!!!] SARBANES OXLEY ACT [SOX]

It is designed to **protect investors and the public** by increasing the accuracy and reliability of the corporate disclosure

* **TITLE 1**
  
  **Public Company Accounting oversight board [PCAOB]** provides independent oversight of public accounting firms providing *audit services* **(auditors)**

* **TITLE 2**
  
  **Auditor independence**

* **TITLE 3**
  
  **Corporate responsibility** mandates that every senior executives take individual responsibility for the accuracy and completeness of corporate financial reports

* **TITLE 4**
  
  **Enhanced financial disclosures** describe enhanced reporting requirements for financial transactions, including off-balance-sheet transactions ...

* **TITLE 5**
  
  **Analyst conflicts of interest**, more confidence in the reporting of securities analysts

* **TITLE 6**
  
  **Commission resources and authority**

* **TITLE 7**
  
  **Studies and Reports**, credit rating agencies ...

* **TITLE 8**
  
  **Corporate and Criminal fraud accountability**, description of specific criminal penalties for fraud ...

* **TITLE 9**
  
  **Corporate tax return**

* **TITLE 10**
  
  **White collar crime penalty enhancement**

* **TITLE 11**
  
  **Corporate fraud accountability**

* **... 10 titles left ...**

---

## GRAMM-LEACH-BLILEY ACT [GLBA]

It has the objective to ease the transfer of *financial information* between institutions and banks

---

## GENERAL DATA PROTECTION REGULATION [GDPR]

It is used against those who violates its privacy and security standards

---

## DATA PROTECTION ACT [DPA]

It is an act to make provision for the regulation of the processing of information relating to *individuals*.

Individuals have the right:

* data submitted must be processed lawfullly

* get information about how the data are processed

* give the holder of that office responsibilities

---

## Information Security Standards [ISO]

![](ISO.png)

---

## Digital Millennium Copyright Act [DMCA]

It defines the *legal prohibitions* against the circumvention of technological protection measures employed by copyright owners to protect their works

---

## Federal Information Security Management Act [FISMA]

It provides a comprehensive framework for ensuring the *effectiveness of information security controls* over information resources that supports Federal operations and assets

* **standards for categorizing information**

* **standards for minimum security requirements**

* **guidance for selecting appropriate security controls**

* **guidance for assessing security controls**

* **guidance for security authorization of information systems**

---

---

# Security Policy

It is a **well documented set of plans, processes, procedures, standards and guidelines** to establish an ideal information security status of an organization.

Security policies are used to inform people on how to work in a safe and secure manner.

* **Enhanced Data and Network security**

* **Risk mitigation**

* **Better network performance**

* **Quick Response to issues**

* **Monitored and Controlled device usage and data transfers**

## Contents of security policy

### High-level security requirements

The requirements of a system when implementing security policies that include discipline security, safeguard security, procedural security and assurance security

### Policy description based on requirements

### Security concept of operation

Defines the **roles**, **responsibilities** and **functions** of a security policy

### Allocation of security enforcement

Provides a computer system **architecture allocation** to each system in the program

## Types of Information Security Policies

### Enterprise information security policies [EISP]

It drives an organization's scope and provides direction to their security policies

* Application policy

* Network and network devices security policies

* Back up and restore policy

* System security policy

### Issue specific security policies [ISSP]

It directs the audience on the usage of technology-based systems with the help of *guidelines*

* Remote access and wireless policies

* Incident response plan

* Password policies

* Policies for personal devices

### System specific security policies [SSSP]

It directs users while *configuring or maintaining* a system

* DMZ policy

* Encryption policy

* Policies for intrusion detection and prevention

* Access control policy

# Internet Access Policies

## Promiscuous Policy

No restrictions on internet/remote access **(NOTHING IS BLOCKED)**

## Permissive Policy

Known dangerous services/attacks blocked **(KNOWN THREATS BLOCKED)**

## Paranoid Policy

Everything is blocked, no internet connection or severely limited internet usage **(EVERYTHING IS BLOCKED)**

## Prudent Policy

Provides maximum security while allowing known, but necessary, dangers. All services are blocked, except for the *safe or necessary* ones **(EVERYTHING BLOCKED EXCEPT FOR)**

---

## Password Policy

It provides guidelines for using strong passwords for an organization's resources

1. Password length and formation

2. Complexity of password

3. Password blacklists

4. Password duration

5. Common password practice

---

---

# Physical controls

A successful unauthorized physical access may lead to *theft*, *damage* or *modification* of the information system. Physical security is the basis of any *information system program*   in an organization. It allows to restrict unauthorized physical access to the organization or directly to the network.

### Common attack vectors

* **Natural/Environmental Threats**

* **Man-made Threats**

## Types of physical security controls

### Preventive controls

Prevent *security violation* and enforce various access control mechanisms.

[door locks, security guards ...]

### Detective controls

Detect security violations and *record any intrusion attempts*.

[motion detectors, cameras, sensors ...]

### Deterrent controls

Used to discourage attackers and *send warning messages* to the attackers to discourage intrusion attempts.

[warning signs, ... "I will add also in-software detection routines" ...]

### Recovery controls

Used to recover from security violations and *restore information and systems* to a persistent state.

[disaster recovery, backups ...]

### Compensating controls

Used as an alternative control when the *intended controls failed* or *cannot be used*.

[hot sites, backup power systems ...]

---

## Location considerations

* **Visibility of the assets**
  
  *"No servers must be visible from outside"*

* **Neighboring buildings**
  
  *"Better not to have bad actors nearby"*

* **Local considerations**

* **Impact of catastrophic events**
  
  *"Don't stay on active volcano"*

* **Joint tenancy risks**
  
  *"In the 3° floor there is a strange organization; What kind of customers they bring in?"*

---

## Site architecture considerations

You need to consider what kind of rooms do you need in order to keep data and services up and secure, but also people must be secure.

[emergency exits, separate locations for critical systems, plans for environment hazards, sanitation systems ...]

---

## Physical Security policy

Allows to *define guidelines* to ensure that adequate physical security measures are in place. Can be everything relate with physical part of an organization, for example the lighting system.

In the context of environmental threats, we can also think about **heat** and **electromagnetic interference**, which are two of the most important things to consider for proper infrastructure defense.

![](phyChecklist.png)

---

---

# Network segmentation

it is the practice of **splitting** a network in smaller network segments and separating groups of systems or applications from each other.

Groups of systems or applications that have no interaction with each other will be placed in different network segments.

**+** Improved security

**+** Better access control

**+** Improved monitoring

**+** better containment

*It is the inverse of a Flat network (no segmentation)*

## Physical segmentation

![](phy_seg.png)

Splitting a large network into smaller physical components, each segment can communicate via *intermediary devices* such as switches, hubs or routers.

It is expensive, it requires a good configuration (each segment requires components and dedicated router network interfaces)

## Logical segmentation

![](log_seg.png)

Based on **VLANs**, which are *isolated logically* without considering the physical locations of devices. Each VLAN is an independent logical unit and devices of the VLAN communicate as though they are in their own isolated network.

Firewalls are shared and switches handle the VLAN infrastructure.

It is flexible to implement and to operate.

## Network virtualization

![](virt_seg.png)

It is a process of *combining* all the available network resources and enabling security professionals to share these resources among the network users using a **single administrative unit**. 

Network virtualization enables each user to access available network resources from their system.

# Firewalls

![](firewall.png)

A **Bastion host** is a computer system designed and configured to *protect network resources* from attacks; it is the only host computer on the internet that can be **addressed directly from the public network**.

It provides a limited range of services such as website hosting and mail to ensure security. 

*The bastion host has one interface for the internet and one for the network, basically we can think Windows Defender as a bastion host*

The Bastion must:

+ Minimize the chances of penetration by intruders

+ Create **logs** in order to identify attack or attempts of attack

+ In case of attack, bastion host must act as **scapegoat**

+ Provide an additional level of security

### Positioning of the Bastion Host

* **Physical location**
  
  Must be placed in a specially selected server room with *suitable environmental controls*, in a locked server cabinet with proper ventilation, cooling and backup power.

* **Network location**
  
  Set on a special network also known as **Demilitarized Zone [DMZ]** that **does not carry sensitive data**. Cannot be placed on internal networks, should be located on an addition layer know as **perimeter network**.
  
  *We can attach a* `packet filtering routing` *in order to track packets*

## DMZ Network

It is a computer sub-network that is placed between the organization's private network such as a **LAN** and an outside public network such as the **internet**.

Contains the servers that need to be accessed from an outside network.

Both **internal** and **external** networks can connect to the DMZ, hosts in the DMZ **cannot connect to internal networks** but can connect to external networks.

### Single Firewall DMZ

The network architecture consists of **three network interfaces**.

The *First* interface connects the ISP to the firewall (external network), the *Second* interface forms the internal network, and the *Third* interface forms the DMZ.

### Dual Firewall DMZ

There are *2* firewalls, the *First firewall* allows only **sanitized traffic** to enter the DMZ (packets for exposed services), and the *Second firewall* conducts a double check on it.

*It is the most secure approach*

## Types of Firewalls

### Hardware firewall

It is a dedicated **stand-alone hardware device or part of the router** that *filters* the network traffic using some *packet filtering technique*. It is used to filter out the network traffic for large business networks.

* **Network-based firewall**
  
  It is used to *filter inbound / outbound traffic* from **internal LAN**

### Software firewall

It is a **software program** installed on a computer; It filters traffic for individual home users.

* **Host-based firewall**
  
  It is used to *filter inbound / outbound traffic* of an **individual computer** in which it is *installed*

## Firewall technologies

![](firewall_tech.png)

### Packet Filtering firewalls

Work at the **network level (OSI) / IP level (TCP/IP)**, they are usually part of a router.

Each packet is compared with a *set of criteria* before it is forwarded; traffic is filtered base on **specific rules**, for example source, destination IP addresses.

### Circuit level Gateways

Work at the **session level (OSI) / TCP layer (TCP/IP)**, they *monitor TCP handshakes* between packets to determine whether a *request session is legitimate or not*.

Information passed to a remote computer appears to have originated from the gateway.

Traffic is filtered on **specific session rules**.

### Application level Gateways

Can filter packets at the **application level**, they can filter *application-specific command* such as *http:post* and *get* or *specific protocols*. We can decide to filter the traffic based on rules about protocols or commands.

### Stateful Multilayer inspection firewalls

**Combines the aspects of the previously described technologies.**

They are expensive, because they require competent personnel that have to administrate the device used for filter the traffic at *three levels*; Filter based on a wide range of specified applications, sessions and / or filtering rules.

### Application Proxy

Works as a proxy server and **filters connections** for specific services; It filters connections based on **services** and **protocols**.

*A DNS proxy will only allow DNS traffic to pass through.*

---

# Next Generation Firewall

It is a **third-generation firewall technology** that moves beyond *port / protocol inspection*, can inspect traffic based on **packet content**.

## Technologies

### Network Address translation [NAT]

It separates IP addresses into *two sets* and enables the LAN to use these addresses for *internal* and *external traffic*. NAT will modify the packets the router sends.

Distinction between **private IP address** and **public IP address**, the *first* refers to the actual IP used from a host in the network; the *second* refers to the external IP address from which communications start;

- private IP are mapped to public IP

*It limits the number of public IP addresses* **(increase security = less hosts visible)**

### Virtual Private Network [VPN]

It is a **private network** constructed using public networks; It is used for the *secure transmission* of sensitive information over an untrusted network.

It is based on **encapsulation** and **encryption**, in order to create *dedicated connections* using a VPN tunnel in which communication is encrypted.

---

### Firewalls don't

* prevent the network from **backdoor attacks**

* protect the network from **insider attacks**

* do anything if the network design and configuration is faulty

* be an alternative to **antivirus** or **antimalware**

* prevent **new viruses**

* prevent **social engineering threats**

* prevent **passwords misuse**

* block attacks from higher level of protocol stack

### Secure Firewall implementation

* filter **unused** and common **vulnerable** ports

* create a **unique user ID** to run the firewall service (not root or admin)

* **deny all** and allow only the services required

* change all default passwords

* **limit running applications** in order to enhance the performances

* configure a **remote syslog server**

* monitor **firewall logs**

* investigate **suspicious log**

---

## Firewall implementation and deployment

* **PLANNING**
  
  Organizations must *plan* their **positioning** in advance

* **CONFIGURING**
  
  Hardware, software, **policy configuration**, implementing **logging** and **alerting** mechanisms

* **TESTING**
  
  Check if the **firewall rules** are set according to the actions performed by the firewall

* **DEPLOYING**
  
  A phased approach to deploy multiple firewalls on a network helps detect and *resolve issues* regarding **conflicting policies**

* **MANAGING AND MAINTAINING**
  
  Firewall **architecture**, **policies**, software and other components deployed on the network must be maintaining

---

# Host-based Firewall protection

## Iptables

It is a built-in firewall utility for *Linux OS*.

* **Filter non TCP packets**
  
  `iptables -A INPUT -p tcp ! --syn m state --state NEW -j DROP`

* **Blocking XMAS scan attack**
  
  *"Send XMAS packets during port scanning, in order to detect open ports"*
  
  `iptables -A INPUT -p tcp --tcp-flags ALL -j DROP`

* **Drop any NULL packets**
  
  `iptables -A INPUT -f -j DROP`

* **Drop any fragmented packets**
  
  `iptables -A INPUT -f -j DROP`

* **List existing rules**
  
  `iptables -L -n -v`

* **Block specific IP**
  
  `iptables -A INPUT -s <IP-ADDR> -j DROP`

---

---

# Intrusion Detection and Prevention System [IDS / IPS]

It is a *network security appliance* that **inspects all inbound and outbound traffic** for suspicious patterns that might indicate a network or system security breach.

If any pattern is recognized, the IDS will **alert** the administrator.

IDS checks the network traffic for **signatures** that match *known intrusion patterns* and triggers an alarm.

![](IDs.png)

**IDS** works from *inside the network* (behind the firewall) != firewall that looks outside the network.

## Signature recognition

Also known as misuse detection, tries to *identify events* that indicate an abuse of a system or network resource.

This method uses *string comparison* operations to compare **ongoing activity** and looks for matches with the known signatures.

**+** Less false alarms

**+** Fast

**-** Detects only known threats

**-** Cannot detect variants of known threats

---

## Anomaly detection

It detects the intrusion based on *fixed behavioral characteristics* of the users and components in a computer system

This method monitors the typical activity for a particular time interval and then builds the **statistics fro the network traffic** (bandwidth usage, failed logon attempts, processor utilization ...)

**+** Identifies abnormal behavior

**+** Information acquired are used to *define the signatures for Signature detection*

**-** More false alarms

**-** Build up an extensive set of system events in order to characterize normal behavior patterns

---

## Approach-based / Stateful protocol detection

*Compares observed events* with predetermined profiles based on accepted definition of **benign activity for each protocol** to identify any **deviations** of the protocol state.

Variances in command length, min max values for attributes and other anomalies; for any protocol performing authentication, IDS/IPS will keep track of the *authenticator* being used for each session.

**+** Can identify strange sequence of commands

---

---

## Protection-based IDS

![](protection_IDS.png)

* **Network intrusion detection system [NIDS]**
  
  It protects the network **+ low false-positive rate**

* **Host intrusion detection system [HIDS]**
  
  It protects the host **+ anomaly-based detection**

* **Hybrid intrusion detection system [Hybrid IDS]**
  
  It protects the network and the host

---

## Structure-based IDS

* **Centralized IDS**
  
  Data are shipped to a *central location* for analysis

* **Decentralized IDS**
  
  Several IDS are *deployed* over a large network and each IDS communicates with each other for traffic analysis

---

## Analysis Timing-based IDS

Analysis time is a **span of time elapsed** between the events occurring and the analysis of those events

* **Interval-based IDS**
  
  The *information about an intrusion* is **stored and forwarded**, it performs analysis on the detected intrusion *offline*

* **Real-Time-based IDS**
  
  The *information about an intrusion* **flows continuously** from monitoring points to analysis engines. The analysis on the detected intrusion is performed *on the fly*

---

## Source Data analysis-based IDS

An IDS uses data and sources such as **audit trail** and network packets to detect intrusions

* **Intrusion detection using Audit Trails**
  
  Audit trails help the IDS detect *performance problems, security violations and flaws in applications*

* **Intrusion detection using Network Packets**
  
  Capturing and Analyzing network packets help an IDS detect *well-known attacks*

---

---

## Intrusion indicators

### File System intrusions

The presence of *new* or *unfamiliar* files or programs; Unexplained *changes* in a file's size or permissions. Missing files or *rogue* files that do not correspond to the master list of signed files.

### Network intrusions

Connections from *unusual locations* and repeated *login attempts*; Repeated probes of available services on the machine and a sudden *influx of log data*.

### System intrusion

*Incomplete*, *Missing* or with *incorrect permissions* or *ownership* logs; Unfamiliar processes or slow system performance; Strange modifications to system software and configuration files.

---

### Active IDS

**DETECTS**  and **RESPONDS** to detected intrusions

### Passive IDS

**DETECTS** intrusions

---

---

## IDS Components

![](IDS_components.png)

### Network sensors

Are **HW** or **SW** components that **monitor traffic** and **trigger alarms** if any abnormal activity is detected. Network sensors should be placed and located at *common entry points*.

*"Gateways, between LANs, VPNs, sides of firewall and remote access servers"*

### Alert systems

Sends an **alert message** when an anomaly or misuse is detected.

### Command console (Sguil)

It runs on a *separate system* that is dedicated to the IDS.

It provides a user interface to an administrator for the purpose of *receiving* and *analyzing* security events, alert messages and log files. It **evaluates security events** from different security devices.

*"Must be installed on a **dedicated** computer system!"*

### Response system

Issues countermeasures against any intrusion that is detected.

You also need to be involved in the decision during incident response and should have the ability to respond on your own. You have to make decisions on how to deal with *false positives* and when a response needs escalation.

### Attack signatures database

**IDS does not make decisions** but maintain a database of attack signatures and patterns. Network traffic is compared against these known attack signatures.

**IDS will raise alert and block the traffic** if there is a match.

---

---

# Intrusion detection Tools

## Snort

It is a *network intrusion detection system*, capable of performing real-time **traffic analysis and packet logging on IP networks**.

`snort`

It is used to detect various attacks and probes such as buffer overflows, stealth port scans and OS fingerprinting attempts.

## Suricata

It is a robust *network threat detection engine* capable of **real-time IDS**, **inline IPS**, **network security monitoring** and **offline pcap processing** (*we can pass wireshark files to be processed*).

---

---


