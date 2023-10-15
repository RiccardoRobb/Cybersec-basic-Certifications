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

-

### TACACS+  (Terminal access controller access control system)

Is a **network security protocol** used for *AAA* of the **network devices**, TACACS+ **encrypts** the entire communication between client and server in order to protect from *sniffing attacks*.

**Steps:**

1. The already authenticated client requests for a resource directly to the TACACS+ server.

2. The server receives the *REQUEST* and prepares the **service shell**

3. *RESPONSE* is sent to the client including *pass* of *fail*

4. The client will be *granted* or *denied*

-

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

-

### PGP (Pretty good privacy)

Is an **application layer protocol** which provides **cryptographic privacy** and authentication for network communications.

It *encrypts* and *decrypts* email communications as well as authenticates messages with **digital signatures** and *encrypts* stored files.

-

### S/MIME (Secure/Multipurpose internet mail extensions)

Is an application layer protocol which is used for *sending* **digitally signed** and **encrypted email messages**.

It uses **RSA** system to email encryption and network defenders needs to enable S/MIME-based security for mailboxes in their organization.encrypted email messages

-

### S-HTTP [deprecated]

Is an application layer protocol that is used to **encrypt web communications** carried over HTTP.  

Problem is that we have some not encrypted communications.

-

### HTTP (Hypertext transfer protocol secure)

Ensures **secure communication** between two computers over HTTP. The connection is *encrypted* using a **transport layer security (TLS)** or rarely **SSL**. Protects against *man-in-the-middle attack* because of the encrypted channel.

-

### TLS (Transport layer security)

Ensures a *secure communication* between client-server applications, it prevents the network communication from being eavesdropped or tamped.

* **TLS Record Protocol** ensures *connection security* with encryption

* **TLS Handshake Protocol** ensures client and server *authentication*

-

### SSL (Secure socket layer)

*Manages the security* of a message transmission on the internet, it uses **RSA asymmetric (public key) encryption** to encrypt data transferred over *SSL* connections.

-

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

-

### Need-to-know

Access is provided only to the information that is required for performing a specific task.

-

### Principle of Least Privilege [POLP]

Extends the *need-to-know* principle providing only needed rights for each user.

---

## Access Control Models

Are the standards which provide a predefined framework for implementing the necessary level of access control.

-

### Mandatory Access Control [MAC]

Only the **Admin/Sys owner** has the rights to *assign privileges*, the end user cannot decide who can access the information.

-

### Discretionary Access Control [DAC]

End user has complete access to the information they **own**

-

### Role-based Access Control [RBAC]

Permission are assigned based on **user roles**

-

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

-

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

-

In the context of environmental threats, we can also think about **heat** and **electromagnetic interference**, which are two of the most important things to consider for proper infrastructure defense.

-

![](phyChecklist.png)

---

---




























































