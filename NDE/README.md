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


