# GoCircum System Architecture Diagrams

## 1. Overall System Architecture

```mermaid
graph TB
    subgraph "Client Applications"
        CLI[CLI Application]
        Mobile[Mobile App]
        Browser[Browser/App via SOCKS5]
    end
    
    subgraph "GoCircum Core"
        Engine[Core Engine]
        Config[Configuration Manager]
        Proxy[SOCKS5 Proxy Server]
        Ranker[Strategy Ranker]
        Bootstrap[Bootstrap Manager]
    end
    
    subgraph "Transport Layer"
        TCP[TCP Transport]
        QUIC[QUIC Transport]
        Fragment[Fragmentation Layer]
        TLS[uTLS Implementation]
    end
    
    subgraph "Network Protocols"
        DoH[DNS over HTTPS]
        DomainFront[Domain Fronting]
        TrafficShape[Traffic Shaping]
    end
    
    subgraph "Discovery Mechanisms"
        DGA[Domain Generation Algorithm]
        Stego[Steganographic Discovery]
        P2P[Peer-to-Peer Discovery]
        Social[Social Media Discovery]
    end
    
    subgraph "External Services"
        CDN[CDN/Cloud Providers]
        DoHProviders[DoH Providers]
        TargetServers[Target Servers]
    end
    
    CLI --> Engine
    Mobile --> |Bridge| Engine
    Browser --> Proxy
    
    Engine --> Config
    Engine --> Proxy
    Engine --> Ranker
    Engine --> Bootstrap
    
    Proxy --> TCP
    Proxy --> QUIC
    TCP --> Fragment
    QUIC --> Fragment
    Fragment --> TLS
    
    TLS --> DoH
    TLS --> DomainFront
    TLS --> TrafficShape
    
    Bootstrap --> DGA
    Bootstrap --> Stego
    Bootstrap --> P2P
    Bootstrap --> Social
    
    DomainFront --> CDN
    DoH --> DoHProviders
    CDN --> TargetServers
    
    style Engine fill:#ff9999
    style Proxy fill:#99ccff
    style Bootstrap fill:#99ff99
    style DomainFront fill:#ffcc99
```

## 2. Component Interaction Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Engine
    participant Config
    participant Bootstrap
    participant Ranker
    participant Proxy
    participant Transport
    
    User->>CLI: Start with config file
    CLI->>Engine: NewEngine(config)
    Engine->>Config: LoadFileConfig()
    Config-->>Engine: Validated config
    
    Engine->>Bootstrap: Initialize providers
    Bootstrap-->>Engine: Bootstrap manager ready
    
    Engine->>Ranker: NewRanker(dohProviders)
    Ranker-->>Engine: Ranker instance
    
    User->>CLI: Start proxy
    CLI->>Engine: GetBestStrategy()
    Engine->>Ranker: TestAndRank(strategies)
    
    loop For each strategy
        Ranker->>Transport: Test connection
        Transport-->>Ranker: Success/failure + latency
    end
    
    Ranker-->>Engine: Best strategy
    Engine->>Proxy: StartProxyWithStrategy()
    Proxy-->>Engine: Proxy address
    Engine-->>CLI: Proxy running
    CLI-->>User: Proxy ready at address
```

## 3. SOCKS5 Proxy Connection Flow

```mermaid
sequenceDiagram
    participant Client
    participant SOCKS5
    participant DoH
    participant DomainFront
    participant CDN
    participant Target
    
    Client->>SOCKS5: CONNECT target.com:443
    SOCKS5->>DoH: Resolve front domain
    DoH-->>SOCKS5: Front domain IP
    
    SOCKS5->>DomainFront: Create fronted connection
    Note over DomainFront: SNI: front.cdn.com<br/>Host: target.com
    
    DomainFront->>CDN: TLS handshake (SNI: front.cdn.com)
    CDN-->>DomainFront: TLS established
    
    DomainFront->>CDN: HTTP CONNECT target.com:443<br/>(encrypted in TLS)
    CDN->>Target: Forward connection
    Target-->>CDN: Connection established
    CDN-->>DomainFront: HTTP 200 OK
    
    DomainFront-->>SOCKS5: Tunnel established
    SOCKS5-->>Client: SOCKS5 success
    
    loop Data transfer
        Client->>SOCKS5: Application data
        SOCKS5->>DomainFront: Obfuscated data
        DomainFront->>CDN: Encrypted data
        CDN->>Target: Data
        Target-->>CDN: Response
        CDN-->>DomainFront: Encrypted response
        DomainFront-->>SOCKS5: Deobfuscated response
        SOCKS5-->>Client: Response data
    end
```

## 4. Bootstrap Discovery Architecture

```mermaid
graph TB
    subgraph "Bootstrap Manager"
        BM[Bootstrap Manager]
        Cache[Provider Cache]
        Health[Health Checker]
    end
    
    subgraph "Discovery Channels"
        DoH_Discovery[DoH Discovery]
        DGA_Gen[DGA Generator]
        Stego_Discovery[Steganographic Discovery]
        P2P_Discovery[P2P Discovery]
        WellKnown[Well-Known Endpoints]
    end
    
    subgraph "Entropy Sources"
        SystemRand[System Random]
        NetworkTime[Network Timing]
        UserBehavior[User Behavior]
        HardwareRNG[Hardware RNG]
    end
    
    subgraph "External Sources"
        Twitter[Twitter/Social Media]
        GitHub[GitHub Repositories]
        Blockchain[Blockchain Networks]
        DHT[Distributed Hash Table]
        DoH_Providers[DoH Provider Pool]
    end
    
    subgraph "Validation & Health"
        Validator[Address Validator]
        HealthTest[Health Test]
        Reputation[Reputation Check]
        Blacklist[Blacklist Filter]
    end
    
    BM --> DoH_Discovery
    BM --> DGA_Gen
    BM --> Stego_Discovery
    BM --> P2P_Discovery
    BM --> WellKnown
    
    DGA_Gen --> SystemRand
    DGA_Gen --> NetworkTime
    DGA_Gen --> UserBehavior
    DGA_Gen --> HardwareRNG
    
    Stego_Discovery --> Twitter
    Stego_Discovery --> GitHub
    P2P_Discovery --> Blockchain
    P2P_Discovery --> DHT
    DoH_Discovery --> DoH_Providers
    
    DoH_Discovery --> Validator
    DGA_Gen --> Validator
    Stego_Discovery --> Validator
    P2P_Discovery --> Validator
    WellKnown --> Validator
    
    Validator --> HealthTest
    Validator --> Reputation
    Validator --> Blacklist
    
    HealthTest --> Cache
    Cache --> Health
    Health --> BM
    
    style BM fill:#ff9999
    style DGA_Gen fill:#99ccff
    style Validator fill:#99ff99
```

## 5. DNS Resolution Flow with DoH

```mermaid
sequenceDiagram
    participant App
    participant DNSBlocker
    participant DoHResolver
    participant Provider1
    participant Provider2
    participant Provider3
    participant DecoyGen
    
    App->>DNSBlocker: Resolve domain.com
    DNSBlocker->>DNSBlocker: Block system DNS
    DNSBlocker->>DoHResolver: Use DoH only
    
    DoHResolver->>DoHResolver: Get shuffled providers
    
    par Parallel DoH queries
        DoHResolver->>Provider1: DNS-over-HTTPS query
        Provider1-->>DoHResolver: A record response
    and
        DoHResolver->>Provider2: DNS-over-HTTPS query  
        Provider2-->>DoHResolver: A record response
    and
        DoHResolver->>Provider3: DNS-over-HTTPS query
        Provider3-->>DoHResolver: A record response
    end
    
    DoHResolver->>DoHResolver: Validate responses
    DoHResolver->>DecoyGen: Generate decoy queries
    
    loop Decoy traffic
        DecoyGen->>Provider1: Decoy query (random domain)
        DecoyGen->>Provider2: Decoy query (random domain)
    end
    
    DoHResolver-->>App: Resolved IP address
    
    Note over DNSBlocker: System DNS permanently blocked<br/>All queries use DoH
    Note over DecoyGen: Continuous decoy traffic<br/>to mask real queries
```

## 6. Strategy Testing and Ranking Flow

```mermaid
flowchart TD
    Start([Start Strategy Testing]) --> LoadStrategies[Load Fingerprint Strategies]
    LoadStrategies --> GeneratePlan[Generate Organic Test Plan]
    
    GeneratePlan --> BrowsingSession{Create Browsing Sessions}
    BrowsingSession --> Session1[Session 1: Business Hours]
    BrowsingSession --> Session2[Session 2: Evening Entertainment]
    BrowsingSession --> Session3[Session 3: Casual Browsing]
    
    Session1 --> EmbedTests1[Embed Strategy Tests in Normal Traffic]
    Session2 --> EmbedTests2[Embed Strategy Tests in Normal Traffic]
    Session3 --> EmbedTests3[Embed Strategy Tests in Normal Traffic]
    
    EmbedTests1 --> PreActivity1[Generate Pre-Request Activity]
    EmbedTests2 --> PreActivity2[Generate Pre-Request Activity]
    EmbedTests3 --> PreActivity3[Generate Pre-Request Activity]
    
    PreActivity1 --> TestStrategy1[Perform Disguised Strategy Test]
    PreActivity2 --> TestStrategy2[Perform Disguised Strategy Test]
    PreActivity3 --> TestStrategy3[Perform Disguised Strategy Test]
    
    TestStrategy1 --> PostActivity1[Generate Post-Request Activity]
    TestStrategy2 --> PostActivity2[Generate Post-Request Activity]
    TestStrategy3 --> PostActivity3[Generate Post-Request Activity]
    
    PostActivity1 --> CollectResults[Collect Test Results]
    PostActivity2 --> CollectResults
    PostActivity3 --> CollectResults
    
    CollectResults --> RankResults[Rank by Success + Latency]
    RankResults --> ReturnBest[Return Best Strategy]
    ReturnBest --> End([End])
    
    style Start fill:#99ff99
    style GeneratePlan fill:#ffcc99
    style CollectResults fill:#99ccff
    style End fill:#ff9999
```

## 7. Traffic Obfuscation and Fragmentation

```mermaid
graph TB
    subgraph "Application Data"
        AppData[Application Data<br/>HTTP/HTTPS Traffic]
    end
    
    subgraph "Traffic Analysis"
        NetworkAnalysis[Real-time Network Analysis]
        MLClassifier[ML Traffic Classifier]
        ProfileSelector[Target Profile Selector]
    end
    
    subgraph "Traffic Profiles"
        WebBrowsing[Web Browsing Profile]
        VideoStreaming[Video Streaming Profile]
        Gaming[Gaming Profile]
        VoIP[VoIP Profile]
    end
    
    subgraph "Pattern Generation"
        MarkovChain[Markov Chain Generator]
        StatisticalModel[Statistical Model]
        EntropySource[Cryptographic Entropy]
    end
    
    subgraph "Fragmentation Layer"
        PacketFragmenter[Packet Fragmenter]
        DelayInjector[Delay Injector]
        DecoyGenerator[Decoy Traffic Generator]
    end
    
    subgraph "Transport Layer"
        TCPTransport[TCP Transport]
        QUICTransport[QUIC Transport]
        TLSLayer[uTLS Layer]
    end
    
    subgraph "Network Output"
        ObfuscatedTraffic[Statistically Indistinguishable<br/>Network Traffic]
    end
    
    AppData --> NetworkAnalysis
    NetworkAnalysis --> MLClassifier
    MLClassifier --> ProfileSelector
    
    ProfileSelector --> WebBrowsing
    ProfileSelector --> VideoStreaming
    ProfileSelector --> Gaming
    ProfileSelector --> VoIP
    
    WebBrowsing --> MarkovChain
    VideoStreaming --> MarkovChain
    Gaming --> MarkovChain
    VoIP --> MarkovChain
    
    MarkovChain --> StatisticalModel
    EntropySource --> StatisticalModel
    StatisticalModel --> PacketFragmenter
    
    PacketFragmenter --> DelayInjector
    DelayInjector --> DecoyGenerator
    
    DecoyGenerator --> TCPTransport
    DecoyGenerator --> QUICTransport
    TCPTransport --> TLSLayer
    QUICTransport --> TLSLayer
    
    TLSLayer --> ObfuscatedTraffic
    
    style NetworkAnalysis fill:#ff9999
    style MarkovChain fill:#99ccff
    style PacketFragmenter fill:#99ff99
    style ObfuscatedTraffic fill:#ffcc99
```

## 8. Configuration Loading and Validation

```mermaid
flowchart TD
    ConfigFile[Configuration File<br/>strategies.yaml] --> LoadFile[Load File Content]
    LoadFile --> CheckEncryption{Encrypted?}
    
    CheckEncryption -->|Yes| GetKey[Get Decryption Key]
    CheckEncryption -->|No| ParseYAML[Parse YAML]
    
    GetKey --> KeySources{Key Source}
    KeySources -->|Hardware| HardwareKey[Hardware Security Module]
    KeySources -->|System| SystemKeychain[System Keychain]
    KeySources -->|Derived| DeriveKey[Multi-factor Key Derivation]
    
    HardwareKey --> DecryptConfig[Decrypt Configuration]
    SystemKeychain --> DecryptConfig
    DeriveKey --> DecryptConfig
    
    DecryptConfig --> ParseYAML
    ParseYAML --> ValidateConfig[Validate Configuration]
    
    ValidateConfig --> SecurityPolicies{Security Policies}
    SecurityPolicies --> CheckDomainFronting[Check Domain Fronting Required]
    SecurityPolicies --> CheckTLSLibrary[Check uTLS Required]
    SecurityPolicies --> CheckDoHProviders[Check DoH Providers]
    
    CheckDomainFronting --> GeneratePolymorphic[Generate Polymorphic Strategies]
    CheckTLSLibrary --> GeneratePolymorphic
    CheckDoHProviders --> GeneratePolymorphic
    
    GeneratePolymorphic --> InjectDecoys[Inject Decoy Strategies]
    InjectDecoys --> RandomizeOrder[Randomize Strategy Order]
    RandomizeOrder --> FinalConfig[Final Configuration]
    
    style ConfigFile fill:#99ff99
    style ValidateConfig fill:#ff9999
    style GeneratePolymorphic fill:#99ccff
    style FinalConfig fill:#ffcc99
```

## 9. Mobile Bridge Architecture

```mermaid
sequenceDiagram
    participant MobileApp
    participant Bridge
    participant StatusUpdater
    participant Engine
    participant Proxy
    
    MobileApp->>Bridge: StartEngine(configJSON)
    Bridge->>StatusUpdater: OnStatusUpdate("CONNECTING", "Loading...")
    
    Bridge->>Bridge: Parse configuration
    Bridge->>Engine: NewEngine(config)
    Engine-->>Bridge: Engine instance
    
    Bridge->>StatusUpdater: OnStatusUpdate("CONNECTING", "Finding strategy...")
    Bridge->>Engine: TestStrategies()
    
    loop Strategy Testing
        Engine->>Engine: Test each strategy
    end
    
    Engine-->>Bridge: Strategy results
    Bridge->>Bridge: Select best strategy
    
    Bridge->>StatusUpdater: OnStatusUpdate("CONNECTING", "Starting proxy...")
    Bridge->>Engine: StartProxyWithStrategy()
    
    par
        Engine->>Proxy: Start SOCKS5 proxy
        Proxy-->>Engine: Proxy started
    and
        Bridge->>Bridge: Start monitoring goroutine
    end
    
    Engine-->>Bridge: Proxy address
    Bridge->>StatusUpdater: OnStatusUpdate("CONNECTED", "Proxy running")
    
    Note over Bridge: Proxy runs in background
    
    MobileApp->>Bridge: StopEngine()
    Bridge->>Engine: Stop()
    Engine->>Proxy: Stop proxy
    Proxy-->>Engine: Stopped
    Engine-->>Bridge: Engine stopped
    Bridge->>StatusUpdater: OnStatusUpdate("DISCONNECTED", "Stopped")
```

## 10. Entropy Management and Security

```mermaid
graph TB
    subgraph "Entropy Sources"
        HWRandom[Hardware Random]
        CryptoRand[crypto/rand]
        SystemEntropy[System Entropy Pool]
        NetworkTiming[Network Timing]
        UserBehavior[User Behavior]
    end
    
    subgraph "Entropy Management"
        EntropyManager[Entropy Manager]
        QualityValidator[Quality Validator]
        StatisticalTests[Statistical Tests]
        EntropyPool[Entropy Pool]
    end
    
    subgraph "Security Validation"
        NISTTests[NIST Test Suite]
        FrequencyTest[Frequency Test]
        RunsTest[Runs Test]
        SerialTest[Serial Test]
        EntropyTest[Entropy Test]
    end
    
    subgraph "Cryptographic Operations"
        DGAGeneration[DGA Generation]
        SessionIDs[Session ID Generation]
        TrafficJitter[Traffic Jitter]
        KeyDerivation[Key Derivation]
    end
    
    subgraph "Failure Handling"
        SecurityAlert[Security Alert]
        SafeMode[Safe Mode]
        ProcessTermination[Process Termination]
    end
    
    HWRandom --> EntropyManager
    CryptoRand --> EntropyManager
    SystemEntropy --> EntropyManager
    NetworkTiming --> EntropyManager
    UserBehavior --> EntropyManager
    
    EntropyManager --> QualityValidator
    QualityValidator --> StatisticalTests
    StatisticalTests --> EntropyPool
    
    StatisticalTests --> NISTTests
    StatisticalTests --> FrequencyTest
    StatisticalTests --> RunsTest
    StatisticalTests --> SerialTest
    StatisticalTests --> EntropyTest
    
    EntropyPool --> DGAGeneration
    EntropyPool --> SessionIDs
    EntropyPool --> TrafficJitter
    EntropyPool --> KeyDerivation
    
    QualityValidator -->|Failure| SecurityAlert
    SecurityAlert --> SafeMode
    SecurityAlert -->|Critical Mode| ProcessTermination
    
    style EntropyManager fill:#ff9999
    style QualityValidator fill:#99ccff
    style SecurityAlert fill:#ffcc99
    style ProcessTermination fill:#ff6666
```

## 11. Domain Fronting Connection Flow

```mermaid
sequenceDiagram
    participant Client
    participant Engine
    participant DoHResolver
    participant FrontingDialer
    participant CDN
    participant TargetServer
    
    Client->>Engine: Connect to target.com
    Engine->>DoHResolver: Resolve front-domain.cdn.com
    DoHResolver-->>Engine: Front domain IP
    
    Engine->>FrontingDialer: Create fronted connection
    Note over FrontingDialer: SNI: front-domain.cdn.com<br/>Target: target.com
    
    FrontingDialer->>CDN: TCP connection to front domain IP
    CDN-->>FrontingDialer: TCP established
    
    FrontingDialer->>CDN: TLS handshake (SNI: front-domain.cdn.com)
    CDN-->>FrontingDialer: TLS established
    
    FrontingDialer->>CDN: HTTP CONNECT target.com:443<br/>Host: target.com<br/>(encrypted in TLS tunnel)
    CDN->>TargetServer: Forward CONNECT request
    TargetServer-->>CDN: Connection accepted
    CDN-->>FrontingDialer: HTTP 200 Connection established
    
    FrontingDialer-->>Engine: Tunnel ready
    Engine-->>Client: Connection established
    
    loop Data Transfer
        Client->>Engine: Application data
        Engine->>FrontingDialer: Fragmented/obfuscated data
        FrontingDialer->>CDN: Encrypted data (TLS)
        CDN->>TargetServer: Forwarded data
        TargetServer-->>CDN: Response data
        CDN-->>FrontingDialer: Encrypted response
        FrontingDialer-->>Engine: Deobfuscated response
        Engine-->>Client: Application response
    end
    
    Note over CDN: CDN only sees traffic to<br/>front-domain.cdn.com
    Note over FrontingDialer: Real destination hidden<br/>in encrypted Host header
```

These diagrams provide a comprehensive visual understanding of the GoCircum system architecture, data flows, and security mechanisms. Each diagram focuses on a specific aspect of the system to help understand how the components interact and how data flows through the censorship circumvention pipeline. 