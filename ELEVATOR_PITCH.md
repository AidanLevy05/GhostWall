# GhostWall — Elevator Pitch

Every day, servers face thousands of automated attacks — SSH brute-force attempts, port sweeps, credential stuffing — and most defenders are stuck choosing between heavyweight commercial tools or crude IP blocklists that catch attackers only after the damage is done.

**GhostWall flips the script.** Instead of just blocking attackers, it *deceives* them. A fake SSH proxy sits on port 22 and silently routes suspicious traffic into a honeypot, while legitimate users pass through untouched. Fake FTP servers dangle tempting files that go nowhere. Attackers waste their time on a ghost — and every move they make feeds GhostWall's real-time threat scoring engine.

That engine watches the network live — ARP scans, port sweeps, brute-force bursts — and assigns a continuously updated threat score using weighted, sliding-window metrics. As the score climbs from green to yellow to red, GhostWall automatically escalates its response: rate-limiting, temporary bans, full firewall lockdowns via nftables. When the attack ends, an LLM-powered debrief summarizes what happened and recommends next steps.

The whole system runs in two modes — a Docker stack for quick deployment or a native runtime for full packet-level control — with live dashboards (web and terminal) showing every event as it unfolds.

**In short: GhostWall is an autonomous, deception-first network defense system that turns attackers into intelligence sources — detecting, deceiving, scoring, and responding to threats in real time, without human intervention.**
