# Building a Home Intrusion Detection System with Suricata and WatcherDash

**Category:** Cybersecurity / Networking / Python / Linux  
**Status:** Active project

I wanted to get some hands-on experience with intrusion detection systems (IDS). I had learned about them in school, and one of my professors recommended setting one up at home. My homelab was already growing, so I figured this would be a good way to learn something useful while putting some of my existing equipment to work.

The original goal was pretty simple: get Suricata running, feed it traffic from my home network, and learn how to interpret what it was detecting. I wanted to understand how an IDS actually works outside of a lab exercise where everything is already configured for you.

That goal eventually turned into two connected projects. The first was building the IDS itself. The second was a Python terminal dashboard called **WatcherDash**, which I had absolutely no intention of making when I started. It came about because I got tired of manually digging through logs and wanted a way to see what was happening without constantly checking in on the system.

## Hardware and Software

I decided to repurpose a Dell Inspiron 13 7000 2-in-1 laptop. It had been sitting around without much to do, but its hardware was more than capable of running an IDS. I kept Windows installed and gave Debian 13 its own partition so the laptop could serve as a lightweight Linux sensor.

The main pieces of the setup were:

| Component | Purpose |
| --- | --- |
| Dell Inspiron 13 7000 2-in-1 | Dedicated IDS sensor |
| Debian 13 | Operating system for the sensor |
| Suricata 7.0.10 | Network intrusion detection engine |
| Emerging Threats Open | Detection signatures |
| UniFi Lite 8 PoE | Managed switch used for port mirroring |
| GL.iNet router | Home network gateway |
| ASIX AX88179A USB Ethernet adapter | Dedicated interface for packet capture |
| Built-in laptop Wi-Fi | Management and SSH access |
| Python and its built-in terminal tools | WatcherDash interface and saved alert history |

I scoped Suricata to my home subnet rather than leaving it configured for a much broader set of private networks.

The network design is straightforward. The router connects to the UniFi switch, and the switch copies traffic from its router-facing port to the Dell's dedicated capture port. Suricata listens on that capture interface. The Dell's Wi-Fi connection is used separately for administration, so I can SSH into the sensor without needing an IP address on the sniffing interface.

This separation ended up being useful, although it took some troubleshooting to get there.

## Getting Suricata Running

I installed Suricata on Debian and configured it to use the USB Ethernet adapter. I also loaded the Emerging Threats Open ruleset, giving the sensor more than 53,000 detection rules to work with.

At first, I wasn't trying to detect anything sophisticated. I wanted to prove the basic pipeline worked. I created a local ICMP rule, generated some ping traffic, and watched for the resulting alerts in Suricata's logs.

That worked, but I quickly learned that a running IDS and a useful IDS are not necessarily the same thing.

Suricata could see traffic addressed to the Dell, along with ordinary broadcast and multicast traffic. What it couldn't reliably see was the unrelated unicast traffic moving between other devices and the router. That was a problem, because the whole point was to monitor the network rather than just the sensor itself.

## The Port Mirroring Rabbit Hole

This was probably the most frustrating yet educational part of the setup.

I had purchased the UniFi Lite 8 PoE partly because I wanted hands-on experience with managed switches. Port mirroring seemed like a perfect feature to learn. I configured the switch to copy traffic from the router-facing port to the port connected to the Dell, expecting to see traffic immediately.

Instead, I mostly saw multicast traffic and random device-discovery packets. I could generate web traffic or ping the router from another computer and still see almost nothing useful.

I spent a lot of time checking the switch configuration, port counters, routes, adapter status, and promiscuous mode. The USB Ethernet adapter was an ASIX AX88179A, and Debian was using the `cdc_ncm` driver. I started looking at how the adapter was enumerated over USB and which driver was handling it. At one point, we were digging into USB configurations and kernel modules just to figure out why a mirrored packet would not appear in tcpdump.

I also dragged out another laptop running Arch Linux to help isolate the problem. That turned into its own adventure, because the installation had package-signing and dependency issues. All I wanted was tcpdump, and I somehow ended up dealing with an old package database and a broken upgrade path.

Rather than spend the entire afternoon fixing Arch, I used a short Python script with a raw packet socket to listen for ICMP traffic. That was enough to prove the switch was sending mirrored traffic. It also gave me a way to compare the behavior of the two Ethernet adapters.

After more testing, including toggling promiscuous mode on the Dell's capture interface, the expected traffic finally started appearing. I could see requests and replies between devices that weren't the IDS sensor at all.

I then moved management traffic to the Dell's built-in Wi-Fi and left the USB Ethernet adapter dedicated to passive capture. With that arrangement, the capture interface didn't need a normal IPv4 address, while SSH access continued working over Wi-Fi.

The biggest lesson here was to test the different pieces independently. Seeing a few packets in tcpdump didn't prove that port mirroring was working. I needed to see unrelated unicast traffic, including both sides of a conversation, before I could trust the setup.

## Tuning and Testing the IDS

Once Suricata was receiving mirrored traffic, I tuned its `AF_PACKET` configuration for passive monitoring and scoped its `HOME_NET` setting to my home subnet. I also configured automatic log rotation, because continuously recording network events can use disk space surprisingly quickly.

I started looking through `fast.log`, `eve.json`, and `stats.log`. Suricata's EVE JSON output was particularly useful because it gave me structured information about alerts, flows, DNS queries, HTTP activity, and other network events.

I tested detection in several ways. A custom ICMP rule confirmed that Suricata could generate alerts from known traffic. Later, I used HTTP requests with recognizable User-Agent strings and ran Nmap's service-version detection against my own network. Steam was actually a surprise. It automatically started on my Windows laptop without my knowledge, and it immediately generated a Priority 1 alert for its HTTP User-Agent. What a scare to see an unexpected Priority 1 alert! Once I tracked that down, opening Steam became a convenient way to test whether the red alert panel was working.

The Nmap test was especially satisfying. Suricata identified the Nmap User-Agent, and the logs showed activity on ports associated with SSH, FTP, SMB, LDAP, RDP, and Telnet. It was a useful demonstration that the same activity could appear as both a signature-based alert and a set of network connection observations.

I also learned pretty quickly that not every alarming-looking signature means an actual attack. One alert suggested that a suspicious Windows executable had been downloaded. By following its Suricata `flow_id` and inspecting the related HTTP events, I found evidence consistent with a Microsoft Defender update. The detection was real, but the context made it look much less concerning.

That became a recurring lesson: an IDS tells you that traffic matched a rule. You still need to understand what happened before deciding how serious it is.

## WatcherDash: The Project I Didn't Plan to Build

At this point Suricata was working, but I had another problem. I didn't want to spend all day running commands, searching JSON files, and reading alerts every few days. If something interesting happened, I'd rather notice it while it was happening.

I looked at existing dashboards and alert-management tools, but I didn't really want a web interface. The Dell has its own screen, but its Debian install was headless. A dashboard running in a browser on my main computer would just end up buried behind whatever I was working on.

I also liked the idea of having one of those cheesy, old-school hacker terminals that movies love so much. Something green on black, with boxes, counters, and warnings that actually meant something.

Since I am not a software engineer, and wanted something quickly, I asked ChatGPT to write a small terminal dashboard based on the features I wanted. That became **WatcherDash**.

WatcherDash is a Python application that runs inside a terminal. It reads the EVE JSON output Suricata already produces and presents the information in a way that's easier to glance at. It also keeps track of acknowledgements and saved reviews between runs.

There isn't a web server or a large SIEM stack. It's a relatively small program that runs directly on the Dell's screen 24/7 or in any terminal that connects (over SSH).

The first version was basic, but it worked. I could leave it running on the Dell's screen and watch new alerts appear. From there, I kept using it, figuring out what annoyed me, and asking ChatGPT to revise the code. I was making decisions about what the tool should do and testing the changes, not writing the Python myself.

## Making the Dashboard Useful

One of the first features was a pinned alert area. Priority 1 alerts appear in red and Priority 2 alerts in amber. They remain visible until I acknowledge them, rather than scrolling off the screen while I'm doing something else. Suricata's priority numbers are not a guarantee that an event is malicious, but this gives me a good starting point for deciding what to look at.

The next big improvement was grouping.

My Windows computer generates an enormous amount of STUN traffic (thousands of packets per day, thousands of alerts per day), which Suricata recognizes and logs. At one point, the dashboard was filling with almost identical alerts from different remote IP addresses. Simply scrolling through them wasn't really possible.

I asked ChatGPT to change the grouping so alerts would be organized by signature and protected host instead of creating a separate row for every source and destination pair. Now I can see how many times a rule fired, how many different remote peers were involved, and then drill down into the peer addresses if I actually want that detail.

We also refined the keyboard controls after I found some of the navigation frustrating. The arrow keys let me scroll through alerts without losing my place when new traffic arrives. I can open an alert's details, go another level into its remote peers, or press Escape to return to the live feed.

The dashboard eventually gained a third section called **Connection Watch**. It tracks activity involving administrative and file-sharing protocols such as `SSH, FTP, SMB, Telnet, LDAP, and RDP`. Originally, it relied mostly on Suricata flow records, which meant some observations appeared only after a connection timed out. The SSH connection I established would not be detected for hours or days sometimes. I wanted something faster, so ChatGPT helped write a custom Suricata rule for TCP SYN packets, which I added to my sensor. That made new connection attempts show up immediately. In the event of a breach, I won't find out after the attacker is done.

That distinction matters. A SYN packet proves that a connection was attempted, not that someone logged in or successfully established an SSH tunnel. WatcherDash labels the evidence accordingly.

Other features came out of normal use:

- Alerts that need to be acknowledged are saved between runs instead of disappearing when the program closes.
- Repeated connection observations are grouped to keep the screen readable.
- Alerts and connections can be flagged for later review, with a simple investigation queue and notes.
- The bottom help bar changes based on which screen I'm viewing.
- A screenshot shortcut saves the terminal display as an SVG image along with a searchable text copy.
- Multiple terminal sessions can share the same saved alert state.

That last feature also exposed a bug. The dashboard ran overnight on the Dell's own screen, but another terminal session sometimes crashed. I copied the traceback into ChatGPT, which identified a conflict between two instances saving the same connection event and generated a small patch. My part was noticing the failure and reporting what happened, not debugging the internal database code. It was a good example of how this project worked: I used the software, found a problem, and worked with ChatGPT to address it.

## Real Testing, Not Just a Pretty Screen

I wanted to make sure WatcherDash was showing useful evidence, not just looking cool.

I tested it with normal traffic, known detection rules, and deliberately generated activity on my own network. After Steam unexpectedly triggered a Priority 1 rule, I used it again as an easy test of the red pinned-alert panel. Running Nmap with service-version detection triggered an Nmap-related signature and produced a series of Connection Watch observations. Failed FTP and SMB connection attempts showed up as port activity, and the custom SYN rule made those attempts visible much sooner.

I also rebooted the Dell to confirm the important pieces would come back to life. Suricata started automatically, the Wi-Fi management connection returned, and the mirrored capture interface was available again. WatcherDash itself still needed to be launched manually, which is something I may automate later.

Throughout this process I used screenshots, tcpdump, Suricata logs, and deliberately generated traffic to check whether the behavior I expected was actually happening.

## Results

At the time of writing, WatcherDash is still running as part of my normal homelab setup. A saved dashboard snapshot reported approximately **14.7 million packets in its capture counter**, with **57 grouped alert categories** visible in the session.

The grouping results are probably the clearest example of why WatcherDash was worth building. Two STUN groups on one host contained approximately **79,000 requests** and **76,000 responses**. Instead of filling the screen with more than 150,000 individual lines, WatcherDash displayed two readable entries with occurrence counts and peer details available when needed.

The system also demonstrated that it could detect controlled Nmap activity, track selected connection attempts, pin higher-priority Suricata alerts, and preserve review information. The dashboard remained lightweight enough to leave running on the Dell's built-in display.

There is an important performance limitation I am still working through. The same snapshot reported approximately **5.7 million kernel packet drops**. Those counters need more investigation, especially as traffic volume increases. The dashboard is useful, but I don't want to claim the sensor is seeing every packet when its own statistics indicate otherwise. Resolving or reducing capture loss is one of the next priorities.

The router-port mirror is another limitation. It gives me visibility into traffic crossing that uplink, but it does not automatically capture every conversation between two devices connected elsewhere on the same switch, nor does it reveal traffic blocked before reaching the router's LAN interface.

## What I Learned

The original goal was to learn how to work with an IDS in my own homelab, and I absolutely accomplished that. I learned about setting up Suricata, managing its rules, using `AF_PACKET`, inspecting logs, and following network flows. Just as importantly, I learned how much the usefulness of an IDS depends on what traffic it can actually see.

The port-mirroring problems forced me to get much more familiar with switch configuration, Linux network interfaces, USB Ethernet drivers, packet capture, and basic troubleshooting. The Arch laptop adventure was a little ridiculous, but even that produced a useful Python packet listener.

WatcherDash taught me something different. I wasn't setting out to make a software project, but having an actual problem to solve made the process much more interesting. Each feature came from using the dashboard and discovering something I wanted to change. I learned a lot about what I wanted from a monitoring tool, and about testing whether those features actually worked in my environment.


One other lesson was that a security alert is not the same thing as a security incident. Normal applications can generate very dramatic-sounding signatures. Knowing how to investigate an alert and decide what it actually represents is just as important as making the alert appear in the first place.

## Next Steps

This is still an active project. I'd like to investigate the packet drops, continue tuning Suricata's capture performance, and improve how WatcherDash saves evidence related to a particular investigation. I'd also like the dashboard to start automatically on the Dell's display after a reboot, while keeping it separate from the privileges Suricata needs for packet capture.

Longer term, I want to clean up the WatcherDash code and publish it as its own GitHub project. There are also opportunities to improve alert filtering, preserve more context around related flows, and move Suricata to a supported version.

## Conclusion

I started this project because I wanted hands-on experience with intrusion detection systems. What I ended up with was a working home IDS, a much better understanding of network monitoring, and a terminal dashboard I didn't even know I wanted when I began.

Getting Suricata installed was only one part of the job. Figuring out why it wasn't seeing traffic, learning how to interpret alerts, and finding a way to make the data useful were the parts that taught me the most.

WatcherDash was an unexpected addition, but it made the IDS something I actually enjoy keeping on and checking throughout the day. I still have work to do, especially around capture performance, but I have a system I can keep testing and improving in my own lab. That's exactly what I wanted out of this project.

---

## Suggested Projects Page Card

**Title:** Building a Home IDS with Suricata and WatcherDash  
**Category:** Cybersecurity / Networking / Python  
**Status:** Active project

A home intrusion detection system built with Suricata, Debian Linux, and UniFi switch-port mirroring. What started as an experiment with IDS deployment eventually led to WatcherDash, a custom Python terminal dashboard for live alerts, connection monitoring, and investigations.

## Notes for Website Integration

These are editorial notes, not part of the published article.

- Keep the article's first-person voice and informal tone. Avoid converting it into a formal report.
- Suggested images: a network topology diagram with no real IP addresses or internal hostnames, a tcpdump capture with addresses redacted, a WatcherDash terminal screenshot with internal and public endpoint IPs obscured, and an alert-details or Connection Watch view with identifying network details removed.
- Treat the packet and alert counts as a snapshot from the time of writing, not live metrics or all-time verified totals.
- Keep the packet-drop limitation in the article. Avoid claiming complete capture coverage.
- Do not add real subnet ranges, gateway IPs, device hostnames, or unredacted EVE / tcpdump screenshots to the public page. Keep hardware model names and the general architecture.
- Suggested page location: `/projects/suricata-watcherdash/`.
- This Markdown is source copy for future website integration, not an instruction to automatically edit the website.
