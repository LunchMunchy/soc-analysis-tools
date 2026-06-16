#!/usr/bin/env bash
#
# ip_investigate.sh — Pull the most pertinent details on a single IP address
# -----------------------------------------------------------------------------
#
# Feed it any IPv4 address and it prints a one-screen analyst report:
# scope/classification, reverse DNS, geolocation, network ownership (ASN/ISP),
# risk indicators (hosting / proxy-VPN / mobile), WHOIS registration details,
# and a short heuristic "analyst notes" assessment.
#
# Sources:
#   - dig         reverse DNS (PTR)
#   - ip-api.com  geolocation, ASN, ISP, hosting/proxy/mobile flags  (free, no key)
#   - whois       registration: net range, netname, org, country, abuse contact
#
# Note: ip-api.com and whois are EXTERNAL queries — the IP you look up is sent to
# those services. Use only on addresses you are authorised to investigate.
#
# Requirements: dig, whois, curl, jq.
#
# Usage:
#   ./ip_investigate.sh <ipv4-address>
#
# Example:
#   ./ip_investigate.sh 69.50.95.167
# -----------------------------------------------------------------------------

set -uo pipefail

die() { printf 'Error: %s\n' "$1" >&2; exit 1; }

[[ $# -ge 1 ]] || { echo "Usage: $0 <ipv4-address>" >&2; exit 1; }
IP="$1"

for t in dig curl jq; do command -v "$t" >/dev/null 2>&1 || die "$t not found (install it to run this tool)"; done

# ---- validate IPv4 ----------------------------------------------------------
valid_ipv4() {
  local ip="$1" o
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do (( o <= 255 )) || return 1; done
  return 0
}
valid_ipv4 "$IP" || die "not a valid IPv4 address: $IP"

# ---- classify scope locally (no network) ------------------------------------
IFS=. read -r A B C D <<<"$IP"
scope() {
  if   (( A==10 ));                         then echo "Private (RFC1918)"
  elif (( A==172 && B>=16 && B<=31 ));       then echo "Private (RFC1918)"
  elif (( A==192 && B==168 ));               then echo "Private (RFC1918)"
  elif (( A==127 ));                         then echo "Loopback"
  elif (( A==169 && B==254 ));               then echo "Link-local"
  elif (( A==100 && B>=64 && B<=127 ));      then echo "CGNAT (RFC6598)"
  elif (( A==0 ));                           then echo "Reserved (this-network)"
  elif (( A>=224 && A<=239 ));               then echo "Multicast"
  elif (( A>=240 ));                         then echo "Reserved (future-use)"
  else                                            echo "Public (globally routable)"
  fi
}
SCOPE="$(scope)"
PUBLIC=0; [[ "$SCOPE" == Public* ]] && PUBLIC=1

# ---- reverse DNS ------------------------------------------------------------
PTR="$(dig +short +time=3 +tries=1 -x "$IP" 2>/dev/null | head -1)"
PTR="${PTR%.}"; [[ -n "$PTR" ]] || PTR="(none)"

# ---- geolocation / ASN via ip-api.com (public IPs only) ---------------------
JSON=""
if (( PUBLIC )); then
  JSON="$(curl -s --max-time 10 \
    "http://ip-api.com/json/${IP}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query" \
    2>/dev/null || true)"
fi
jget() { [[ -n "$JSON" ]] && printf '%s' "$JSON" | jq -r --arg k "$1" '.[$k] // empty' 2>/dev/null; }
GEO_OK=0; [[ "$(jget status)" == "success" ]] && GEO_OK=1

COUNTRY="$(jget country)"; CC="$(jget countryCode)"; REGION="$(jget regionName)"
CITY="$(jget city)"; LAT="$(jget lat)"; LON="$(jget lon)"; TZ="$(jget timezone)"
ISP="$(jget isp)"; ORG="$(jget org)"; ASRAW="$(jget as)"; ASNAME="$(jget asname)"
HOSTING="$(jget hosting)"; PROXY="$(jget proxy)"; MOBILE="$(jget mobile)"

# ---- WHOIS registration (public IPs only) -----------------------------------
WHO=""
if (( PUBLIC )) && command -v whois >/dev/null 2>&1; then
  WHO="$(whois "$IP" 2>/dev/null || true)"
fi
wfirst() { printf '%s\n' "$WHO" | grep -iE -m1 "$1" | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d '\r'; }
W_RANGE="$(wfirst '^(NetRange|inetnum|inet6num)')"
W_CIDR="$(wfirst '^(CIDR|route)')"
W_NAME="$(wfirst '^(NetName|netname)')"
# prefer the real owner; skip bare RIR names that often appear first
W_ORG="$(printf '%s\n' "$WHO" | grep -iE '^(OrgName|org-name|owner|descr|organisation)' \
          | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d '\r' \
          | grep -ivE '^(ARIN|RIPE( NCC)?|APNIC|LACNIC|AFRINIC)$' | head -1)"
W_CC="$(wfirst '^country')"
W_ABUSE="$(printf '%s\n' "$WHO" | grep -iE 'OrgAbuseEmail|abuse-mailbox|abuse.*@' \
            | grep -oiE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | head -1)"

# ---- build heuristic analyst notes ------------------------------------------
notes=()
if (( ! PUBLIC )); then
  notes+=("Non-public address (${SCOPE}). It would not appear as a genuine remote internet peer — treat as a capture/NAT artifact or possible spoofing.")
fi
[[ "$HOSTING" == "true" ]] && notes+=("Datacenter / hosting IP. BitTorrent from a hosting provider is atypical for residential P2P — likely a seedbox, VPN/proxy exit, or automated crawler. Higher investigative priority.")
[[ "$PROXY"  == "true" ]] && notes+=("Flagged as anonymiser (proxy / VPN / Tor). The operator's true location is obscured; correlate across sessions rather than trusting geo.")
[[ "$MOBILE" == "true" ]] && notes+=("Mobile carrier network. The address is typically shared/rotating via CGNAT, so attribution to a single subscriber is unreliable without carrier records.")
shopt -s nocasematch
[[ "$PTR" == *tor* ]] && notes+=("Reverse DNS contains 'tor' — possible Tor exit node.")
[[ "$PTR" == *vpn* ]] && notes+=("Reverse DNS contains 'vpn' — possible commercial VPN endpoint.")
shopt -u nocasematch
if (( PUBLIC && GEO_OK )) && [[ "$HOSTING" != "true" && "$PROXY" != "true" && "$MOBILE" != "true" ]]; then
  notes+=("No elevated risk flags from automated sources — consistent with an ordinary residential/business peer.")
fi
(( PUBLIC )) && (( ! GEO_OK )) && notes+=("Geolocation lookup unavailable (offline or rate-limited) — geo/ASN fields below may be blank; rely on WHOIS.")

# ---- print report -----------------------------------------------------------
line() { printf '%s\n' "============================================================"; }
val()  { printf '  %-15s: %s\n' "$1" "${2:-(unknown)}"; }

line
printf ' IP INVESTIGATION REPORT: %s\n' "$IP"
printf ' Generated: %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
line
echo
echo "[ Classification ]"
val "IP version" "IPv4"
val "Scope"      "$SCOPE"
echo
echo "[ Reverse DNS ]"
val "PTR"        "$PTR"
if (( PUBLIC )); then
  echo
  echo "[ Geolocation ]            (source: ip-api.com)"
  val "Country"  "${COUNTRY:+$COUNTRY (${CC})}"
  val "Region"   "$REGION"
  val "City"     "$CITY"
  val "Coords"   "${LAT:+$LAT, $LON}"
  val "Timezone" "$TZ"
  echo
  echo "[ Network / Ownership ]    (source: ip-api.com)"
  val "ASN"      "${ASRAW:-$ASNAME}"
  val "ISP"      "$ISP"
  val "Org"      "$ORG"
  echo
  echo "[ Risk Indicators ]"
  val "Hosting/DC"    "$([[ "$HOSTING" == "true" ]] && echo "YES" || echo "no")"
  val "Proxy/VPN/Tor" "$([[ "$PROXY"   == "true" ]] && echo "YES" || echo "no")"
  val "Mobile net"    "$([[ "$MOBILE"  == "true" ]] && echo "YES" || echo "no")"
  echo
  echo "[ WHOIS (registration) ]   (source: whois)"
  val "NetRange"  "$W_RANGE"
  val "CIDR"      "$W_CIDR"
  val "NetName"   "$W_NAME"
  val "Org"       "$W_ORG"
  val "Country"   "$W_CC"
  val "Abuse"     "$W_ABUSE"
fi
echo
echo "[ Analyst Notes ]"
if ((${#notes[@]})); then
  for n in "${notes[@]}"; do printf '  - %s\n' "$n" | fold -s -w 70 | sed '2,$s/^/    /'; done
else
  echo "  - No automated assessment available."
fi
line
