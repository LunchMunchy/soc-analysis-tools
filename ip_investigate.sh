#!/usr/bin/env bash
#
# ip_investigate.sh — quick, general-purpose intelligence on a single IP address
# =============================================================================
# Give it any IPv4 or IPv6 address and it prints a one-screen report:
#
#   Classification   public vs private/reserved, address family
#   Reverse DNS      PTR record
#   Geolocation      country / region / city / coordinates / timezone
#   Ownership        ASN, ISP, organisation
#   Risk indicators  hosting/datacenter, proxy/VPN/Tor, mobile network
#   Registration     WHOIS net range, netname, org, country, abuse contact
#   Analyst notes    plain-language interpretation of all of the above
#
# It is deliberately context-agnostic: nothing assumes *why* you are looking the
# address up, so the same tool works for any investigation.
#
# DATA SOURCES (everything except local classification is an external lookup —
# the address you query is sent to that service; only investigate addresses you
# are authorised to):
#   dig          reverse DNS (PTR)
#   ip-api.com   geo / ASN / ISP / hosting|proxy|mobile flags   (free, no key)
#   whois        registration details   (optional — skipped if not installed)
#
# REQUIREMENTS: bash, dig, curl, jq.  (whois is optional.)
#
# USAGE:
#   ./ip_investigate.sh <ip-address>
#
# EXAMPLES:
#   ./ip_investigate.sh 69.50.95.167
#   ./ip_investigate.sh 2606:4700:4700::1111
#
# HOW TO EXTEND (sections are marked below):
#   * Configuration   — change timeouts or the geolocation provider/fields.
#   * Analyst notes   — add a heuristic by appending one `note "..."` line.
#   * Report          — each block is plain echo/row calls; copy one to add a row.
# =============================================================================

set -uo pipefail

# ---- Configuration (safe to tweak) ------------------------------------------
DNS_TIMEOUT=3                     # seconds for the reverse-DNS query
HTTP_TIMEOUT=10                   # seconds for the geolocation API call
GEO_URL="http://ip-api.com/json"  # geolocation provider; must return JSON
GEO_FIELDS="status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"

# ---- Small helpers ----------------------------------------------------------
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
row() { printf '  %-15s: %s\n' "$1" "${2:-(unknown)}"; }     # print "label : value"
yn()  { [[ "$1" == "true" ]] && echo "YES" || echo "no"; }   # bool string -> YES/no

# ---- Input ------------------------------------------------------------------
[[ $# -eq 1 ]] || die "usage: $0 <ip-address>"
IP="$1"
for t in dig curl jq; do command -v "$t" >/dev/null || die "missing required tool: $t"; done

# ---- Validate + classify scope (purely local, no network) -------------------
# Sets three globals: FAMILY (4 or 6), SCOPE (human label), PUBLIC (1 = routable).
classify() {
  if [[ "$IP" == *:* ]]; then                    # ---------- IPv6 ----------
    [[ "$IP" =~ ^[0-9A-Fa-f:]+$ ]] || die "not a valid IPv6 address: $IP"
    FAMILY=6
    local lc; lc="$(printf '%s' "$IP" | tr 'A-F' 'a-f')"
    case "$lc" in
      ::1)                 SCOPE="Loopback" ;;
      ::)                  SCOPE="Unspecified" ;;
      fe8*|fe9*|fea*|feb*) SCOPE="Link-local (fe80::/10)" ;;
      fc*|fd*)             SCOPE="Unique-local (fc00::/7)" ;;
      ff*)                 SCOPE="Multicast" ;;
      *)                   SCOPE="Public (global unicast)" ;;
    esac
  else                                            # ---------- IPv4 ----------
    [[ "$IP" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] \
      || die "not a valid IPv4 address: $IP"
    local a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]} c=${BASH_REMATCH[3]} d=${BASH_REMATCH[4]}
    for o in "$a" "$b" "$c" "$d"; do (( o <= 255 )) || die "octet out of range: $IP"; done
    FAMILY=4
    if   (( a==10 || (a==172 && b>=16 && b<=31) || (a==192 && b==168) )); then SCOPE="Private (RFC1918)"
    elif (( a==127 ));                   then SCOPE="Loopback"
    elif (( a==169 && b==254 ));          then SCOPE="Link-local"
    elif (( a==100 && b>=64 && b<=127 )); then SCOPE="CGNAT (RFC6598)"
    elif (( a==0 ));                      then SCOPE="Reserved (this-network)"
    elif (( a>=224 && a<=239 ));          then SCOPE="Multicast"
    elif (( a>=240 ));                    then SCOPE="Reserved (future use)"
    else                                       SCOPE="Public (globally routable)"
    fi
  fi
  [[ "$SCOPE" == Public* ]] && PUBLIC=1 || PUBLIC=0
}
classify

# ---- Gather: reverse DNS ----------------------------------------------------
PTR="$(dig +short +time="$DNS_TIMEOUT" +tries=1 -x "$IP" 2>/dev/null | head -1)"
PTR="${PTR%.}"; PTR="${PTR:-(none)}"

# ---- Gather: geolocation / ownership / risk flags (public addresses only) ---
JSON=""
(( PUBLIC )) && JSON="$(curl -s --max-time "$HTTP_TIMEOUT" "$GEO_URL/$IP?fields=$GEO_FIELDS" 2>/dev/null || true)"
jget() { [[ -n "$JSON" ]] && printf '%s' "$JSON" | jq -r --arg k "$1" '.[$k] // empty' 2>/dev/null; }
GEO_OK=0; [[ "$(jget status)" == "success" ]] && GEO_OK=1

G_COUNTRY="$(jget country)";  G_CC="$(jget countryCode)"
G_REGION="$(jget regionName)"; G_CITY="$(jget city)"
G_LAT="$(jget lat)";          G_LON="$(jget lon)";   G_TZ="$(jget timezone)"
G_ASN="$(jget as)";           G_ASNAME="$(jget asname)"
G_ISP="$(jget isp)";          G_ORG="$(jget org)"
HOSTING="$(jget hosting)";    PROXY="$(jget proxy)";  MOBILE="$(jget mobile)"

# ---- Gather: WHOIS registration (public addresses only; whois optional) -----
WHO=""
if (( PUBLIC )) && command -v whois >/dev/null; then WHO="$(whois "$IP" 2>/dev/null || true)"; fi
# First value of the first line whose label matches the given regex.
whois_get() { printf '%s\n' "$WHO" | grep -iE -m1 "$1" | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d '\r'; }

W_RANGE="$(whois_get '^(NetRange|inetnum|inet6num)')"
W_CIDR="$(whois_get '^(CIDR|route6|route)')"
W_NAME="$(whois_get '^(NetName|netname)')"
# Owner: take the first org/owner line that is NOT just the registry's own name.
W_ORG="$(printf '%s\n' "$WHO" | grep -iE '^(OrgName|org-name|owner|descr|organisation)' \
          | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d '\r' \
          | grep -ivE '^(ARIN|RIPE( NCC)?|APNIC|LACNIC|AFRINIC)$' | head -1)"
W_CC="$(whois_get '^country')"
# Abuse: first e-mail address on an abuse-related line.
W_ABUSE="$(printf '%s\n' "$WHO" | grep -iE 'OrgAbuseEmail|abuse-mailbox|abuse.*@' \
            | grep -ioE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | head -1)"

# ---- Analyst notes (heuristics) ---------------------------------------------
# Plain-language interpretation, independent of why you are looking the IP up.
# EXTEND HERE: add a rule by appending one `note "..."` line.
NOTES=()
note() { NOTES+=("$1"); }

(( ! PUBLIC )) && note "Not a public, internet-routable address ($SCOPE) — internal/NAT/reserved space. It does not identify a host on the public internet (could be a capture artifact or a spoofed/source-local address)."
[[ "$HOSTING" == "true" ]] && note "Hosted in a datacenter, not a residential/end-user line. Common for servers, cloud workloads, VPN/proxy exits, scanners and bots — treat as infrastructure rather than a person."
[[ "$PROXY"   == "true" ]] && note "Flagged as an anonymiser (proxy / VPN / Tor). The real operator and location are hidden, geolocation is unreliable, and the address may be shared by many users."
[[ "$MOBILE"  == "true" ]] && note "Mobile-carrier network. Addresses are shared and rotate via CGNAT, so they map to one subscriber only with carrier records and a precise timestamp."
shopt -s nocasematch
[[ "$PTR" == *tor* ]] && note "Reverse DNS contains 'tor' — possible Tor exit node."
[[ "$PTR" == *vpn* ]] && note "Reverse DNS contains 'vpn' — possible VPN endpoint."
shopt -u nocasematch
if (( PUBLIC && GEO_OK )) && [[ "$HOSTING$PROXY$MOBILE" != *true* ]]; then
  note "No hosting/anonymiser/mobile flags — consistent with an ordinary residential or business endpoint."
fi
(( PUBLIC )) && (( ! GEO_OK )) && note "Geolocation lookup failed (offline or rate-limited) — geo/ownership fields are blank; rely on reverse DNS and WHOIS."

# ---- Report -----------------------------------------------------------------
hr() { printf '%s\n' "============================================================"; }

hr
printf ' IP INVESTIGATION: %s  (IPv%s)\n' "$IP" "$FAMILY"
printf ' Generated: %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
hr

echo; echo "[ Classification ]"
row "Scope" "$SCOPE"

echo; echo "[ Reverse DNS ]"
row "PTR" "$PTR"

if (( PUBLIC )); then
  echo; echo "[ Geolocation ]            (source: ip-api.com)"
  row "Country"  "${G_COUNTRY:+$G_COUNTRY ($G_CC)}"
  row "Region"   "$G_REGION"
  row "City"     "$G_CITY"
  row "Coords"   "${G_LAT:+$G_LAT, $G_LON}"
  row "Timezone" "$G_TZ"

  echo; echo "[ Ownership ]              (source: ip-api.com)"
  row "ASN" "${G_ASN:-$G_ASNAME}"
  row "ISP" "$G_ISP"
  row "Org" "$G_ORG"

  echo; echo "[ Risk indicators ]"
  row "Hosting/DC"    "$(yn "$HOSTING")"
  row "Proxy/VPN/Tor" "$(yn "$PROXY")"
  row "Mobile net"    "$(yn "$MOBILE")"

  echo; echo "[ WHOIS registration ]     (source: whois)"
  row "Net range" "$W_RANGE"
  row "CIDR"      "$W_CIDR"
  row "Net name"  "$W_NAME"
  row "Org"       "$W_ORG"
  row "Country"   "$W_CC"
  row "Abuse"     "$W_ABUSE"
fi

echo; echo "[ Analyst notes ]"
if ((${#NOTES[@]})); then
  for n in "${NOTES[@]}"; do printf '  - %s\n' "$n" | fold -s -w 70 | sed '2,$s/^/    /'; done
else
  echo "  - No automated assessment available."
fi
hr
