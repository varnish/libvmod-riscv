#!/bin/bash
# Walk through a viewer session against demo/manifests.vcl on :8000
set -e
V=http://127.0.0.1:8000
DIR=$(cd "$(dirname "$0")" && pwd)

b64u() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
# Generate an HS256 entitlement from the subscriber's authentication service.
entitlement() {
	local h p
	h=$(printf '{"alg":"HS256","typ":"JWT"}' | b64u)
	p=$(printf '{"sub":"%s","exp":%d}' "$1" $(( $(date +%s) + 300 )) | b64u)
	echo "$h.$p.$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -hmac change-me-entitlement-secret -binary | b64u)"
}

echo "== Master playlist without an entitlement"
curl -s -o /dev/null -w '%{http_code}\n' $V/live/ch1/master.m3u8

echo; echo "== Master playlist with an entitlement for alice: a new viewer session"
curl -s -D /tmp/master.hdr -o /tmp/master.m3u8 "$V/live/ch1/master.m3u8?auth=$(entitlement alice)"
grep -i '^X-Viewer-ID' /tmp/master.hdr
cat /tmp/master.m3u8
token=$(sed -n 's/^low\/index\.m3u8?token=//p' /tmp/master.m3u8)
session=$(echo "$token" | cut -d. -f3)

echo; echo "== Variant playlist with its signed URL: live segments expire before the session"
curl -s "$V/live/ch1/low/index.m3u8?token=$token" | tee /tmp/low.m3u8
seg=$(sed -n 's/^seg100\.m4s?token=//p' /tmp/low.m3u8)

echo; echo "== Segment with its signed URL: the A or B variant for this session"
curl -s "$V/live/ch1/low/seg100.m4s?token=$seg"

echo; echo "== Rejected requests: missing or forged token, wrong segment, rendition, or channel"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch1/low/seg100.m4s"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch1/low/seg100.m4s?token=x$seg"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch1/low/seg101.m4s?token=$seg"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch1/high/seg100.m4s?token=$seg"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch2/low/seg100.m4s?token=$seg"

echo; echo "== Revoke session $session: the tenant reloads its revocation list"
cp "$DIR/manifests/revoked.txt" /tmp/revoked.txt.orig
echo "$session" >> "$DIR/manifests/revoked.txt"
sleep 1
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch1/low/seg100.m4s?token=$seg"
cp /tmp/revoked.txt.orig "$DIR/manifests/revoked.txt"

echo; echo "== DASH, another subscriber: templates sign the path before the first \$ and after the last \$"
curl -s -D /tmp/mpd.hdr -o /tmp/manifest.mpd "$V/vod/movie/manifest.mpd?auth=$(entitlement bob)"
grep -i '^X-Viewer-ID' /tmp/mpd.hdr
grep 'token=' /tmp/manifest.mpd
media=$(grep -o 'seg_[$]Number[$][.]m4s?token=[^"]*' /tmp/manifest.mpd | cut -d= -f2)
curl -s -o /dev/null -w 'video/720p/seg_2.m4s %{http_code}\n' "$V/vod/movie/video/720p/seg_2.m4s?token=$media"
curl -s -o /dev/null -w 'video/720p/init.mp4  %{http_code}\n' "$V/vod/movie/video/720p/init.mp4?token=$media"
