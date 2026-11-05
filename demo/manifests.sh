#!/bin/bash
# Walk through a viewer session against demo/manifests.vcl on :8000
set -e
V=http://127.0.0.1:8000

echo "== Master playlist, no token: a new viewer session"
curl -s -D /tmp/master.hdr -o /tmp/master.m3u8 $V/live/ch1/master.m3u8
grep -i '^X-Viewer-ID' /tmp/master.hdr
cat /tmp/master.m3u8
token=$(sed -n 's/^low\/index\.m3u8?token=//p' /tmp/master.m3u8)

echo; echo "== Variant playlist with the viewer's token (the session is extended)"
curl -s "$V/live/ch1/low/index.m3u8?token=$token" | tee /tmp/low.m3u8
seg=$(sed -n 's/^seg100\.m4s?token=//p' /tmp/low.m3u8)

echo; echo "== Segment with token (shared cache object)"
curl -s "$V/live/ch1/low/seg100.m4s?token=$seg"

echo; echo "== Segment without token, forged token, other channel"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch1/low/seg100.m4s"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch1/low/seg100.m4s?token=x$seg"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch2/low/seg100.m4s?token=$seg"

echo; echo "== DASH, another viewer"
curl -s -D - $V/vod/movie/manifest.mpd | grep -iE '^X-Viewer-ID|token='
