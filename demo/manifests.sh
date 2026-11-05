#!/bin/bash
# Walk through a viewer session against demo/manifests.vcl on :8000
set -e
V=http://127.0.0.1:8000

echo "== Master playlist, no token: a new viewer session"
curl -s -D /tmp/master.hdr -o /tmp/master.m3u8 $V/live/ch1/master.m3u8
grep -i '^X-Viewer-ID' /tmp/master.hdr
cat /tmp/master.m3u8
token=$(sed -n 's/^low\/index\.m3u8?token=//p' /tmp/master.m3u8)

echo; echo "== Variant playlist with its signed URL (the session is extended)"
curl -s "$V/live/ch1/low/index.m3u8?token=$token" | tee /tmp/low.m3u8
seg=$(sed -n 's/^seg100\.m4s?token=//p' /tmp/low.m3u8)

echo; echo "== Segment with its signed URL (shared cache object)"
curl -s "$V/live/ch1/low/seg100.m4s?token=$seg"

echo; echo "== The segment token on other URLs: no token, forged, next segment, other rendition, other channel"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch1/low/seg100.m4s"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch1/low/seg100.m4s?token=x$seg"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch1/low/seg101.m4s?token=$seg"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch1/high/seg100.m4s?token=$seg"
curl -s -o /dev/null -w '%{http_code}\n' "$V/live/ch2/low/seg100.m4s?token=$seg"

echo; echo "== DASH, another viewer: templates sign the path before the first \$ and after the last \$"
curl -s -D /tmp/mpd.hdr -o /tmp/manifest.mpd $V/vod/movie/manifest.mpd
grep -i '^X-Viewer-ID' /tmp/mpd.hdr
grep 'token=' /tmp/manifest.mpd
media=$(grep -o 'seg_[$]Number[$][.]m4s?token=[^"]*' /tmp/manifest.mpd | cut -d= -f2)
curl -s -o /dev/null -w 'video/720p/seg_2.m4s %{http_code}\n' "$V/vod/movie/video/720p/seg_2.m4s?token=$media"
curl -s -o /dev/null -w 'video/720p/init.mp4  %{http_code}\n' "$V/vod/movie/video/720p/init.mp4?token=$media"
