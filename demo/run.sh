set -e
PROGRAM=${1:-basic}
VARNISHD=varnishd

$VARNISHD -f $PWD/demo.vcl -a :8000 -p thread_pool_stack=64k -n /tmp/varnishd -F
