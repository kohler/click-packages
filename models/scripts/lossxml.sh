#! /bin/sh

usage () {
    echo "Usage: lossxml.sh FILE" 1>&2
    exit 1
}


doconfig=0
if test "$1" = '--config'; then 
    shift 1; doconfig=1
fi

if test $# = 0; then
    usage
fi

if echo "$1" | grep '/' >/dev/null; then
    dir=`echo $1 | sed 's/\(.*\/\)[^\/]*/\1/'`
else
    dir='./'
fi
file=`echo $1 | sed 's/.*\///'`
base=`echo $file | sed 's/\.gz//
s/\.dump//'`

from=''
case $file in
  *.dump|*.dump.gz)
    from='FromDump("'"$file"'", FORCE_IP true, STOP true)';;
  *.gz)
    text=`zcat "$file" | head -c 2000`;;
  *)
    text=`head -c 2000 "$file"`;;
esac

if test -z "$from"; then
    case "$text" in
      [0-9]*)
        from='FromTcpdump("'"$file"'", STOP true)';;
      \xA1\xB2\xC3\xD4*)
        from='FromDump("'"$file"'", FORCE_IP true, STOP true)';;
      !*)
        from='FromIPSummaryDump("'"$file"'", STOP true)';;
      *)
        echo "lossxml.sh: file type not recognized" 1>&2
	usage;;
    esac
fi

shift 1

config="
require(models)
fd :: $from
    -> aipf :: AggregateIPFlows
    -> IPFilter(0 tcp || icmp)
    -> loss :: CalculateTCPLossEvents(TRACEINFO $base.xml, /*FLOWDUMPS tifd,*/ SOURCE fd, IP_ID false, NOTIFIER aipf, ACKCAUSALITY true, UNDELIVERED true)
    // -> tifd :: ToIPFlowDumps($base.dir, NOTIFIER aipf, TCP_OPT true, TCP_WINDOW true)
    -> Discard;

ProgressBar(fd.filepos, fd.filesize, BANNER '$dir$base')
DriverManager(wait, write loss.clear, /*write tifd.clear,*/ stop)
"

if test $doconfig = 1; then 
    echo "$config"
else
    cd $dir
    click -e "$config"
fi
