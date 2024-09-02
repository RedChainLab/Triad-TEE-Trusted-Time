#/bin/sh
FILEPATH_PREFIX="out/count/count-`date +%Y-%m-%d-%H-%M-%S`"

CORE_COUNTER=1
CORE_MONITOR=2

if test $# -lt 1 || test $1 -lt 0 || test $1 -gt 1
then
    echo "Usage: $0 {0|1|2} [<sleep_time>*<repeats>]..."
    exit 1
fi
for param in `echo $@ | cut -d' ' -f2-`
do
    sleep_time=`echo $param | cut -d'*' -f1`
    repeats=`echo $param | cut -d'*' -f2`
    if test $sleep_time -le 0
    then
        echo "Sleep time must be greater than 0"
        exit 1
    fi
    if test $repeats -lt 0
    then
        echo "Repeats must be greater than or equal to 0"
        exit 2
    fi
    echo "${sleep_time}s sleep time, $repeats repeats"
    for i in $(seq 1 $repeats)
    do
        echo "> ${sleep_time}s sleep time, repetition $i"
        ./app $sleep_time $1 $CORE_COUNTER $CORE_MONITOR > $FILEPATH_PREFIX-$1-$sleep_time-$i.csv
    done
    echo "Finished generating $FILEPATH_PREFIX-$1-$sleep_time-*.csv"
done