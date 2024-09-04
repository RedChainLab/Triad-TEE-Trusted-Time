#/bin/sh
CORE_COUNTER=1
CORE_MONITOR=2

VERBOSITY=2 # Required value for subsequent scripts

FILEPATH_PREFIX="out/count${VERBOSITY}/count-`date +%Y-%m-%d-%H-%M-%S`"

sleep_time_to_string() 
{
    case $1 in
        0)
            echo "syscall sleep"
            ;;
        1)
            echo "readTSC sleep"
            ;;
        2)
            echo "in-enclave adder sleep"
            ;;
        3)
            echo "asm adder sleep"
            ;;
        *)
            echo "Invalid sleep type"
            ;;
    esac
}

if test $# = 0
then
    echo "Usage: $0 <sleep_type>*<sleep_time>*<repeats>]..."
    exit 1
fi
for param
do
    sleep_type=`echo $param | cut -d'*' -f1`
    sleep_time=`echo $param | cut -d'*' -f2`
    repeats=`echo $param | cut -d'*' -f3`
    if test $sleep_type -lt 0 || test $sleep_type -gt 3
    then
        echo "Sleep type must be between 0 and 3"
        exit 1
    fi
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
    echo "`sleep_time_to_string ${sleep_type}` for ${sleep_time}s sleep time, $repeats repeats"
    for i in $(seq 1 $repeats)
    do
        echo "> `sleep_time_to_string ${sleep_type}`, ${sleep_time}s sleep time, repetition $i"
        ./app $sleep_time $1 $VERBOSITY $CORE_COUNTER $CORE_MONITOR > $FILEPATH_PREFIX-$sleep_type-$sleep_time-$i.csv
    done
    echo "Finished generating $FILEPATH_PREFIX-$sleep_type-$sleep_time-*.csv"
done