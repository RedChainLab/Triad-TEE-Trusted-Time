#/bin/sh
CORE_COUNTER=2
CORE_MONITOR=3

VERBOSITY=2 # Required value for subsequent scripts

FILEPATH_PREFIX="out/count${VERBOSITY}/count-`date +%Y-%m-%d-%H-%M-%S`"

sleep_time_to_string() 
{
    case $1 in
        0)
            echo "syscall sleep"
            ;;
        1)
            echo "ocall readTSC sleep"
            ;;
        2)
            echo "enclave readTSC sleep"
            ;;
        3)
            echo "in-enclave adder sleep"
            ;;
        4)
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
    sgx_type=`echo $param | cut -d'*' -f1`
    sleep_type=`echo $param | cut -d'*' -f2`
    sleep_time=`echo $param | cut -d'*' -f3`
    repeats=`echo $param | cut -d'*' -f4`
    if test $sgx_type -lt 1 || test $sgx_type -gt 2
    then
        echo "SGX type must be 1 or 2"
        exit 1
    fi
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
        ./app $sgx_type $sleep_time $sleep_type $VERBOSITY $CORE_COUNTER $CORE_MONITOR > $FILEPATH_PREFIX-$sleep_type-$sleep_time-$i.csv
    done
    echo "Finished generating $FILEPATH_PREFIX-$sleep_type-$sleep_time-*.csv"
done