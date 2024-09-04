for file in `ls out/count1/count-*.csv`
do
    echo "Processing $file $1"
    python3 analysis/aex_difference.py $file $1
    python3 analysis/aex_timeline.py $file $1
    python3 analysis/aex_tspAEX.py $file $1
done