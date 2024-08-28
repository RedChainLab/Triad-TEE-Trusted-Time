if test -f out/aex/aex-$1-$2-$3.csv
then
    rm out/aex/aex-$1-$2-$3.csv
fi
for file in `ls out/count/count-$1-$2-$3-*`; do tail -n 1 $file >> out/aex/aex-$1-$2-$3.csv; done