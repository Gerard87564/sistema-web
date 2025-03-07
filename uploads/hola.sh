#!/bin/bash

input="Downloads/dict.txt"
input2="dictEs.txt"
input3="dictAng.txt"
inpu4="dictCat.txt"
output="Downloads/randomized_output.txt"

echo "Quin dict vols utilitzar? "
echo "1) Espanyol"
echo "2) Anglés"
echo "3) Català"
echo "4) Lorem"
read dict

read -p "Cuantes paraules vols generar? " paraules
read -p "Fins cuants bytes vols que arribi el fitxer? " bytes
paraules1=()

if [[ $dict -eq 1 ]]; then
    while IFS= read -r line; do
        paraules1+=("$line")
    done < "$input2"
elif [[ $dict -eq 2 ]]; then
    while IFS= read -r line; do
        paraules1+=("$line")
    done < "$input3"
elif [[ $dict -eq 3 ]]; then
    while IFS= read -r line; do
        paraules1+=("$line")
    done < "$input4"
else
    while IFS= read -r line; do
        paraules1+=("$line")
    done < "$input"
fi

echo "Total paraules llegides: ${#paraules1[@]}"

for ((i=${#paraules1[@]}-1; i>0; i--)); do
    j=$((RANDOM % (i + 1))) 
    temp="${paraules1[i]}"
    paraules1[i]="${paraules1[j]}"
    paraules1[j]="$temp"
done

seleccionades=("${paraules1[@]:0:paraules}")

echo -n "" > "$output"

for paraula in "${seleccionades[@]}"; do
    if (( $(stat -c %s "$output") + ${#paraula} + 1 > bytes )); then
        break
    fi
    echo "Escribint: $paraula"
    echo "$paraula" >> "$output"
done

echo "El contingut s'ha guardat en $output"